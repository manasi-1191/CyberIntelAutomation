"""
CyberIntel Automation — main entry point.

Commands:
  python main.py collect                              # collect data, build report, run AI, auto-send email
  python main.py collect --date 2026-06-16           # backfill a specific date
  python main.py collect --dry-run                    # collect only, no writes, no email
  python main.py collect --no-email                  # collect and save, skip email
  python main.py summarize --report-id 2026-06-17   # run AI extraction+summarization on a saved report
  python main.py send-email --report-id 2026-06-17   # (re)send approval email for a saved report
  python main.py check-approval                      # poll Gmail for replies on all pending reports
  python main.py check-approval --report-id 2026-06-17  # check one specific report
"""
import argparse
import logging
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

from config.settings import settings
from utils.logging_config import logger

from collectors.cisa_kev import CisaKevCollector
from collectors.cisa_advisories import CisaAdvisoriesCollector
from collectors.nvd_cve import NvdCveCollector
from collectors.rss_feeds import RssFeedCollector

from pipeline.normalizer import normalize_vulnerabilities, normalize_events
from pipeline.filter import filter_vulnerabilities, filter_events
from pipeline.deduplicator import deduplicate
from pipeline.enricher import enrich_with_kev
from pipeline.prioritizer import assign_priority_tiers, severity_counts
from pipeline.report_builder import build_report

from storage.local_store import (
    save_raw_collection, save_report, load_report, list_reports,
    save_extracted_events, save_summaries_text,
)
from storage.audit_logger import log_action
from models.audit import AuditAction
from models.report import DailyReport, ApprovalStatus


# ── Collect lock ─────────────────────────────────────────────────────────────

def _acquire_collect_lock() -> Path | None:
    """
    Write a PID lock file so two collect runs cannot overlap.
    Returns the lock Path on success, or None if another run is already active.
    Stale locks whose PID is no longer running are cleaned up automatically.
    """
    lock_path = settings.data_dir / ".collect.lock"
    if lock_path.exists():
        try:
            pid = int(lock_path.read_text().strip())
            os.kill(pid, 0)   # signal 0 = existence check only, no signal sent
            logger.warning(
                "collect already running (PID %d) — exiting to prevent duplicate run",
                pid,
            )
            log_action(
                AuditAction.ERROR,
                detail=f"collect skipped — already running under PID {pid}",
                success=False,
                error_message="duplicate collect prevented by lockfile",
            )
            return None
        except (ValueError, ProcessLookupError):
            # PID in lock file is gone — stale lock, safe to remove
            logger.info("Removing stale collect lock (PID no longer running)")
            lock_path.unlink(missing_ok=True)
        except PermissionError:
            # Cannot signal the process — treat as active to be safe
            logger.warning("Cannot verify collect lock PID — skipping run to be safe")
            return None
    lock_path.write_text(str(os.getpid()))
    return lock_path


def _release_collect_lock(lock_path: Path | None) -> None:
    """Remove the collect lock file, ignoring errors if already gone."""
    if lock_path and lock_path.exists():
        lock_path.unlink(missing_ok=True)


# ── Collect ───────────────────────────────────────────────────────────────────

def cmd_collect(args: argparse.Namespace) -> None:
    report_date: datetime = args.date
    dry_run: bool = args.dry_run
    skip_email: bool = args.no_email or dry_run

    report_id = report_date.strftime("%Y-%m-%d")
    window_end = report_date.replace(hour=23, minute=59, second=59)
    window_start = window_end - timedelta(hours=settings.collection_window_hours)

    logger.info(
        "=== collect | report_id=%s | window=[%s → %s] | test_mode=%s ===",
        report_id,
        window_start.isoformat(),
        window_end.isoformat(),
        settings.test_mode,
    )

    if settings.test_mode:
        logger.info("TEST_MODE=true — LinkedIn publishing disabled")

    settings.ensure_dirs()
    lock_path = _acquire_collect_lock()
    if lock_path is None:
        return

    try:
        log_action(AuditAction.COLLECTION_STARTED, report_id=report_id)

        # 1. Collect
        collectors = [
            CisaKevCollector(window_start, window_end),
            CisaAdvisoriesCollector(window_start, window_end),
            NvdCveCollector(window_start, window_end),
            RssFeedCollector(window_start, window_end),
        ]

        all_vulns, all_events = [], []
        for collector in collectors:
            try:
                v, e = collector.collect()
                all_vulns.extend(v)
                all_events.extend(e)
                log_action(
                    AuditAction.ITEM_COLLECTED,
                    report_id=report_id,
                    source=collector.name,
                    detail=f"{len(v)} vulns, {len(e)} events",
                )
            except Exception as exc:
                logger.error("Collector %s failed: %s", collector.name, exc)
                log_action(
                    AuditAction.ERROR,
                    report_id=report_id,
                    source=collector.name,
                    success=False,
                    error_message=str(exc),
                )

        logger.info("Collected: %d vulns, %d events (pre-dedup)", len(all_vulns), len(all_events))

        # 2. Normalize
        all_vulns = normalize_vulnerabilities(all_vulns)
        all_events = normalize_events(all_events)

        # 3. Filter
        all_vulns = filter_vulnerabilities(all_vulns, window_start, window_end)
        all_events = filter_events(all_events, window_start, window_end)
        logger.info("After filter: %d vulns, %d events", len(all_vulns), len(all_events))

        # 4. Deduplicate (within-run only)
        unique_vulns, unique_events, dupe_count = deduplicate(all_vulns, all_events)
        log_action(AuditAction.ITEM_DEDUPLICATED, report_id=report_id,
                   detail=f"{dupe_count} within-run duplicates removed")

        # 5. Enrich — mark KEV flag on any CVE that appears in the KEV catalog
        unique_vulns = enrich_with_kev(unique_vulns)

        # 6. Prioritize — assign tiers and sort
        unique_vulns = assign_priority_tiers(unique_vulns)
        sc = severity_counts(unique_vulns)
        logger.info(
            "Priority tiers: KEV=%d  CRITICAL(CVSS≥9)=%d  CRITICAL=%d  HIGH=%d  MEDIUM=%d  LOW/UNK=%d",
            sc["kev"], sc["critical_high_cvss"], sc["critical"],
            sc["high"], sc["medium"], sc["low_unknown"],
        )

        # Preserve linkedin_preview from any prior run before build_report resets it.
        # load_report reads the file that was saved by the *previous* collect run;
        # once save_report() runs below it will be overwritten with the new report.
        _prior_preview = ""
        if not dry_run:
            _prior = load_report(report_id)
            if _prior and _prior.linkedin_preview and "PLACEHOLDER" not in _prior.linkedin_preview:
                _prior_preview = _prior.linkedin_preview
                logger.info(
                    "Carrying forward linkedin_preview from prior run (%d words)",
                    len(_prior_preview.split()),
                )

        # 7. Build report
        report = build_report(
            report_id=report_id,
            window_start=window_start,
            window_end=window_end,
            vulnerabilities=unique_vulns,
            threat_events=unique_events,
            collection_window_hours=settings.collection_window_hours,
        )
        if _prior_preview:
            report.linkedin_preview = _prior_preview

        # 8. Persist
        if not dry_run:
            save_raw_collection(report_id, unique_vulns, unique_events)
            report_path = save_report(report)
            log_action(AuditAction.REPORT_GENERATED, report_id=report_id, detail=str(report_path))
            logger.info("Report saved: %s", report_path)
        else:
            logger.info("DRY RUN — skipping storage writes")

        # 9. AI extraction + summarization
        if not dry_run:
            _run_ai_pipeline(report)

        log_action(AuditAction.COLLECTION_COMPLETED, report_id=report_id)

        logger.info(
            "=== Done | vulns=%d (critical=%d, kev=%d) | events=%d (breaches=%d, attacks=%d) ===",
            len(unique_vulns), report.critical_cve_count, report.kev_count,
            len(unique_events), report.breach_count, report.attack_count,
        )

        # 10. Send approval email (unless skipped)
        if not dry_run and not skip_email:
            _send_email_for_report(report)

    finally:
        _release_collect_lock(lock_path)


# ── AI pipeline ──────────────────────────────────────────────────────────────

def _run_ai_pipeline(report: DailyReport) -> None:
    """Phase 3: extract threat intelligence from events, then generate summaries."""
    from summarizer.ai_provider import get_ai_client
    from summarizer.extractor import extract_threat_events
    from summarizer.summarizer import generate_summaries, generate_linkedin_preview

    client = get_ai_client()
    if client is None:
        logger.info(
            "AI disabled (AI_PROVIDER=%s) — extraction and summarization skipped",
            settings.ai_provider,
        )
        log_action(
            AuditAction.AI_SKIPPED_NO_KEY,
            report_id=report.report_id,
            detail=f"AI_PROVIDER={settings.ai_provider}",
        )
        return

    logger.info("AI pipeline starting (provider=%s, model=%s)", settings.ai_provider, client.model)

    # Phase 3A — extract structured intelligence from threat events
    extracted = extract_threat_events(report.threat_events, client)
    if extracted:
        path = save_extracted_events(report.report_id, extracted)
        report.extracted_events_path = str(path)
        log_action(
            AuditAction.AI_EXTRACTION_COMPLETED,
            report_id=report.report_id,
            detail=f"{len(extracted)} events extracted using {client.model}",
        )

    # Phase 3B — generate executive and detailed summaries
    executive, detailed = generate_summaries(report, extracted, client)
    if executive or detailed:
        report.executive_summary = executive
        report.detailed_summary = detailed
        summaries_path = save_summaries_text(report.report_id, executive, detailed)
        report.summaries_path = str(summaries_path)
        log_action(
            AuditAction.AI_SUMMARY_GENERATED,
            report_id=report.report_id,
            detail=(
                f"exec={len(executive.split())}w, "
                f"detail={len(detailed.split())}w, "
                f"model={client.model}"
            ),
        )
        logger.info("Summaries saved: %s", summaries_path)

    # Phase 3C — generate LinkedIn preview (shown in approval email; published on APPROVE)
    linkedin_preview = generate_linkedin_preview(report, extracted, client)
    if linkedin_preview:
        report.linkedin_preview = linkedin_preview
        log_action(
            AuditAction.AI_SUMMARY_GENERATED,
            report_id=report.report_id,
            detail=f"linkedin_preview={len(linkedin_preview.split())}w model={client.model}",
        )
        logger.info("LinkedIn preview generated: %d words", len(linkedin_preview.split()))
    elif report.linkedin_preview:
        # AI + fallback both failed but a valid preview was carried forward from a prior run.
        logger.info(
            "LinkedIn preview generation returned empty — keeping existing preview "
            "from prior run (%d words)",
            len(report.linkedin_preview.split()),
        )
    else:
        logger.warning(
            "LinkedIn preview is empty and no prior preview is available — "
            "publishing will be blocked. "
            "Re-run: python main.py summarize --report-id %s",
            report.report_id,
        )
        log_action(
            AuditAction.ERROR,
            report_id=report.report_id,
            detail="linkedin_preview empty — AI failed and no fallback or prior preview available",
            success=False,
            error_message="linkedin_preview generation failed with no fallback",
        )

    save_report(report)


# ── Summarize subcommand ──────────────────────────────────────────────────────

def cmd_summarize(args: argparse.Namespace) -> None:
    """Re-run AI extraction and summarization on a previously collected report."""
    settings.ensure_dirs()
    report = load_report(args.report_id)
    if not report:
        logger.error("Report not found: %s", args.report_id)
        sys.exit(1)
    _run_ai_pipeline(report)


# ── Send email ────────────────────────────────────────────────────────────────

def cmd_send_email(args: argparse.Namespace) -> None:
    settings.ensure_dirs()
    report = load_report(args.report_id)
    if not report:
        logger.error("Report not found: %s", args.report_id)
        sys.exit(1)
    _send_email_for_report(report)


def _report_ready_for_email(report: DailyReport) -> tuple[bool, str]:
    """
    Returns (ready, reason).  True only when all three content fields are
    populated with real content — empty strings and build_report placeholder
    stubs (containing the literal word PLACEHOLDER) are both rejected.
    """
    if not report.executive_summary:
        return False, "executive_summary is empty"
    if "PLACEHOLDER" in report.executive_summary:
        return False, "executive_summary contains PLACEHOLDER"
    if not report.detailed_summary:
        return False, "detailed_summary is empty"
    if "PLACEHOLDER" in report.detailed_summary:
        return False, "detailed_summary contains PLACEHOLDER"
    if not report.linkedin_preview or not report.linkedin_preview.strip():
        return False, "linkedin_preview is empty"
    if "PLACEHOLDER" in report.linkedin_preview:
        return False, "linkedin_preview contains PLACEHOLDER"
    return True, ""


def _send_email_for_report(report: DailyReport) -> None:
    ready, reason = _report_ready_for_email(report)
    if not ready:
        logger.error(
            "Approval email blocked — required content not ready for report %s: %s. "
            "Re-run: python main.py summarize --report-id %s",
            report.report_id, reason, report.report_id,
        )
        log_action(
            AuditAction.ERROR,
            report_id=report.report_id,
            source="emailer",
            detail=f"email blocked — {reason}",
            success=False,
            error_message=reason,
        )
        return

    from emailer.gmail_auth import is_configured, GmailCredentialsError
    from emailer.sender import send_approval_email

    if not is_configured():
        logger.warning(
            "Gmail not configured — skipping email. "
            "Run: python scripts/gmail_setup.py"
        )
        log_action(
            AuditAction.EMAIL_SKIPPED_NO_CREDENTIALS,
            report_id=report.report_id,
            detail="Gmail credentials not set in .env",
        )
        return

    try:
        thread_id, message_id = send_approval_email(report)
        report.email_sent_at = datetime.utcnow()
        report.gmail_thread_id = thread_id
        report.gmail_message_id = message_id
        save_report(report)
        log_action(
            AuditAction.EMAIL_SENT,
            report_id=report.report_id,
            detail=f"thread_id={thread_id} to={settings.approval_email_recipient}",
        )
        logger.info(
            "Approval email sent to %s | thread_id=%s",
            settings.approval_email_recipient,
            thread_id,
        )
    except Exception as exc:
        logger.error("Failed to send approval email: %s", exc)
        log_action(
            AuditAction.ERROR,
            report_id=report.report_id,
            source="emailer",
            success=False,
            error_message=str(exc),
        )


# ── Check approval ────────────────────────────────────────────────────────────

def cmd_check_approval(args: argparse.Namespace) -> None:
    settings.ensure_dirs()

    if args.report_id:
        report_ids = [args.report_id]
    else:
        # Check all reports that have an email sent but are still pending
        report_ids = [
            rid for rid in list_reports()
            if _is_pending_with_email(rid)
        ]

    if not report_ids:
        logger.info("No pending reports with sent emails found.")
        return

    logger.info("Checking approval for %d report(s): %s", len(report_ids), report_ids)

    for report_id in report_ids:
        report = load_report(report_id)
        if report:
            _check_and_process_approval(report)


def _is_pending_with_email(report_id: str) -> bool:
    report = load_report(report_id)
    return (
        report is not None
        and report.approval_status == ApprovalStatus.PENDING
        and bool(report.gmail_thread_id)
    )


def _check_and_process_approval(report: DailyReport) -> None:
    from emailer.approval_poller import check_for_reply
    from emailer.gmail_auth import GmailCredentialsError

    if report.linkedin_post_id:
        logger.info(
            "Report %s already published (linkedin_post_id=%s) — skipping",
            report.report_id, report.linkedin_post_id,
        )
        return
    if report.approval_status in (ApprovalStatus.APPROVED, ApprovalStatus.EDITED_APPROVED):
        logger.info(
            "Report %s already processed (status=%s) — skipping re-poll",
            report.report_id, report.approval_status,
        )
        return

    logger.info("Polling Gmail for report %s (thread %s)", report.report_id, report.gmail_thread_id)
    log_action(AuditAction.APPROVAL_POLL_CHECKED, report_id=report.report_id,
               detail=f"thread_id={report.gmail_thread_id}")

    try:
        result = check_for_reply(report.gmail_thread_id, report.gmail_message_id)
    except GmailCredentialsError as exc:
        logger.error("Gmail credentials error: %s", exc)
        return
    except Exception as exc:
        logger.error("Error polling Gmail for %s: %s", report.report_id, exc)
        log_action(AuditAction.ERROR, report_id=report.report_id,
                   source="approval_poller", success=False, error_message=str(exc))
        return

    if result.status == "pending":
        logger.info("Report %s: still awaiting approval reply", report.report_id)
        return

    # Process the decision
    report.approval_received_at = datetime.utcnow()
    report.approved_by = result.approved_by

    if result.status == "approved":
        if not report.linkedin_preview or not report.linkedin_preview.strip():
            logger.error(
                "Cannot publish report %s: linkedin_preview is empty. "
                "Re-run AI pipeline: python main.py summarize --report-id %s",
                report.report_id, report.report_id,
            )
            log_action(
                AuditAction.ERROR,
                report_id=report.report_id,
                source="check_approval",
                success=False,
                error_message="linkedin_preview empty — publish blocked",
            )
            return
        if "PLACEHOLDER" in report.linkedin_preview:
            logger.error(
                "Cannot publish report %s: linkedin_preview contains PLACEHOLDER — "
                "AI generation incomplete. Re-run: python main.py summarize --report-id %s",
                report.report_id, report.report_id,
            )
            log_action(
                AuditAction.ERROR,
                report_id=report.report_id,
                source="check_approval",
                success=False,
                error_message="linkedin_preview contains PLACEHOLDER — publish blocked",
            )
            return
        if not report.detailed_summary or not report.detailed_summary.strip():
            logger.warning(
                "Report %s: detailed_summary is empty — email showed incomplete briefing. "
                "Re-run: python main.py summarize --report-id %s",
                report.report_id, report.report_id,
            )
        report.approval_status = ApprovalStatus.APPROVED
        report.published_content = report.linkedin_preview
        log_action(AuditAction.APPROVAL_RECEIVED, report_id=report.report_id,
                   detail=f"approved by {result.approved_by}")
        logger.info("APPROVED by %s", result.approved_by)

    elif result.status == "edited_approved":
        report.approval_status = ApprovalStatus.EDITED_APPROVED
        report.published_content = result.content
        log_action(AuditAction.APPROVAL_EDITED, report_id=report.report_id,
                   detail=f"edited content approved by {result.approved_by}")
        logger.info("EDITED APPROVAL by %s — custom content will be published", result.approved_by)

    elif result.status == "rejected":
        report.approval_status = ApprovalStatus.REJECTED
        log_action(AuditAction.APPROVAL_REJECTED, report_id=report.report_id,
                   detail=f"rejected by {result.approved_by}")
        logger.info("REJECTED by %s — skipping publish", result.approved_by)
        save_report(report)
        return

    save_report(report)

    # Publish (or simulate in TEST_MODE)
    if report.approval_status in (ApprovalStatus.APPROVED, ApprovalStatus.EDITED_APPROVED):
        _publish_or_simulate(report)


def _publish_or_simulate(report: DailyReport) -> None:
    if settings.test_mode:
        output_path = settings.reports_dir / f"{report.report_id}_linkedin_draft.txt"
        output_path.write_text(report.published_content, encoding="utf-8")
        report.test_output_path = str(output_path)
        save_report(report)
        log_action(
            AuditAction.CONTENT_SAVED_TEST_MODE,
            report_id=report.report_id,
            detail=str(output_path),
        )
        logger.info(
            "TEST_MODE — approved content saved to: %s",
            output_path,
        )
    else:
        _publish_to_linkedin(report)


def _publish_to_linkedin(report: DailyReport) -> None:
    """Publish approved content to LinkedIn. Falls back to manual file on any failure."""
    from linkedin.auth import is_configured as linkedin_is_configured
    from linkedin.publisher import publish_post

    if report.linkedin_post_id:
        logger.info(
            "Report %s already has linkedin_post_id=%s — skipping duplicate publish",
            report.report_id, report.linkedin_post_id,
        )
        return

    if not linkedin_is_configured():
        logger.warning(
            "LinkedIn credentials not configured — saving content for manual posting. "
            "Run: python scripts/linkedin_setup.py"
        )
        _save_for_manual_posting(report)
        return

    try:
        post_id = publish_post(
            content=report.published_content,
            author_urn=settings.linkedin_author_urn,
            report_id=report.report_id,
        )
    except ValueError as exc:
        logger.error("LinkedIn publish validation error: %s", exc)
        _save_for_manual_posting(report)
        return
    except Exception as exc:
        logger.error("LinkedIn publish unexpected error: %s", exc)
        _save_for_manual_posting(report)
        return

    if post_id:
        report.linkedin_post_id = post_id
        report.linkedin_published_at = datetime.utcnow()
        save_report(report)
        log_action(
            AuditAction.LINKEDIN_PUBLISHED,
            report_id=report.report_id,
            detail=f"post_id={post_id} author={settings.linkedin_author_urn}",
        )
        logger.info("Published to LinkedIn: %s", post_id)
    else:
        _save_for_manual_posting(report)


def _save_for_manual_posting(report: DailyReport) -> None:
    """LinkedIn publish failed or not configured — save content for manual copy-paste."""
    output_path = settings.reports_dir / f"{report.report_id}_linkedin_manual.txt"
    instructions = (
        f"LinkedIn post for {report.report_id}\n"
        f"{'=' * 60}\n\n"
        f"{report.published_content}\n\n"
        f"{'=' * 60}\n"
        "Copy the text above and post it manually at:\n"
        "https://www.linkedin.com/feed/\n"
    )
    output_path.write_text(instructions, encoding="utf-8")
    report.test_output_path = str(output_path)
    save_report(report)
    log_action(
        AuditAction.LINKEDIN_PUBLISH_FAILED,
        report_id=report.report_id,
        detail=f"manual fallback saved to {output_path}",
    )
    logger.warning("Content saved for manual LinkedIn posting: %s", output_path)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CyberIntel Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # collect
    p_collect = sub.add_parser("collect", help="Run data collection pipeline")
    p_collect.add_argument(
        "--date",
        type=lambda s: datetime.strptime(s, "%Y-%m-%d"),
        default=datetime.utcnow(),
        metavar="YYYY-MM-DD",
        help="Report date (default: today UTC)",
    )
    p_collect.add_argument("--dry-run", action="store_true",
                           help="No storage writes, no email")
    p_collect.add_argument("--no-email", action="store_true",
                           help="Save report but skip sending email")

    # summarize
    p_sum = sub.add_parser("summarize", help="Run AI extraction + summarization on a saved report")
    p_sum.add_argument("--report-id", required=True, metavar="YYYY-MM-DD",
                       help="Report ID to summarize")

    # send-email
    p_send = sub.add_parser("send-email", help="Send approval email for a saved report")
    p_send.add_argument("--report-id", required=True, metavar="YYYY-MM-DD",
                        help="Report ID to email")

    # check-approval
    p_check = sub.add_parser("check-approval", help="Poll Gmail for approval replies")
    p_check.add_argument("--report-id", default=None, metavar="YYYY-MM-DD",
                         help="Check one specific report (default: all pending)")

    return parser


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    dispatch = {
        "collect": cmd_collect,
        "summarize": cmd_summarize,
        "send-email": cmd_send_email,
        "check-approval": cmd_check_approval,
    }

    try:
        dispatch[args.command](args)
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        sys.exit(0)
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        sys.exit(1)

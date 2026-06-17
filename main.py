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

    # 7. Build report
    report = build_report(
        report_id=report_id,
        window_start=window_start,
        window_end=window_end,
        vulnerabilities=unique_vulns,
        threat_events=unique_events,
        collection_window_hours=settings.collection_window_hours,
    )

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


# ── AI pipeline ──────────────────────────────────────────────────────────────

def _run_ai_pipeline(report: DailyReport) -> None:
    """Phase 3: extract threat intelligence from events, then generate summaries."""
    from summarizer.ai_provider import get_ai_client
    from summarizer.extractor import extract_threat_events
    from summarizer.summarizer import generate_summaries

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


def _send_email_for_report(report: DailyReport) -> None:
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
        report.approval_status = ApprovalStatus.APPROVED
        report.published_content = report.detailed_summary
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
        # Phase 3 will replace this
        logger.info(
            "LinkedIn publishing not yet implemented (Phase 3). "
            "Content ready in report.published_content."
        )
        log_action(
            AuditAction.LINKEDIN_SKIPPED_TEST_MODE,
            report_id=report.report_id,
            detail="Phase 3 not implemented",
        )


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

"""
CyberIntel Automation — Phase 1 entry point.
Runs the collection pipeline and produces a daily report JSON.

Usage:
  python main.py                  # run for today
  python main.py --date 2026-06-16  # run for a specific date (for backfills)
  python main.py --dry-run        # skip storage writes
"""
import argparse
import logging
import sys
from datetime import datetime, timedelta

from config.settings import settings
from utils.logging_config import logger

from collectors.cisa_kev import CisaKevCollector
from collectors.cisa_advisories import CisaAdvisoriesCollector
from collectors.nvd_cve import NvdCveCollector
from collectors.rss_feeds import RssFeedCollector

from pipeline.normalizer import normalize_vulnerabilities, normalize_events
from pipeline.filter import filter_vulnerabilities, filter_events
from pipeline.deduplicator import deduplicate
from pipeline.report_builder import build_report

from storage.local_store import save_raw_collection, save_report
from storage.audit_logger import log_action
from models.audit import AuditAction


def run(report_date: datetime, dry_run: bool = False) -> None:
    report_id = report_date.strftime("%Y-%m-%d")
    window_end = report_date.replace(hour=23, minute=59, second=59)
    window_start = window_end - timedelta(hours=settings.collection_window_hours)

    logger.info(
        "=== CyberIntel run | report_id=%s | window=[%s → %s] | test_mode=%s ===",
        report_id,
        window_start.isoformat(),
        window_end.isoformat(),
        settings.test_mode,
    )

    if settings.test_mode:
        logger.info("TEST_MODE=true — LinkedIn publishing disabled, emails go to test account")

    settings.ensure_dirs()

    log_action(AuditAction.COLLECTION_STARTED, report_id=report_id)

    # ── 1. Collect ────────────────────────────────────────────────────────────
    collectors = [
        CisaKevCollector(window_start, window_end),
        CisaAdvisoriesCollector(window_start, window_end),
        NvdCveCollector(window_start, window_end),
        RssFeedCollector(window_start, window_end),
    ]

    all_vulns = []
    all_events = []

    for collector in collectors:
        try:
            vulns, events = collector.collect()
            all_vulns.extend(vulns)
            all_events.extend(events)
            log_action(
                AuditAction.ITEM_COLLECTED,
                report_id=report_id,
                source=collector.name,
                detail=f"{len(vulns)} vulns, {len(events)} events",
            )
        except Exception as exc:
            logger.error("Collector %s failed: %s", collector.name, exc)
            log_action(
                AuditAction.ERROR,
                report_id=report_id,
                source=collector.name,
                detail=str(exc),
                success=False,
                error_message=str(exc),
            )

    logger.info("Collected totals: %d vulns, %d events (pre-dedup)", len(all_vulns), len(all_events))

    # ── 2. Normalize ─────────────────────────────────────────────────────────
    all_vulns = normalize_vulnerabilities(all_vulns)
    all_events = normalize_events(all_events)

    # ── 3. Filter to window ──────────────────────────────────────────────────
    all_vulns = filter_vulnerabilities(all_vulns, window_start, window_end)
    all_events = filter_events(all_events, window_start, window_end)

    logger.info("After filter: %d vulns, %d events", len(all_vulns), len(all_events))

    # ── 4. Deduplicate ───────────────────────────────────────────────────────
    unique_vulns, unique_events, dupe_count = deduplicate(all_vulns, all_events)

    log_action(
        AuditAction.ITEM_DEDUPLICATED,
        report_id=report_id,
        detail=f"{dupe_count} duplicates removed",
    )

    # ── 5. Build report ──────────────────────────────────────────────────────
    report = build_report(
        report_id=report_id,
        window_start=window_start,
        window_end=window_end,
        vulnerabilities=unique_vulns,
        threat_events=unique_events,
        collection_window_hours=settings.collection_window_hours,
    )

    # ── 6. Persist ───────────────────────────────────────────────────────────
    if not dry_run:
        save_raw_collection(report_id, unique_vulns, unique_events)
        report_path = save_report(report)
        log_action(
            AuditAction.REPORT_GENERATED,
            report_id=report_id,
            detail=str(report_path),
        )
        logger.info("Report saved: %s", report_path)
    else:
        logger.info("DRY RUN — skipping storage writes")

    log_action(AuditAction.COLLECTION_COMPLETED, report_id=report_id)

    # ── Summary ───────────────────────────────────────────────────────────────
    logger.info(
        "=== Done | vulns=%d (critical=%d, kev=%d) | events=%d (breaches=%d, attacks=%d) ===",
        len(unique_vulns),
        report.critical_cve_count,
        report.kev_count,
        len(unique_events),
        report.breach_count,
        report.attack_count,
    )

    if settings.test_mode:
        logger.info("Phase 2 (email) and Phase 3 (LinkedIn) not yet implemented.")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CyberIntel Automation — Phase 1")
    parser.add_argument(
        "--date",
        type=lambda s: datetime.strptime(s, "%Y-%m-%d"),
        default=datetime.utcnow(),
        help="Report date in YYYY-MM-DD format (default: today UTC)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect and process data but skip all storage writes",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    try:
        run(report_date=args.date, dry_run=args.dry_run)
    except KeyboardInterrupt:
        logger.info("Interrupted.")
        sys.exit(0)
    except Exception as exc:
        logger.exception("Fatal error: %s", exc)
        sys.exit(1)

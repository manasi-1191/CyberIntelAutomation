"""
Assembles a DailyReport from normalized, deduplicated collections.
Phase 4 will populate executive_summary and detailed_summary via Anthropic.
Phase 1 inserts placeholder text so the structure is complete and testable.
"""
from datetime import datetime

from models.vulnerability import Vulnerability, Severity
from models.report import DailyReport
from models.threat import ThreatEvent, ThreatCategory

_BREACH_CATS = {ThreatCategory.DATA_BREACH}
_ATTACK_CATS = {ThreatCategory.CYBER_ATTACK, ThreatCategory.RANSOMWARE, ThreatCategory.APT}


def build_report(
    report_id: str,
    window_start: datetime,
    window_end: datetime,
    vulnerabilities: list[Vulnerability],
    threat_events: list[ThreatEvent],
    collection_window_hours: int,
) -> DailyReport:
    critical = [v for v in vulnerabilities if v.severity == Severity.CRITICAL]
    high = [v for v in vulnerabilities if v.severity == Severity.HIGH]
    kev = [v for v in vulnerabilities if v.is_known_exploited]
    breaches = [e for e in threat_events if e.category in _BREACH_CATS]
    attacks = [e for e in threat_events if e.category in _ATTACK_CATS]

    report = DailyReport(
        report_id=report_id,
        window_start=window_start,
        window_end=window_end,
        collection_window_hours=collection_window_hours,
        vulnerabilities=vulnerabilities,
        threat_events=threat_events,
        critical_cve_count=len(critical),
        high_cve_count=len(high),
        kev_count=len(kev),
        breach_count=len(breaches),
        attack_count=len(attacks),
        executive_summary=_placeholder_executive(vulnerabilities, threat_events),
        detailed_summary=_placeholder_detailed(vulnerabilities, threat_events),
    )
    return report


def _placeholder_executive(
    vulns: list[Vulnerability],
    events: list[ThreatEvent],
) -> str:
    critical = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
    kev = sum(1 for v in vulns if v.is_known_exploited)
    total_events = len(events)
    return (
        f"[PLACEHOLDER — Phase 4 will generate this via Anthropic] "
        f"Collected {len(vulns)} vulnerabilities ({critical} critical, {kev} actively exploited) "
        f"and {total_events} threat events."
    )


def _placeholder_detailed(
    vulns: list[Vulnerability],
    events: list[ThreatEvent],
) -> str:
    top_cvss = sorted(
        [v for v in vulns if v.cvss],
        key=lambda v: v.cvss.base_score,  # type: ignore[union-attr]
        reverse=True,
    )[:3]
    top_cve_ids = ", ".join(v.cve_id for v in top_cvss) if top_cvss else "none"
    categories = {e.category for e in events}
    cat_str = ", ".join(sorted(categories)) if categories else "none"

    return (
        f"[PLACEHOLDER — Phase 4 will generate this via Anthropic] "
        f"Top CVEs by CVSS score: {top_cve_ids}. "
        f"Threat event categories observed: {cat_str}. "
        f"Total items: {len(vulns)} vulnerabilities, {len(events)} threat events."
    )

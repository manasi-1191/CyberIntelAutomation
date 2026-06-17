"""
Vulnerability prioritization and ranking.

Tier definitions (lower = higher priority):
  0  KEV — actively exploited in the wild (CISA Known Exploited Vulnerabilities)
  1  CRITICAL severity + CVSS base score >= 9.0
  2  CRITICAL severity + CVSS base score < 9.0, or CRITICAL with no CVSS score
  3  HIGH severity
  4  MEDIUM severity
  5  LOW or UNKNOWN severity

Within each tier, vulnerabilities are sorted by CVSS base score descending.

featured_vulnerabilities = all tier-0 + all tier-1 + all tier-2
                         + top MAX_HIGH tier-3
                         capped at MAX_FEATURED total.

The full vulnerability list is preserved in the report for Phase 4 (AI summarizer).
featured_vulnerabilities is what appears in emails and human-readable output.
"""
import logging
from config.settings import settings
from models.vulnerability import Vulnerability, Severity

logger = logging.getLogger(__name__)

MAX_FEATURED: int = 30   # hard cap on featured list length
MAX_HIGH: int = 10       # max HIGH-severity CVEs to include in featured list


def assign_priority_tiers(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """
    Assign priority_tier to every vulnerability and return the list
    sorted by (tier asc, cvss_score desc).
    """
    for v in vulns:
        v.priority_tier = _tier(v)

    return sorted(
        vulns,
        key=lambda v: (v.priority_tier, -(v.cvss.base_score if v.cvss else 0.0)),
    )


def get_featured_vulnerabilities(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """
    Return the high-signal subset for human-readable sections.
    Assumes assign_priority_tiers() has already been called.
    """
    featured: list[Vulnerability] = []

    tier_0 = [v for v in vulns if v.priority_tier == 0]
    tier_1 = [v for v in vulns if v.priority_tier == 1]
    tier_2 = [v for v in vulns if v.priority_tier == 2]
    tier_3 = [v for v in vulns if v.priority_tier == 3]

    featured.extend(tier_0)
    featured.extend(tier_1)
    featured.extend(tier_2)
    featured.extend(tier_3[:MAX_HIGH])

    if len(featured) > MAX_FEATURED:
        featured = featured[:MAX_FEATURED]

    logger.info(
        "Featured vulnerabilities: %d selected (KEV=%d, CRITICAL-high=%d, "
        "CRITICAL=%d, HIGH=%d) from %d total",
        len(featured),
        len(tier_0),
        len(tier_1),
        len(tier_2),
        min(len(tier_3), MAX_HIGH),
        len(vulns),
    )
    return featured


def severity_counts(vulns: list[Vulnerability]) -> dict[str, int]:
    """Return count per priority tier for logging/reporting."""
    counts: dict[str, int] = {
        "kev": 0,
        "critical_high_cvss": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low_unknown": 0,
    }
    labels = {0: "kev", 1: "critical_high_cvss", 2: "critical",
               3: "high", 4: "medium", 5: "low_unknown"}
    for v in vulns:
        key = labels.get(v.priority_tier, "low_unknown")
        counts[key] += 1
    return counts


def _tier(v: Vulnerability) -> int:
    if v.is_known_exploited:
        return 0

    sev = v.severity if isinstance(v.severity, str) else v.severity.value

    if sev == Severity.CRITICAL:
        score = v.cvss.base_score if v.cvss else 0.0
        return 1 if score >= 9.0 else 2

    if sev == Severity.HIGH:
        return 3

    if sev == Severity.MEDIUM:
        return 4

    return 5  # LOW, NONE, UNKNOWN

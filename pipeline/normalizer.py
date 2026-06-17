"""
Normalizes raw collected data into consistent, clean records.
Fixes missing fields, standardizes severity labels, strips HTML from descriptions.
"""
import re
import html
import logging

from models.vulnerability import Vulnerability, Severity
from models.threat import ThreatEvent

logger = logging.getLogger(__name__)


def normalize_vulnerabilities(vulns: list[Vulnerability]) -> list[Vulnerability]:
    return [_normalize_vuln(v) for v in vulns]


def normalize_events(events: list[ThreatEvent]) -> list[ThreatEvent]:
    return [_normalize_event(e) for e in events]


def _normalize_vuln(v: Vulnerability) -> Vulnerability:
    v.cve_id = v.cve_id.strip().upper()
    v.description = _clean_text(v.description)
    v.affected_products = [p.strip() for p in v.affected_products if p.strip()]

    # Ensure severity is consistent with CVSS score when both present
    if v.cvss and v.severity == Severity.UNKNOWN:
        v.severity = v.cvss.severity  # type: ignore[assignment]

    return v


def _normalize_event(e: ThreatEvent) -> ThreatEvent:
    e.title = _clean_text(e.title)
    e.description = _clean_text(e.description)
    e.tags = [t.strip().lower() for t in e.tags if t.strip()]
    e.cve_references = [c.strip().upper() for c in e.cve_references]
    return e


def _clean_text(text: str) -> str:
    """Strip HTML tags, decode entities, collapse whitespace."""
    if not text:
        return ""
    text = html.unescape(text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

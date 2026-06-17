"""
In-run deduplication only — no cross-run persistence.

Design rationale: the 48-hour collection window already defines freshness.
Persisting hashes across runs caused every item to be suppressed on the
second run, even though it was still legitimately within the window.

Vulns are keyed by normalized CVE ID (separate set from events).
Events are keyed by SHA-1 of source_url-or-title (separate set from vulns).
Using separate sets prevents theoretical cross-type hash collisions.
"""
import hashlib
import logging

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent

logger = logging.getLogger(__name__)


def _vuln_key(v: Vulnerability) -> str:
    return v.cve_id.upper().strip()


def _event_key(e: ThreatEvent) -> str:
    raw = (e.source_url or e.title).strip().lower()
    return hashlib.sha1(raw.encode()).hexdigest()


def deduplicate(
    vulns: list[Vulnerability],
    events: list[ThreatEvent],
) -> tuple[list[Vulnerability], list[ThreatEvent], int]:
    """
    Remove items that appear more than once within this run.
    Returns (unique_vulns, unique_events, duplicate_count).
    Stamps dedup_hash on each record.
    """
    seen_vulns: set[str] = set()
    seen_events: set[str] = set()
    unique_vulns: list[Vulnerability] = []
    unique_events: list[ThreatEvent] = []
    dupes = 0

    for v in vulns:
        key = _vuln_key(v)
        v.dedup_hash = hashlib.sha1(key.encode()).hexdigest()
        if key in seen_vulns:
            dupes += 1
            continue
        seen_vulns.add(key)
        unique_vulns.append(v)

    for e in events:
        key = _event_key(e)
        e.dedup_hash = key
        if key in seen_events:
            dupes += 1
            continue
        seen_events.add(key)
        unique_events.append(e)

    logger.info(
        "Deduplication: %d unique vulns, %d unique events, %d within-run duplicates removed",
        len(unique_vulns),
        len(unique_events),
        dupes,
    )
    return unique_vulns, unique_events, dupes

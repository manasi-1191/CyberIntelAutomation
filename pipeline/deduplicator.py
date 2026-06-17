"""
Deduplication via stable content hashes.
For vulnerabilities: keyed on CVE ID.
For threat events: keyed on (source_url or title) normalized.
Seen hashes are persisted across runs in a JSON sidecar file.
"""
import hashlib
import json
import logging
from pathlib import Path

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent

logger = logging.getLogger(__name__)

_SEEN_FILE = Path("data/raw/seen_hashes.json")


def _load_seen() -> set[str]:
    if _SEEN_FILE.exists():
        try:
            return set(json.loads(_SEEN_FILE.read_text()))
        except Exception:
            return set()
    return set()


def _save_seen(seen: set[str]) -> None:
    _SEEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SEEN_FILE.write_text(json.dumps(sorted(seen), indent=2))


def _vuln_key(v: Vulnerability) -> str:
    raw = v.cve_id.upper().strip()
    return hashlib.sha1(raw.encode()).hexdigest()


def _event_key(e: ThreatEvent) -> str:
    raw = (e.source_url or e.title).strip().lower()
    return hashlib.sha1(raw.encode()).hexdigest()


def deduplicate(
    vulns: list[Vulnerability],
    events: list[ThreatEvent],
) -> tuple[list[Vulnerability], list[ThreatEvent], int]:
    """
    Returns (unique_vulns, unique_events, duplicate_count).
    Stamps dedup_hash on each record and persists seen hashes.
    """
    seen = _load_seen()
    unique_vulns: list[Vulnerability] = []
    unique_events: list[ThreatEvent] = []
    dupes = 0

    for v in vulns:
        h = _vuln_key(v)
        v.dedup_hash = h
        if h in seen:
            dupes += 1
            continue
        seen.add(h)
        unique_vulns.append(v)

    for e in events:
        h = _event_key(e)
        e.dedup_hash = h
        if h in seen:
            dupes += 1
            continue
        seen.add(h)
        unique_events.append(e)

    _save_seen(seen)
    logger.info(
        "Deduplication: %d unique vulns, %d unique events, %d duplicates removed",
        len(unique_vulns),
        len(unique_events),
        dupes,
    )
    return unique_vulns, unique_events, dupes

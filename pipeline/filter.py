"""
Filters collected records to only those within the configured time window.
Records without a published_at timestamp are dropped with a warning.
"""
import logging
from datetime import datetime

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent

logger = logging.getLogger(__name__)


def filter_vulnerabilities(
    vulns: list[Vulnerability],
    window_start: datetime,
    window_end: datetime,
) -> list[Vulnerability]:
    result = []
    dropped_no_date = 0

    for v in vulns:
        if v.published_at is None:
            dropped_no_date += 1
            continue
        ts = v.published_at.replace(tzinfo=None)
        if window_start <= ts <= window_end:
            result.append(v)

    if dropped_no_date:
        logger.debug("Dropped %d vulns with no published_at", dropped_no_date)

    return result


def filter_events(
    events: list[ThreatEvent],
    window_start: datetime,
    window_end: datetime,
) -> list[ThreatEvent]:
    result = []
    dropped_no_date = 0

    for e in events:
        if e.published_at is None:
            dropped_no_date += 1
            continue
        ts = e.published_at.replace(tzinfo=None)
        if window_start <= ts <= window_end:
            result.append(e)

    if dropped_no_date:
        logger.debug("Dropped %d events with no published_at", dropped_no_date)

    return result

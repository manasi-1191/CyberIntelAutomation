"""
KEV enrichment step.

After deduplication, NVD records for CVEs that are also in the CISA KEV
catalog will have is_known_exploited=False because NVD does not publish
that data. This step corrects that by marking any deduplicated vulnerability
whose CVE ID appears in the KEV catalog.

Also backfills ransomware_use and kev_due_date from the catalog when the
winning record came from NVD rather than the CISA KEV collector.
"""
import logging
from datetime import datetime

from models.vulnerability import Vulnerability
from collectors.cisa_kev import fetch_kev_catalog

logger = logging.getLogger(__name__)


def enrich_with_kev(vulns: list[Vulnerability]) -> list[Vulnerability]:
    """
    Mark any vulnerability whose CVE ID is in the KEV catalog.
    Mutates in place and returns the same list.
    """
    try:
        catalog = fetch_kev_catalog()
    except Exception as exc:
        logger.error("Could not fetch KEV catalog for enrichment: %s", exc)
        return vulns

    enriched = 0
    for v in vulns:
        entry = catalog.get(v.cve_id.upper())
        if entry is None:
            continue
        if not v.is_known_exploited:
            v.is_known_exploited = True
            enriched += 1
        # Backfill KEV-specific fields if the NVD record won dedup
        if not v.ransomware_use:
            v.ransomware_use = entry.get("knownRansomwareCampaignUse", "Unknown")
        if not v.kev_due_date:
            v.kev_due_date = _parse_date(entry.get("dueDate", ""))

    if enriched:
        logger.info("KEV enrichment: marked %d additional CVEs as actively exploited", enriched)
    else:
        logger.debug("KEV enrichment: no new CVEs to mark (KEV collector records already won dedup)")

    return vulns


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None

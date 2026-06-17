"""
CISA Known Exploited Vulnerabilities (KEV) Catalog collector.
Public endpoint — no API key required.
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Also exposes fetch_kev_catalog() for use by the KEV enricher, so the catalog
is fetched once per process and reused without a second HTTP call.
"""
from datetime import datetime

from models.vulnerability import Vulnerability, Severity
from collectors.base import BaseCollector, get_http_client

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Module-level cache — populated on first call, reused within the same process run.
_catalog_cache: dict[str, dict] | None = None


def fetch_kev_catalog() -> dict[str, dict]:
    """
    Return the full KEV catalog as {cve_id: entry_dict}.
    Cached for the lifetime of the process — one HTTP call per run.
    """
    global _catalog_cache
    if _catalog_cache is not None:
        return _catalog_cache

    client = get_http_client()
    resp = client.get(_KEV_URL)
    resp.raise_for_status()
    data = resp.json()
    _catalog_cache = {
        e["cveID"]: e
        for e in data.get("vulnerabilities", [])
        if e.get("cveID")
    }
    return _catalog_cache


def _reset_catalog_cache() -> None:
    """For test isolation only — do not call in production code."""
    global _catalog_cache
    _catalog_cache = None


class CisaKevCollector(BaseCollector):
    name = "cisa_kev"

    def collect(self) -> tuple[list[Vulnerability], list]:
        self.logger.info("Fetching CISA KEV catalog")
        try:
            catalog = fetch_kev_catalog()
        except Exception as exc:
            self.logger.error("Failed to fetch CISA KEV: %s", exc)
            return [], []

        vulns: list[Vulnerability] = []

        for cve_id, entry in catalog.items():
            date_added = self._parse_date(entry.get("dateAdded", ""))
            if not self.within_window(date_added):
                continue

            vuln = Vulnerability(
                cve_id=cve_id,
                source=self.name,
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                description=entry.get("shortDescription", ""),
                affected_products=[
                    f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip()
                ],
                severity=Severity.CRITICAL,
                is_known_exploited=True,
                ransomware_use=entry.get("knownRansomwareCampaignUse", "Unknown"),
                kev_due_date=self._parse_date(entry.get("dueDate", "")),
                published_at=date_added,
            )
            vulns.append(vuln)

        self.logger.info("CISA KEV: %d entries within window", len(vulns))
        return vulns, []

    @staticmethod
    def _parse_date(value: str) -> datetime | None:
        if not value:
            return None
        for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        return None

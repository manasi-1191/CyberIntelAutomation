"""
CISA Known Exploited Vulnerabilities (KEV) Catalog collector.
Public endpoint — no API key required.
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from datetime import datetime

from models.vulnerability import Vulnerability, Severity
from collectors.base import BaseCollector

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevCollector(BaseCollector):
    name = "cisa_kev"

    def collect(self) -> tuple[list[Vulnerability], list]:
        self.logger.info("Fetching CISA KEV catalog")
        try:
            resp = self._get(_KEV_URL)
        except Exception as exc:
            self.logger.error("Failed to fetch CISA KEV: %s", exc)
            return [], []

        data = resp.json()
        vulns: list[Vulnerability] = []

        for entry in data.get("vulnerabilities", []):
            date_added = self._parse_date(entry.get("dateAdded", ""))
            if not self.within_window(date_added):
                continue

            vuln = Vulnerability(
                cve_id=entry.get("cveID", ""),
                source=self.name,
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                description=entry.get("shortDescription", ""),
                affected_products=[
                    f"{entry.get('vendorProject', '')} {entry.get('product', '')}".strip()
                ],
                severity=Severity.CRITICAL,   # KEV entries are always critical priority
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

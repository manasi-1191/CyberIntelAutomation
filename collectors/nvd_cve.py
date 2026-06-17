"""
NVD CVE API v2 collector.
https://nvd.nist.gov/developers/vulnerabilities
Optional API key in NVD_API_KEY env var — increases rate limit from 5/30s to 50/30s.
"""
import time
from datetime import datetime

from config.settings import settings
from models.vulnerability import Vulnerability, Severity, CVSSVector
from collectors.base import BaseCollector

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000


class NvdCveCollector(BaseCollector):
    name = "nvd"

    def collect(self) -> tuple[list[Vulnerability], list]:
        self.logger.info("Fetching NVD CVEs from %s to %s", self.window_start, self.window_end)

        headers = {}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key

        params = {
            "pubStartDate": self.window_start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": self.window_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": _PAGE_SIZE,
            "startIndex": 0,
        }

        vulns: list[Vulnerability] = []
        total = None

        while True:
            try:
                resp = self._get(_NVD_API, params=params, headers=headers)
            except Exception as exc:
                self.logger.error("NVD API request failed: %s", exc)
                break

            body = resp.json()
            if total is None:
                total = body.get("totalResults", 0)
                self.logger.info("NVD: %d total CVEs in window", total)

            for item in body.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                vuln = self._parse_cve(cve_data)
                if vuln:
                    vulns.append(vuln)

            fetched = params["startIndex"] + len(body.get("vulnerabilities", []))
            if fetched >= total:
                break

            params["startIndex"] = fetched
            # NVD rate limit: 5 requests per 30 seconds without key, 50 with key
            time.sleep(1.0 if settings.nvd_api_key else 6.5)

        self.logger.info("NVD: collected %d CVEs", len(vulns))
        return vulns, []

    def _parse_cve(self, cve: dict) -> Vulnerability | None:
        cve_id: str = cve.get("id", "")
        if not cve_id:
            return None

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        published_str = cve.get("published", "")
        modified_str = cve.get("lastModified", "")
        published = self._parse_nvd_date(published_str)
        modified = self._parse_nvd_date(modified_str)

        # Extract CVSS v3.1 metrics (preferred), fall back to v3.0 or v2
        cvss = self._extract_cvss(cve.get("metrics", {}))

        # Affected products from CPE matches
        products: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    product = self._cpe_to_product(cpe)
                    if product and product not in products:
                        products.append(product)

        # CWE IDs
        cwe_ids = [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]

        return Vulnerability(
            cve_id=cve_id,
            source=self.name,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            description=desc,
            affected_products=products[:20],  # cap for readability
            cvss=cvss,
            severity=Severity(cvss.severity) if cvss else Severity.UNKNOWN,
            cwe_ids=cwe_ids,
            published_at=published,
            modified_at=modified,
        )

    @staticmethod
    def _extract_cvss(metrics: dict) -> CVSSVector | None:
        for key, v_str in [
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0"),
        ]:
            items = metrics.get(key, [])
            if not items:
                continue
            data = items[0].get("cvssData", {})
            base_score = float(data.get("baseScore", 0.0))
            severity = data.get("baseSeverity", "UNKNOWN").upper()

            # v2 doesn't have baseSeverity — derive it
            if key == "cvssMetricV2" and not data.get("baseSeverity"):
                severity = _v2_severity(base_score)

            return CVSSVector(
                version=v_str,
                vector_string=data.get("vectorString", ""),
                base_score=base_score,
                severity=severity,
            )
        return None

    @staticmethod
    def _parse_nvd_date(value: str) -> datetime | None:
        if not value:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(value[:26], fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _cpe_to_product(cpe: str) -> str:
        parts = cpe.split(":")
        if len(parts) >= 5:
            vendor = parts[3].replace("_", " ").title()
            product = parts[4].replace("_", " ").title()
            return f"{vendor} {product}".strip()
        return ""


def _v2_severity(score: float) -> str:
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

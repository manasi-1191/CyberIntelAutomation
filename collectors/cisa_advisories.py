"""
CISA Advisories RSS feed collector.
https://www.cisa.gov/cybersecurity-advisories/all.xml
"""
from datetime import datetime

import feedparser
from dateutil import parser as dateutil_parser

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent, ThreatCategory
from collectors.base import BaseCollector

_ADVISORIES_RSS = "https://www.cisa.gov/cybersecurity-advisories/all.xml"


class CisaAdvisoriesCollector(BaseCollector):
    name = "cisa_advisory"

    def collect(self) -> tuple[list[Vulnerability], list[ThreatEvent]]:
        self.logger.info("Fetching CISA advisories RSS")
        try:
            resp = self._get(_ADVISORIES_RSS)
            feed = feedparser.parse(resp.text)
        except Exception as exc:
            self.logger.error("Failed to fetch CISA advisories: %s", exc)
            return [], []

        vulns: list[Vulnerability] = []
        events: list[ThreatEvent] = []

        for entry in feed.entries:
            published = self._parse_feed_date(entry.get("published", ""))
            if not self.within_window(published):
                continue

            title: str = entry.get("title", "")
            link: str = entry.get("link", "")
            summary: str = entry.get("summary", "")
            tags: list[str] = [t.get("term", "") for t in entry.get("tags", [])]

            # Advisories that reference CVEs become Vulnerability objects;
            # others become ThreatEvent objects (APT, ICS, etc.)
            if "ICS" in title or "Industrial" in title:
                event = ThreatEvent(
                    event_id=self._make_id(link or title),
                    source=self.name,
                    source_url=link,
                    title=title,
                    category=ThreatCategory.OTHER,
                    description=summary,
                    tags=tags,
                    published_at=published,
                )
                events.append(event)
            else:
                vuln = Vulnerability(
                    cve_id=self._extract_cve(title) or f"CISA-{self._make_id(title)[:8]}",
                    source=self.name,
                    source_url=link,
                    description=summary,
                    published_at=published,
                )
                vulns.append(vuln)

        self.logger.info(
            "CISA advisories: %d vulns, %d events within window",
            len(vulns),
            len(events),
        )
        return vulns, events

    @staticmethod
    def _parse_feed_date(value: str) -> datetime | None:
        if not value:
            return None
        try:
            return dateutil_parser.parse(value).replace(tzinfo=None)
        except Exception:
            return None

    @staticmethod
    def _extract_cve(text: str) -> str:
        import re
        match = re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)
        return match.group(0).upper() if match else ""

    @staticmethod
    def _make_id(text: str) -> str:
        import hashlib
        return hashlib.sha1(text.encode()).hexdigest()

"""
CISA Advisories RSS feed collector.
https://www.cisa.gov/cybersecurity-advisories/all.xml

Routing logic:
  - Entry title contains a real CVE ID     → Vulnerability
  - Entry title references ICS/Industrial  → ThreatEvent (ICS category)
  - Everything else without a real CVE ID  → ThreatEvent (advisory category)

Previously, entries without a CVE ID were given a fabricated CISA-{hash}
identifier and stored as Vulnerability objects, polluting the CVE list with
non-CVE records. This version routes them correctly.
"""
import re
import hashlib
from datetime import datetime

import feedparser
from dateutil import parser as dateutil_parser

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent, ThreatCategory
from collectors.base import BaseCollector

_ADVISORIES_RSS = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


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
            published = _parse_date(entry.get("published", ""))
            if not self.within_window(published):
                continue

            title: str = entry.get("title", "")
            link: str = entry.get("link", "")
            summary: str = entry.get("summary", "")
            tags: list[str] = [t.get("term", "") for t in entry.get("tags", [])]
            cve_id = _extract_cve(title)

            if cve_id:
                # Real CVE reference → Vulnerability
                vulns.append(Vulnerability(
                    cve_id=cve_id,
                    source=self.name,
                    source_url=link,
                    description=summary,
                    published_at=published,
                ))
            else:
                # No CVE ID — route to ThreatEvent regardless of ICS/non-ICS
                is_ics = "ICS" in title or "Industrial" in title or "SCADA" in title
                events.append(ThreatEvent(
                    event_id=_make_id(link or title),
                    source=self.name,
                    source_url=link,
                    title=title,
                    category=ThreatCategory.OTHER,
                    description=summary,
                    tags=tags + (["ics"] if is_ics else []),
                    published_at=published,
                ))

        self.logger.info(
            "CISA advisories: %d vulns, %d events within window",
            len(vulns),
            len(events),
        )
        return vulns, events


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return dateutil_parser.parse(value).replace(tzinfo=None)
    except Exception:
        return None


def _extract_cve(text: str) -> str:
    match = _CVE_RE.search(text)
    return match.group(0).upper() if match else ""


def _make_id(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()

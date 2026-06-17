"""
Generic RSS/Atom feed collector for cybersecurity news sources.
Add or remove feeds from FEEDS without touching any other code.

Feed status as of 2026-06-17:
  thehackernews    — active, ~19 articles/48h
  bleepingcomputer — active, ~15 articles/48h (feed capped at 15)
  krebsonsecurity  — active, low frequency (~0-2 articles/48h)
  sans_isc         — active, daily posts (replaced dead Threatpost feed)
  darkreading      — active, ~8 articles/48h
  threatpost       — REMOVED: feed dead since Aug 2022, no new content
"""
import hashlib
from datetime import datetime
from typing import NamedTuple

import feedparser
from dateutil import parser as dateutil_parser

from models.threat import ThreatEvent, ThreatCategory
from collectors.base import BaseCollector


class FeedConfig(NamedTuple):
    url: str
    name: str
    category: ThreatCategory


FEEDS: list[FeedConfig] = [
    FeedConfig(
        url="https://feeds.feedburner.com/TheHackersNews",
        name="thehackernews",
        category=ThreatCategory.OTHER,
    ),
    FeedConfig(
        url="https://www.bleepingcomputer.com/feed/",
        name="bleepingcomputer",
        category=ThreatCategory.OTHER,
    ),
    FeedConfig(
        url="https://krebsonsecurity.com/feed/",
        name="krebsonsecurity",
        category=ThreatCategory.OTHER,
    ),
    FeedConfig(
        url="https://isc.sans.edu/rssfeed_full.xml",
        name="sans_isc",
        category=ThreatCategory.OTHER,
    ),
    FeedConfig(
        url="https://www.darkreading.com/rss.xml",
        name="darkreading",
        category=ThreatCategory.OTHER,
    ),
]

_BREACH_KEYWORDS = {"breach", "leak", "exposed", "stolen", "compromised", "exfiltrated"}
_ATTACK_KEYWORDS = {"attack", "malware", "ransomware", "phishing", "exploit", "backdoor", "trojan"}
_APT_KEYWORDS = {"apt", "nation-state", "espionage", "state-sponsored"}


class RssFeedCollector(BaseCollector):
    name = "rss"

    def collect(self) -> tuple[list, list[ThreatEvent]]:
        events: list[ThreatEvent] = []
        per_feed: dict[str, int] = {}

        for feed_cfg in FEEDS:
            feed_events = self._collect_feed(feed_cfg)
            per_feed[feed_cfg.name] = len(feed_events)
            events.extend(feed_events)

        self.logger.info(
            "RSS feeds: %d events within window %s",
            len(events),
            {k: v for k, v in per_feed.items() if v > 0},
        )
        return [], events

    def _collect_feed(self, cfg: FeedConfig) -> list[ThreatEvent]:
        self.logger.debug("Fetching RSS: %s", cfg.url)
        try:
            resp = self._get(cfg.url)
            feed = feedparser.parse(resp.text)
        except Exception as exc:
            self.logger.warning("Failed to fetch %s: %s", cfg.name, exc)
            return []

        events: list[ThreatEvent] = []
        for entry in feed.entries:
            published = _parse_date(entry.get("published", "") or entry.get("updated", ""))
            if not self.within_window(published):
                continue

            title: str = entry.get("title", "")
            link: str = entry.get("link", "")
            summary: str = entry.get("summary", "")
            text = (title + " " + summary).lower()

            category = _classify(text, cfg.category)
            cve_refs = _extract_cves(title + " " + summary)

            events.append(ThreatEvent(
                event_id=_make_id(link or title, published),
                source=cfg.name,
                source_url=link,
                title=title,
                category=category,
                description=summary,
                cve_references=cve_refs,
                published_at=published,
            ))

        return events


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return dateutil_parser.parse(value).replace(tzinfo=None)
    except Exception:
        return None


def _classify(text: str, default: ThreatCategory) -> ThreatCategory:
    if any(k in text for k in _APT_KEYWORDS):
        return ThreatCategory.APT
    if "ransomware" in text:
        return ThreatCategory.RANSOMWARE
    if any(k in text for k in _BREACH_KEYWORDS):
        return ThreatCategory.DATA_BREACH
    if any(k in text for k in _ATTACK_KEYWORDS):
        return ThreatCategory.CYBER_ATTACK
    return default


def _extract_cves(text: str) -> list[str]:
    import re
    return list({m.upper() for m in re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE)})


def _make_id(text: str, dt: datetime | None) -> str:
    stamp = dt.isoformat() if dt else ""
    return hashlib.sha1(f"{text}{stamp}".encode()).hexdigest()

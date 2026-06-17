"""
Tests for all five Phase 2.5 data quality fixes.

Fix 1: Cross-run dedup removed — within-run only
Fix 2: KEV enrichment marks NVD records
Fix 3: Prioritization and ranking
Fix 4: CISA advisory fake IDs removed
Fix 5: Threatpost removed, SANS ISC added
"""
import hashlib
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from models.vulnerability import Vulnerability, Severity, CVSSVector
from models.threat import ThreatEvent, ThreatCategory
from pipeline.deduplicator import deduplicate, _vuln_key, _event_key
from pipeline.enricher import enrich_with_kev
from pipeline.prioritizer import assign_priority_tiers, get_featured_vulnerabilities, _tier
from collectors.rss_feeds import FEEDS
from collectors.cisa_advisories import CisaAdvisoriesCollector, _extract_cve

NOW = datetime(2026, 6, 17, 12, 0, 0)
WIN_START = NOW - timedelta(hours=48)
WIN_END = NOW


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vuln(cve_id: str, severity=Severity.HIGH, cvss_score: float = 7.5,
          is_kev: bool = False) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        source="test",
        severity=severity,
        cvss=CVSSVector(version="3.1", base_score=cvss_score, severity=severity),
        is_known_exploited=is_kev,
        published_at=NOW - timedelta(hours=1),
    )


def _event(event_id: str, url: str = "") -> ThreatEvent:
    return ThreatEvent(
        event_id=event_id,
        source="test",
        source_url=url or f"https://example.com/{event_id}",
        published_at=NOW - timedelta(hours=1),
    )


# ── Fix 1: Cross-run deduplication ───────────────────────────────────────────

class TestWithinRunDedup:
    def test_same_cve_from_two_sources_deduped_within_run(self):
        """CVE appearing from both CISA and NVD in one run → kept once."""
        kev_entry = _vuln("CVE-2026-1111", is_kev=True)
        kev_entry.source = "cisa_kev"
        nvd_entry = _vuln("CVE-2026-1111")
        nvd_entry.source = "nvd"

        unique, _, dupes = deduplicate([kev_entry, nvd_entry], [])
        assert len(unique) == 1
        assert dupes == 1

    def test_different_cves_both_kept(self):
        """Different CVEs → both kept."""
        v1 = _vuln("CVE-2026-1111")
        v2 = _vuln("CVE-2026-2222")
        unique, _, dupes = deduplicate([v1, v2], [])
        assert len(unique) == 2
        assert dupes == 0

    def test_second_call_does_not_suppress_first_run_items(self):
        """
        Two independent calls to deduplicate() — simulating two separate daily runs.
        Items from run 1 must NOT be suppressed in run 2 (no cross-run persistence).
        """
        run1_vulns = [_vuln("CVE-2026-9999")]
        unique1, _, _ = deduplicate(run1_vulns, [])
        assert len(unique1) == 1

        # Same CVE in run 2 — must pass, not be suppressed
        run2_vulns = [_vuln("CVE-2026-9999")]
        unique2, _, dupes2 = deduplicate(run2_vulns, [])
        assert len(unique2) == 1, "Cross-run dedup must not suppress items from previous runs"
        assert dupes2 == 0

    def test_vuln_and_event_use_separate_hash_spaces(self):
        """A vuln and an event with the same SHA-1 key cannot false-dedup each other."""
        v = _vuln("CVE-2026-7777")
        e = _event("e1", url="https://example.com/CVE-2026-7777")
        # Force vuln key and event key to be the same value to test isolation
        v.cve_id = "CVE-2026-7777"

        unique_vulns, unique_events, dupes = deduplicate([v], [e])
        assert len(unique_vulns) == 1
        assert len(unique_events) == 1
        assert dupes == 0

    def test_dedup_stamps_hash_on_records(self):
        """dedup_hash must be set on every record that passes through."""
        v = _vuln("CVE-2026-1234")
        e = _event("e1")
        unique_vulns, unique_events, _ = deduplicate([v], [e])
        assert unique_vulns[0].dedup_hash != ""
        assert unique_events[0].dedup_hash != ""

    def test_duplicate_events_by_url(self):
        """Two events with the same source_url → deduplicated within run."""
        e1 = _event("e1", url="https://example.com/story")
        e2 = _event("e2", url="https://example.com/story")
        _, unique_events, dupes = deduplicate([], [e1, e2])
        assert len(unique_events) == 1
        assert dupes == 1


# ── Fix 2: KEV enrichment ─────────────────────────────────────────────────────

class TestKevEnrichment:
    _FAKE_CATALOG = {
        "CVE-2026-9001": {
            "cveID": "CVE-2026-9001",
            "knownRansomwareCampaignUse": "Known",
            "dueDate": "2026-06-30",
        }
    }

    def test_nvd_record_gets_kev_flag(self):
        """NVD record for a KEV CVE must have is_known_exploited set to True."""
        v = _vuln("CVE-2026-9001")
        assert v.is_known_exploited is False

        with patch("pipeline.enricher.fetch_kev_catalog", return_value=self._FAKE_CATALOG):
            result = enrich_with_kev([v])

        assert result[0].is_known_exploited is True

    def test_ransomware_use_backfilled(self):
        """ransomware_use must be backfilled from KEV catalog when NVD record won dedup."""
        v = _vuln("CVE-2026-9001")
        v.ransomware_use = None

        with patch("pipeline.enricher.fetch_kev_catalog", return_value=self._FAKE_CATALOG):
            enrich_with_kev([v])

        assert v.ransomware_use == "Known"

    def test_kev_due_date_backfilled(self):
        """kev_due_date must be backfilled when NVD record won dedup."""
        v = _vuln("CVE-2026-9001")
        v.kev_due_date = None

        with patch("pipeline.enricher.fetch_kev_catalog", return_value=self._FAKE_CATALOG):
            enrich_with_kev([v])

        assert v.kev_due_date is not None
        assert v.kev_due_date.strftime("%Y-%m-%d") == "2026-06-30"

    def test_non_kev_cve_unchanged(self):
        """CVE not in KEV catalog must not be modified."""
        v = _vuln("CVE-2026-0000")
        with patch("pipeline.enricher.fetch_kev_catalog", return_value=self._FAKE_CATALOG):
            enrich_with_kev([v])
        assert v.is_known_exploited is False

    def test_existing_kev_flag_not_cleared(self):
        """CVE already marked as KEV (from CISA KEV collector) must not be changed."""
        v = _vuln("CVE-2026-9001", is_kev=True)
        v.ransomware_use = "Unknown"  # already set

        with patch("pipeline.enricher.fetch_kev_catalog", return_value=self._FAKE_CATALOG):
            enrich_with_kev([v])

        assert v.is_known_exploited is True

    def test_catalog_fetch_error_returns_vulns_unchanged(self):
        """If the KEV catalog fetch fails, vulns are returned as-is without crashing."""
        v = _vuln("CVE-2026-9001")
        with patch("pipeline.enricher.fetch_kev_catalog", side_effect=Exception("network")):
            result = enrich_with_kev([v])
        assert result[0].is_known_exploited is False
        assert len(result) == 1


# ── Fix 3: Prioritization ─────────────────────────────────────────────────────

class TestPrioritizer:
    def test_kev_is_tier_0(self):
        v = _vuln("CVE-1", is_kev=True)
        assert _tier(v) == 0

    def test_critical_high_cvss_is_tier_1(self):
        v = _vuln("CVE-1", severity=Severity.CRITICAL, cvss_score=9.8)
        assert _tier(v) == 1

    def test_critical_low_cvss_is_tier_2(self):
        v = _vuln("CVE-1", severity=Severity.CRITICAL, cvss_score=7.5)
        assert _tier(v) == 2

    def test_high_is_tier_3(self):
        v = _vuln("CVE-1", severity=Severity.HIGH)
        assert _tier(v) == 3

    def test_medium_is_tier_4(self):
        v = _vuln("CVE-1", severity=Severity.MEDIUM)
        assert _tier(v) == 4

    def test_low_is_tier_5(self):
        v = _vuln("CVE-1", severity=Severity.LOW)
        assert _tier(v) == 5

    def test_kev_overrides_severity_tier(self):
        """A HIGH severity CVE that is actively exploited must be tier 0, not tier 3."""
        v = _vuln("CVE-1", severity=Severity.HIGH, is_kev=True)
        assert _tier(v) == 0

    def test_assign_priority_tiers_sorts_correctly(self):
        vulns = [
            _vuln("CVE-A", severity=Severity.MEDIUM),
            _vuln("CVE-B", severity=Severity.CRITICAL, cvss_score=9.8),
            _vuln("CVE-C", is_kev=True),
            _vuln("CVE-D", severity=Severity.HIGH),
        ]
        ranked = assign_priority_tiers(vulns)
        tiers = [v.priority_tier for v in ranked]
        assert tiers == sorted(tiers), "Vulns must be sorted by tier ascending"
        assert ranked[0].cve_id == "CVE-C"   # KEV first

    def test_featured_excludes_medium_and_low(self):
        vulns = [
            _vuln("KEV-1", is_kev=True),
            _vuln("CRIT-1", severity=Severity.CRITICAL, cvss_score=9.5),
            _vuln("MED-1", severity=Severity.MEDIUM),
            _vuln("LOW-1", severity=Severity.LOW),
        ]
        assign_priority_tiers(vulns)
        featured = get_featured_vulnerabilities(vulns)
        featured_ids = {v.cve_id for v in featured}
        assert "KEV-1" in featured_ids
        assert "CRIT-1" in featured_ids
        assert "MED-1" not in featured_ids
        assert "LOW-1" not in featured_ids

    def test_featured_respects_max_cap(self):
        """Featured list must never exceed MAX_FEATURED (30)."""
        from pipeline.prioritizer import MAX_FEATURED
        vulns = [_vuln(f"CVE-{i}", severity=Severity.CRITICAL, cvss_score=9.9)
                 for i in range(50)]
        assign_priority_tiers(vulns)
        featured = get_featured_vulnerabilities(vulns)
        assert len(featured) <= MAX_FEATURED

    def test_kev_always_in_featured(self):
        """KEV entries must always appear in featured regardless of other items."""
        vulns = [
            _vuln("CVE-KEV", is_kev=True),
            *[_vuln(f"CVE-{i}", severity=Severity.CRITICAL, cvss_score=9.9)
              for i in range(50)],
        ]
        assign_priority_tiers(vulns)
        featured = get_featured_vulnerabilities(vulns)
        assert any(v.cve_id == "CVE-KEV" for v in featured)


# ── Fix 4: CISA advisory fake IDs ────────────────────────────────────────────

class TestCisaAdvisoryRouting:
    def test_extract_cve_finds_cve_id(self):
        assert _extract_cve("Multiple Vulnerabilities in Cisco (CVE-2026-1234)") == "CVE-2026-1234"

    def test_extract_cve_returns_empty_when_absent(self):
        assert _extract_cve("CISA Releases Advisory on ICS Products") == ""

    def test_extract_cve_case_insensitive(self):
        assert _extract_cve("critical cve-2026-9999 found") == "CVE-2026-9999"

    def test_no_fake_cve_ids_in_vulnerability_list(self):
        """
        Any advisory without a real CVE ID must become a ThreatEvent,
        never a Vulnerability with a fabricated CISA-{hash} ID.
        """
        import respx, httpx
        from datetime import datetime, timedelta

        now = datetime(2026, 6, 17, 12, 0, 0)
        win_start = now - timedelta(hours=48)

        advisory_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>CISA Advisories</title>
    <item>
      <title>CISA Releases Advisory on ICS Products With No CVE</title>
      <link>https://www.cisa.gov/test-advisory</link>
      <pubDate>Tue, 17 Jun 2026 10:00:00 GMT</pubDate>
      <description>Advisory with no CVE reference.</description>
    </item>
    <item>
      <title>Critical Vulnerability CVE-2026-5555 in Apache</title>
      <link>https://www.cisa.gov/cve-advisory</link>
      <pubDate>Tue, 17 Jun 2026 11:00:00 GMT</pubDate>
      <description>Apache vulnerability.</description>
    </item>
  </channel>
</rss>"""

        with respx.mock:
            respx.get("https://www.cisa.gov/cybersecurity-advisories/all.xml").mock(
                return_value=httpx.Response(200, text=advisory_rss)
            )
            collector = CisaAdvisoriesCollector(win_start, now)
            vulns, events = collector.collect()

        # No fake CISA-{hash} IDs in vulns
        for v in vulns:
            assert v.cve_id.startswith("CVE-"), (
                f"Fabricated CVE ID found: {v.cve_id!r} — must be a real CVE ID or routed to ThreatEvent"
            )

        # The no-CVE entry must have become a ThreatEvent
        assert len(events) >= 1, "Non-CVE advisory must become a ThreatEvent"
        # The real CVE entry must have become a Vulnerability
        assert len(vulns) >= 1
        assert vulns[0].cve_id == "CVE-2026-5555"


# ── Fix 5: Feed list ─────────────────────────────────────────────────────────

class TestFeedList:
    def test_threatpost_not_in_feeds(self):
        feed_names = {f.name for f in FEEDS}
        assert "threatpost" not in feed_names, (
            "Threatpost was removed because its feed has been dead since Aug 2022"
        )

    def test_sans_isc_in_feeds(self):
        feed_names = {f.name for f in FEEDS}
        assert "sans_isc" in feed_names

    def test_sans_isc_url(self):
        sans = next(f for f in FEEDS if f.name == "sans_isc")
        assert "isc.sans.edu" in sans.url

    def test_expected_feeds_present(self):
        feed_names = {f.name for f in FEEDS}
        expected = {"thehackernews", "bleepingcomputer", "krebsonsecurity", "sans_isc", "darkreading"}
        assert expected == feed_names

"""
Collector tests use respx to mock HTTP without hitting live APIs.

Note: CisaKevCollector uses a module-level catalog cache (one HTTP call per
process). Each test that exercises different catalog content must reset it
via _reset_catalog_cache() so the mock is actually invoked.
"""
from datetime import datetime, timedelta

import pytest
import respx
import httpx

from collectors.cisa_kev import CisaKevCollector, _reset_catalog_cache
from collectors.rss_feeds import RssFeedCollector, FEEDS

NOW = datetime(2026, 6, 17, 12, 0, 0)
WIN_START = NOW - timedelta(hours=48)
WIN_END = NOW


@pytest.fixture(autouse=True)
def reset_kev_cache():
    """Reset the KEV catalog cache before every test in this module."""
    _reset_catalog_cache()
    yield
    _reset_catalog_cache()


def _kev_payload(date_added: str) -> dict:
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-99999",
                "dateAdded": date_added,
                "shortDescription": "Test vuln",
                "vendorProject": "Acme",
                "product": "Widget",
                "knownRansomwareCampaignUse": "Known",
                "dueDate": "2026-07-01",
            }
        ]
    }


@respx.mock
def test_cisa_kev_within_window():
    respx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(
        return_value=httpx.Response(200, json=_kev_payload("2026-06-16"))
    )
    collector = CisaKevCollector(WIN_START, WIN_END)
    vulns, events = collector.collect()
    assert len(vulns) == 1
    assert vulns[0].cve_id == "CVE-2026-99999"
    assert vulns[0].is_known_exploited is True
    assert events == []


@respx.mock
def test_cisa_kev_outside_window():
    respx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(
        return_value=httpx.Response(200, json=_kev_payload("2026-01-01"))
    )
    collector = CisaKevCollector(WIN_START, WIN_END)
    vulns, _ = collector.collect()
    assert vulns == []


@respx.mock
def test_cisa_kev_network_error_returns_empty():
    respx.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json").mock(
        side_effect=httpx.NetworkError("down")
    )
    collector = CisaKevCollector(WIN_START, WIN_END)
    vulns, events = collector.collect()
    assert vulns == []
    assert events == []

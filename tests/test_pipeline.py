from datetime import datetime, timedelta

from models.vulnerability import Vulnerability, Severity
from models.threat import ThreatEvent, ThreatCategory
from pipeline.filter import filter_vulnerabilities, filter_events
from pipeline.normalizer import normalize_vulnerabilities, normalize_events
from pipeline.report_builder import build_report

NOW = datetime(2026, 6, 17, 12, 0, 0)
WIN_START = NOW - timedelta(hours=48)
WIN_END = NOW


def _vuln(cve_id: str, published: datetime, severity=Severity.HIGH) -> Vulnerability:
    return Vulnerability(cve_id=cve_id, source="test", published_at=published, severity=severity)


def _event(event_id: str, published: datetime, category=ThreatCategory.CYBER_ATTACK) -> ThreatEvent:
    return ThreatEvent(event_id=event_id, source="test", published_at=published, category=category)


def test_filter_keeps_items_in_window():
    inside = _vuln("CVE-2026-1111", NOW - timedelta(hours=10))
    outside = _vuln("CVE-2026-2222", NOW - timedelta(hours=100))
    result = filter_vulnerabilities([inside, outside], WIN_START, WIN_END)
    assert len(result) == 1
    assert result[0].cve_id == "CVE-2026-1111"


def test_filter_drops_items_without_date():
    no_date = Vulnerability(cve_id="CVE-2026-3333", source="test")
    result = filter_vulnerabilities([no_date], WIN_START, WIN_END)
    assert result == []


def test_filter_events():
    inside = _event("e1", NOW - timedelta(hours=24))
    outside = _event("e2", NOW - timedelta(days=10))
    result = filter_events([inside, outside], WIN_START, WIN_END)
    assert len(result) == 1


def test_normalizer_strips_html():
    v = Vulnerability(cve_id="CVE-2026-4444", source="test", description="<b>Bold</b> &amp; text")
    normed = normalize_vulnerabilities([v])
    assert "<b>" not in normed[0].description
    assert "&amp;" not in normed[0].description
    assert "Bold" in normed[0].description


def test_normalizer_uppercases_cve_id():
    v = Vulnerability(cve_id="cve-2026-5555", source="test")
    normed = normalize_vulnerabilities([v])
    assert normed[0].cve_id == "CVE-2026-5555"


def test_report_builder_counts():
    vulns = [
        _vuln("CVE-2026-0001", NOW - timedelta(hours=1), Severity.CRITICAL),
        _vuln("CVE-2026-0002", NOW - timedelta(hours=2), Severity.HIGH),
    ]
    vulns[0].is_known_exploited = True

    events = [
        _event("e1", NOW - timedelta(hours=3), ThreatCategory.DATA_BREACH),
        _event("e2", NOW - timedelta(hours=4), ThreatCategory.CYBER_ATTACK),
    ]

    report = build_report("2026-06-17", WIN_START, WIN_END, vulns, events, 48)
    assert report.critical_cve_count == 1
    assert report.high_cve_count == 1
    assert report.kev_count == 1
    assert report.breach_count == 1
    assert report.attack_count == 1

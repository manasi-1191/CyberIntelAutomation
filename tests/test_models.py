from datetime import datetime
from models.vulnerability import Vulnerability, Severity, CVSSVector
from models.threat import ThreatEvent, ThreatCategory
from models.report import DailyReport, ApprovalStatus
from models.audit import AuditEntry, AuditAction


def test_vulnerability_defaults():
    v = Vulnerability(cve_id="CVE-2024-1234", source="nvd")
    assert v.severity == Severity.UNKNOWN
    assert v.is_known_exploited is False
    assert v.affected_products == []


def test_vulnerability_with_cvss():
    v = Vulnerability(
        cve_id="CVE-2024-9999",
        source="nvd",
        cvss=CVSSVector(version="3.1", base_score=9.8, severity=Severity.CRITICAL),
        severity=Severity.CRITICAL,
    )
    assert v.cvss.base_score == 9.8
    assert v.severity == Severity.CRITICAL


def test_threat_event_defaults():
    e = ThreatEvent(event_id="abc123", source="rss")
    assert e.category == ThreatCategory.OTHER
    assert e.cve_references == []


def test_daily_report_defaults():
    now = datetime.utcnow()
    r = DailyReport(
        report_id="2026-06-17",
        window_start=now,
        window_end=now,
    )
    assert r.approval_status == ApprovalStatus.PENDING
    assert r.vulnerabilities == []


def test_audit_entry():
    entry = AuditEntry(action=AuditAction.COLLECTION_STARTED, report_id="2026-06-17")
    assert entry.success is True
    assert entry.error_message == ""

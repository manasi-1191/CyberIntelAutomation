"""
Tests for Phase 2 email components.
- composer: verifies email structure without sending
- approval_poller: verifies APPROVE/REJECT/attachment parsing logic
"""
import base64
from datetime import datetime
from email import message_from_bytes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest

from models.report import DailyReport, ApprovalStatus
from models.vulnerability import Vulnerability, Severity
from models.threat import ThreatEvent, ThreatCategory
from emailer.composer import build_approval_email
from emailer.approval_poller import (
    ApprovalPollResult,
    _parse_message,
    _extract_body,
    _extract_txt_attachment,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_report() -> DailyReport:
    now = datetime(2026, 6, 17, 12, 0, 0)
    return DailyReport(
        report_id="2026-06-17",
        window_start=now,
        window_end=now,
        executive_summary="Three critical vulnerabilities actively exploited in the wild.",
        detailed_summary="Security researchers identified widespread exploitation of CVE-2026-0001.",
        critical_cve_count=3,
        high_cve_count=5,
        kev_count=2,
        breach_count=1,
        attack_count=4,
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2026-0001",
                source="nvd",
                severity=Severity.CRITICAL,
                is_known_exploited=True,
                description="Remote code execution in Acme Widget.",
            )
        ],
    )


def _make_gmail_message(body_text: str, from_addr: str, attachment: str = "") -> dict:
    """Build a minimal Gmail API message dict from a plain text body."""
    mime = MIMEMultipart("mixed") if attachment else MIMEMultipart("alternative")
    mime["From"] = from_addr
    mime["To"] = "test@example.com"
    mime["Subject"] = "Re: [CyberIntel]"
    mime.attach(MIMEText(body_text, "plain", "utf-8"))

    if attachment:
        att = MIMEText(attachment, "plain", "utf-8")
        att.add_header("Content-Disposition", 'attachment; filename="edit.txt"')
        mime.attach(att)

    raw_bytes = mime.as_bytes()
    encoded = base64.urlsafe_b64encode(raw_bytes).decode()

    headers = [
        {"name": "From", "value": from_addr},
        {"name": "Subject", "value": "Re: [CyberIntel]"},
    ]
    return {
        "id": "reply-msg-id",
        "payload": {
            "headers": headers,
            "body": {"data": encoded},
            "parts": [],
        },
    }


# ── Composer tests ─────────────────────────────────────────────────────────────

def test_composer_returns_mime_message():
    report = _make_report()
    msg = build_approval_email(report)
    assert isinstance(msg, MIMEMultipart)


def test_composer_subject_contains_date():
    report = _make_report()
    msg = build_approval_email(report)
    assert "June 17, 2026" in msg["Subject"]
    assert "Approval Required" in msg["Subject"]


def test_composer_has_plain_and_html_parts():
    report = _make_report()
    msg = build_approval_email(report)
    content_types = [part.get_content_type() for part in msg.get_payload()]
    assert "text/plain" in content_types
    assert "text/html" in content_types


def test_composer_plain_contains_summaries():
    report = _make_report()
    msg = build_approval_email(report)
    plain_part = next(p for p in msg.get_payload() if p.get_content_type() == "text/plain")
    plain_text = plain_part.get_payload(decode=True).decode("utf-8")
    assert report.executive_summary in plain_text
    assert report.detailed_summary in plain_text


def test_composer_plain_contains_stats():
    report = _make_report()
    msg = build_approval_email(report)
    plain_part = next(p for p in msg.get_payload() if p.get_content_type() == "text/plain")
    plain_text = plain_part.get_payload(decode=True).decode("utf-8")
    assert "3" in plain_text   # critical_cve_count
    assert "2" in plain_text   # kev_count
    assert "APPROVE" in plain_text
    assert "REJECT" in plain_text


def test_composer_html_contains_cve():
    report = _make_report()
    msg = build_approval_email(report)
    html_part = next(p for p in msg.get_payload() if p.get_content_type() == "text/html")
    html_text = html_part.get_payload(decode=True).decode("utf-8")
    assert "CVE-2026-0001" in html_text
    assert "Exploited" in html_text   # KEV badge


def test_composer_plain_contains_report_id():
    report = _make_report()
    msg = build_approval_email(report)
    plain_part = next(p for p in msg.get_payload() if p.get_content_type() == "text/plain")
    plain_text = plain_part.get_payload(decode=True).decode("utf-8")
    assert "2026-06-17" in plain_text


# ── Approval parser tests ──────────────────────────────────────────────────────

def test_parse_approve_keyword(monkeypatch):
    monkeypatch.setenv("APPROVAL_EMAIL_RECIPIENT", "approver@example.com")
    # Re-import settings to pick up monkeypatched env
    import importlib
    import config.settings as cs
    importlib.reload(cs)
    import emailer.approval_poller as ap
    importlib.reload(ap)

    msg = _make_gmail_message("APPROVE", "approver@example.com")
    result = ap._parse_message(msg, "approver@example.com")
    assert result is not None
    assert result.status == "approved"


def test_parse_reject_keyword(monkeypatch):
    monkeypatch.setenv("APPROVAL_EMAIL_RECIPIENT", "approver@example.com")
    import importlib
    import emailer.approval_poller as ap
    importlib.reload(ap)

    msg = _make_gmail_message("REJECT", "approver@example.com")
    result = ap._parse_message(msg, "approver@example.com")
    assert result is not None
    assert result.status == "rejected"


def test_parse_edited_approval_attachment(monkeypatch):
    monkeypatch.setenv("APPROVAL_EMAIL_RECIPIENT", "approver@example.com")
    import importlib
    import emailer.approval_poller as ap
    importlib.reload(ap)

    custom = "Custom LinkedIn post content here."
    msg = _make_gmail_message("Here is my edit.", "approver@example.com", attachment=custom)
    result = ap._parse_message(msg, "approver@example.com")
    assert result is not None
    assert result.status == "edited_approved"
    assert "Custom LinkedIn" in result.content


def test_parse_ambiguous_returns_none(monkeypatch):
    monkeypatch.setenv("APPROVAL_EMAIL_RECIPIENT", "approver@example.com")
    import importlib
    import emailer.approval_poller as ap
    importlib.reload(ap)

    msg = _make_gmail_message("Thanks, I'll review this later.", "approver@example.com")
    result = ap._parse_message(msg, "approver@example.com")
    assert result is None


def test_parse_case_insensitive_approve(monkeypatch):
    monkeypatch.setenv("APPROVAL_EMAIL_RECIPIENT", "approver@example.com")
    import importlib
    import emailer.approval_poller as ap
    importlib.reload(ap)

    msg = _make_gmail_message("approve", "approver@example.com")
    result = ap._parse_message(msg, "approver@example.com")
    assert result is not None
    assert result.status == "approved"

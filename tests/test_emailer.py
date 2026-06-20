"""
Tests for Phase 2 email components.
- composer: verifies email structure without sending
- approval_poller: verifies APPROVE/REJECT/attachment parsing logic
"""
import base64
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from unittest.mock import MagicMock

import pytest

from models.report import DailyReport, ApprovalStatus
from models.vulnerability import Vulnerability, Severity
from models.threat import ThreatEvent, ThreatCategory
from emailer.composer import build_approval_email
from emailer.approval_poller import ApprovalPollResult


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


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode()


def _make_gmail_message(body_text: str, from_addr: str, attachment: str = "") -> dict:
    """
    Build a Gmail API-format message dict (format='full' structure).

    For simple text replies, body.data holds the base64-encoded text content.
    For replies with a .txt attachment, the structure uses multipart parts with
    an inline attachment (body.data on the attachment part — no attachmentId
    needed, so no service call is required in tests).
    """
    headers = [
        {"name": "From", "value": from_addr},
        {"name": "Subject", "value": "Re: [CyberIntel]"},
    ]
    if attachment:
        return {
            "id": "reply-msg-id",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": headers,
                "body": {"size": 0},
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "filename": "",
                        "body": {"data": _b64(body_text)},
                    },
                    {
                        "mimeType": "text/plain",
                        "filename": "edit.txt",
                        "body": {"data": _b64(attachment)},
                    },
                ],
            },
        }
    return {
        "id": "reply-msg-id",
        "payload": {
            "mimeType": "text/plain",
            "headers": headers,
            "body": {"data": _b64(body_text)},
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

def test_parse_approve_keyword():
    from emailer.approval_poller import _parse_message
    msg = _make_gmail_message("APPROVE", "approver@example.com")
    result = _parse_message(MagicMock(), msg, "approver@example.com")
    assert result is not None
    assert result.status == "approved"


def test_parse_reject_keyword():
    from emailer.approval_poller import _parse_message
    msg = _make_gmail_message("REJECT", "approver@example.com")
    result = _parse_message(MagicMock(), msg, "approver@example.com")
    assert result is not None
    assert result.status == "rejected"


def test_parse_edited_approval_attachment():
    from emailer.approval_poller import _parse_message
    custom = "Custom LinkedIn post content here."
    msg = _make_gmail_message("Here is my edit.", "approver@example.com", attachment=custom)
    result = _parse_message(MagicMock(), msg, "approver@example.com")
    assert result is not None
    assert result.status == "edited_approved"
    assert "Custom LinkedIn" in result.content


def test_parse_ambiguous_returns_none():
    from emailer.approval_poller import _parse_message
    msg = _make_gmail_message("Thanks, I'll review this later.", "approver@example.com")
    result = _parse_message(MagicMock(), msg, "approver@example.com")
    assert result is None


def test_parse_case_insensitive_approve():
    from emailer.approval_poller import _parse_message
    msg = _make_gmail_message("approve", "approver@example.com")
    result = _parse_message(MagicMock(), msg, "approver@example.com")
    assert result is not None
    assert result.status == "approved"

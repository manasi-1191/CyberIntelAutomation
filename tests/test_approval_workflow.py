"""
Tests for the approval workflow changes:
- Approval email contains the LinkedIn Preview verbatim.
- APPROVE publishes linkedin_preview (not detailed_summary).
- .txt attachment overrides linkedin_preview.
- Empty linkedin_preview blocks publishing.
- linkedin_preview containing PLACEHOLDER blocks publishing.
"""
from datetime import datetime
from unittest.mock import MagicMock, patch, call

import pytest

from emailer.composer import build_approval_email
from emailer.approval_poller import ApprovalPollResult
from main import _check_and_process_approval, _publish_to_linkedin
from models.report import ApprovalStatus, DailyReport


_PREVIEW = (
    "🚨 Critical actively-exploited vulnerability threatens enterprise networks\n\n"
    "A critical authentication bypass in a widely-deployed enterprise platform "
    "is under active exploitation, with ransomware operators observed leveraging "
    "the flaw within hours of disclosure.\n\n"
    "Key developments — last 48 hours:\n\n"
    "• CVE-2026-9999 (CVSS 9.8) — authentication bypass in ExampleProduct, actively exploited\n"
    "• RansomGroup targeting healthcare and finance sectors\n\n"
    "Enterprise considerations:\n\n"
    "• Apply vendor patch immediately; no workaround available\n"
    "• Enable MFA on all administrative interfaces\n\n"
    "#CyberSecurity #ThreatIntelligence #VulnerabilityManagement"
)


def _make_report(**kwargs) -> DailyReport:
    defaults = dict(
        report_id="2026-06-17",
        window_start=datetime(2026, 6, 16),
        window_end=datetime(2026, 6, 17),
        executive_summary="Three critical CVEs under active exploitation.",
        detailed_summary="Detailed internal briefing text for executives.",
        linkedin_preview=_PREVIEW,
        gmail_thread_id="thread-abc",
        gmail_message_id="msg-abc",
    )
    defaults.update(kwargs)
    return DailyReport(**defaults)


# ── 1. Approval email contains LinkedIn Preview ───────────────────────────────

class TestEmailContainsLinkedInPreview:
    def test_plain_text_contains_linkedin_preview_section(self):
        report = _make_report()
        msg = build_approval_email(report)
        plain = msg.get_payload(0).get_payload(decode=True).decode("utf-8")

        assert "LINKEDIN PREVIEW" in plain

    def test_plain_text_contains_preview_content(self):
        report = _make_report()
        msg = build_approval_email(report)
        plain = msg.get_payload(0).get_payload(decode=True).decode("utf-8")

        assert "CVE-2026-9999" in plain
        assert "RansomGroup" in plain

    def test_plain_text_approval_instruction_references_preview(self):
        report = _make_report()
        msg = build_approval_email(report)
        plain = msg.get_payload(0).get_payload(decode=True).decode("utf-8")

        assert "LinkedIn Preview" in plain
        assert "Detailed Summary" not in plain.split("HOW TO RESPOND")[1]

    def test_html_contains_linkedin_preview_box(self):
        report = _make_report()
        msg = build_approval_email(report)
        html = msg.get_payload(1).get_payload(decode=True).decode("utf-8")

        assert "linkedin-box" in html
        assert "LinkedIn Preview" in html

    def test_html_contains_preview_content(self):
        report = _make_report()
        msg = build_approval_email(report)
        html = msg.get_payload(1).get_payload(decode=True).decode("utf-8")

        assert "CVE-2026-9999" in html

    def test_html_shows_warning_when_preview_missing(self):
        report = _make_report(linkedin_preview="")
        msg = build_approval_email(report)
        html = msg.get_payload(1).get_payload(decode=True).decode("utf-8")

        assert "linkedin-missing" in html
        assert "not available" in html

    def test_plain_shows_placeholder_when_preview_missing(self):
        report = _make_report(linkedin_preview="")
        msg = build_approval_email(report)
        plain = msg.get_payload(0).get_payload(decode=True).decode("utf-8")

        assert "not yet generated" in plain


# ── 2. APPROVE publishes linkedin_preview ────────────────────────────────────

class TestApprovePublishesLinkedInPreview:
    def _approved_result(self) -> ApprovalPollResult:
        return ApprovalPollResult(status="approved", approved_by="approver@example.com")

    def test_approved_sets_published_content_from_linkedin_preview(self):
        report = _make_report()

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.published_content == _PREVIEW

    def test_approved_does_not_use_detailed_summary(self):
        report = _make_report()

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.published_content != report.detailed_summary

    def test_approved_status_is_set(self):
        report = _make_report()

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.approval_status == ApprovalStatus.APPROVED


# ── 3. .txt attachment overrides linkedin_preview ────────────────────────────

class TestTxtAttachmentOverridesPreview:
    def test_edited_content_used_instead_of_linkedin_preview(self):
        edited = "This is my manually edited LinkedIn post."
        report = _make_report()
        edited_result = ApprovalPollResult(
            status="edited_approved",
            approved_by="approver@example.com",
            content=edited,
        )

        with patch("emailer.approval_poller.check_for_reply", return_value=edited_result), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.published_content == edited
        assert report.published_content != _PREVIEW

    def test_edited_approved_status_is_set(self):
        edited_result = ApprovalPollResult(
            status="edited_approved",
            approved_by="approver@example.com",
            content="Edited post.",
        )
        report = _make_report()

        with patch("emailer.approval_poller.check_for_reply", return_value=edited_result), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.approval_status == ApprovalStatus.EDITED_APPROVED


# ── 4. Empty linkedin_preview blocks publishing ───────────────────────────────

class TestEmptyLinkedInPreviewBlocksPublish:
    def _approved_result(self) -> ApprovalPollResult:
        return ApprovalPollResult(status="approved", approved_by="approver@example.com")

    def test_empty_preview_returns_without_publishing(self):
        report = _make_report(linkedin_preview="")

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report") as mock_save, \
             patch("main._publish_or_simulate") as mock_publish:
            _check_and_process_approval(report)

        mock_publish.assert_not_called()

    def test_whitespace_only_preview_returns_without_publishing(self):
        report = _make_report(linkedin_preview="   \n  ")

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate") as mock_publish:
            _check_and_process_approval(report)

        mock_publish.assert_not_called()

    def test_approval_status_not_changed_when_preview_empty(self):
        report = _make_report(linkedin_preview="")

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.approval_status == ApprovalStatus.PENDING


# ── 5. PLACEHOLDER in linkedin_preview blocks publishing ─────────────────────

class TestPlaceholderLinkedInPreviewBlocksPublish:
    def _approved_result(self) -> ApprovalPollResult:
        return ApprovalPollResult(status="approved", approved_by="approver@example.com")

    def test_placeholder_preview_returns_without_publishing(self):
        report = _make_report(linkedin_preview="PLACEHOLDER content here")

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate") as mock_publish:
            _check_and_process_approval(report)

        mock_publish.assert_not_called()

    def test_placeholder_mid_text_also_blocks(self):
        report = _make_report(
            linkedin_preview="Some real content\n[PLACEHOLDER for threat actor]\nMore content"
        )

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate") as mock_publish:
            _check_and_process_approval(report)

        mock_publish.assert_not_called()

    def test_approval_status_not_changed_when_placeholder_present(self):
        report = _make_report(linkedin_preview="PLACEHOLDER")

        with patch("emailer.approval_poller.check_for_reply", return_value=self._approved_result()), \
             patch("main.save_report"), \
             patch("main._publish_or_simulate"):
            _check_and_process_approval(report)

        assert report.approval_status == ApprovalStatus.PENDING

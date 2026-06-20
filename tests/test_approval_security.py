"""
Security tests for the approval workflow hardening:

1. _is_authorized_sender — exact email address matching (no substring tricks)
2. _extract_decision_from_body — strict first-line keyword parsing
3. Collect process lock — prevents duplicate concurrent runs
4. Attachment detection — .txt vs .rtf vs .txt.rtf; newest reply wins
"""
import base64
import logging
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ── 1. Sender authorization ───────────────────────────────────────────────────

class TestIsAuthorizedSender:
    """
    _is_authorized_sender must accept only the exact configured email address.
    Substring matches, lookalike domains, and display-name tricks must all fail.
    """

    def _check(self, from_header: str, recipient: str) -> bool:
        from emailer.approval_poller import _is_authorized_sender
        with patch("emailer.approval_poller.settings") as mock_settings:
            mock_settings.approval_email_recipient = recipient
            return _is_authorized_sender(from_header)

    def test_exact_authorized_email_passes(self):
        assert self._check("admin@company.com", "admin@company.com") is True

    def test_display_name_with_authorized_email_passes(self):
        assert self._check("Jane Doe <admin@company.com>", "admin@company.com") is True

    def test_different_email_fails(self):
        assert self._check("other@company.com", "admin@company.com") is False

    def test_lookalike_domain_fails(self):
        # admin@company.com.evil.io must NOT pass even though it contains "company.com"
        assert self._check("admin@company.com.evil.io", "admin@company.com") is False

    def test_email_containing_authorized_as_substring_fails(self):
        # not-admin@company.com contains "admin@company.com" as a substring
        assert self._check("not-admin@company.com", "admin@company.com") is False

    def test_empty_from_header_fails(self):
        assert self._check("", "admin@company.com") is False

    def test_case_insensitive_match_passes(self):
        assert self._check("Admin@Company.COM", "admin@company.com") is True


# ── 2. Approval body parsing ──────────────────────────────────────────────────

class TestDecisionParsing:
    """
    _extract_decision_from_body must return 'approve'/'reject' only when the
    first non-empty, non-quoted line is exactly a decision keyword.
    """

    def _decide(self, body: str) -> str | None:
        from emailer.approval_poller import _extract_decision_from_body
        return _extract_decision_from_body(body)

    # Positive cases
    def test_first_line_approve_passes(self):
        assert self._decide("APPROVE") == "approve"

    def test_first_line_approve_lowercase_passes(self):
        assert self._decide("approve") == "approve"

    def test_first_line_reject_passes(self):
        assert self._decide("REJECT") == "reject"

    def test_first_line_approve_with_trailing_body_passes(self):
        assert self._decide("APPROVE\n\nThanks for the briefing.") == "approve"

    def test_approve_after_blank_lines_passes(self):
        assert self._decide("\n\nAPPROVE\n") == "approve"

    # Negative cases — auto-reply and sentence traps
    def test_approve_in_sentence_does_not_approve(self):
        assert self._decide("your request has been approved for processing") is None

    def test_approve_later_in_body_does_not_approve(self):
        assert self._decide("Hello,\n\nPlease APPROVE this request.") is None

    def test_quoted_approve_in_original_email_does_not_approve(self):
        # Original message quoted below the reply — the quote contains APPROVE
        body = (
            "> Please reply APPROVE or REJECT\n"
            "\n"
            "Thanks for the note — I'll review later."
        )
        assert self._decide(body) is None

    def test_only_quoted_lines_returns_none(self):
        body = "> APPROVE\n> Thanks"
        assert self._decide(body) is None

    def test_empty_body_returns_none(self):
        assert self._decide("") is None

    def test_whitespace_only_body_returns_none(self):
        assert self._decide("   \n\n  ") is None

    def test_unrecognised_keyword_returns_none(self):
        assert self._decide("Sure, looks good!") is None


# ── 3. Collect process lock ───────────────────────────────────────────────────

class TestCollectLock:
    """
    _acquire_collect_lock must prevent two collect runs from overlapping.
    Stale lock files (PID no longer running) must be cleaned up automatically.
    """

    def test_first_acquire_writes_pid_and_returns_path(self, tmp_path):
        from main import _acquire_collect_lock, _release_collect_lock
        with patch("main.settings") as mock_settings, \
             patch("main.log_action"):
            mock_settings.data_dir = tmp_path
            lock_path = _acquire_collect_lock()
            try:
                assert lock_path is not None
                assert lock_path.exists()
                assert lock_path.read_text().strip() == str(os.getpid())
            finally:
                _release_collect_lock(lock_path)

    def test_active_lock_blocks_second_acquire(self, tmp_path):
        from main import _acquire_collect_lock, _release_collect_lock
        with patch("main.settings") as mock_settings, \
             patch("main.log_action"):
            mock_settings.data_dir = tmp_path
            lock1 = _acquire_collect_lock()
            try:
                # Second acquire while lock1 is held (same PID — os.kill(pid, 0) succeeds)
                lock2 = _acquire_collect_lock()
                assert lock2 is None, "second acquire should return None while lock is active"
            finally:
                _release_collect_lock(lock1)

    def test_stale_lock_is_cleaned_up_and_acquire_succeeds(self, tmp_path):
        from main import _acquire_collect_lock, _release_collect_lock
        # Write a lock file with a PID that definitely does not exist
        lock_path = tmp_path / ".collect.lock"
        lock_path.write_text("999999999")   # unrealistically large PID

        with patch("main.settings") as mock_settings, \
             patch("main.log_action"):
            mock_settings.data_dir = tmp_path
            acquired = _acquire_collect_lock()
            try:
                assert acquired is not None, "stale lock should be cleaned up and acquire should succeed"
                assert acquired.read_text().strip() == str(os.getpid())
            finally:
                _release_collect_lock(acquired)

    def test_release_removes_lock_file(self, tmp_path):
        from main import _acquire_collect_lock, _release_collect_lock
        with patch("main.settings") as mock_settings, \
             patch("main.log_action"):
            mock_settings.data_dir = tmp_path
            lock_path = _acquire_collect_lock()
            assert lock_path is not None
            _release_collect_lock(lock_path)
            assert not lock_path.exists()

    def test_release_on_none_is_safe(self):
        from main import _release_collect_lock
        _release_collect_lock(None)  # must not raise


# ── 4. Attachment detection ───────────────────────────────────────────────────

def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode()


def _svc_with_attachment(content: str) -> MagicMock:
    """Mock Gmail service that returns `content` for any attachment fetch."""
    svc = MagicMock()
    svc.users().messages().attachments().get().execute.return_value = {
        "data": _b64(content)
    }
    return svc


class TestAttachmentDetection:
    """
    _parse_message and check_for_reply must correctly handle:
    - .txt attachments (accepted — edited approval without APPROVE keyword)
    - .rtf / .txt.rtf attachments (ignored)
    - Invalid reply followed by a valid .txt reply in the same thread (newest wins)
    """

    APPROVER = "approver@example.com"

    def _msg(self, msg_id: str, payload: dict) -> dict:
        """Wrap a payload dict in a minimal Gmail message dict."""
        payload.setdefault("headers", [{"name": "From", "value": self.APPROVER}])
        return {"id": msg_id, "payload": payload}

    # ── 1. Valid .txt attachment alone approves without any keyword ───────────

    def test_txt_attachment_approves_without_keyword(self):
        from emailer.approval_poller import _parse_message
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {"mimeType": "text/plain", "filename": "", "body": {"data": _b64("No keyword.")}},
                {"mimeType": "text/plain", "filename": "edited_post.txt",
                 "body": {"attachmentId": "att-txt"}},
            ],
        }
        msg = self._msg("m1", payload)
        svc = _svc_with_attachment("My edited LinkedIn post.")
        result = _parse_message(svc, msg, self.APPROVER)
        assert result is not None
        assert result.status == "edited_approved"
        assert result.content == "My edited LinkedIn post."

    # ── 2. .rtf attachment is ignored — no approval ───────────────────────────

    def test_rtf_attachment_is_ignored(self):
        from emailer.approval_poller import _parse_message
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {"mimeType": "text/plain", "filename": "", "body": {"data": _b64("No keyword.")}},
                {"mimeType": "application/rtf", "filename": "post.rtf",
                 "body": {"attachmentId": "att-rtf"}},
            ],
        }
        msg = self._msg("m2", payload)
        result = _parse_message(MagicMock(), msg, self.APPROVER)
        assert result is None  # .rtf ignored, body has no keyword

    # ── 3. "post.txt.rtf" is NOT treated as a .txt attachment ─────────────────

    def test_txt_rtf_not_treated_as_txt(self):
        from emailer.approval_poller import _parse_message
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {"mimeType": "text/plain", "filename": "", "body": {"data": _b64("")}},
                {"mimeType": "application/rtf", "filename": "edited_post.txt.rtf",
                 "body": {"attachmentId": "att-bad"}},
            ],
        }
        msg = self._msg("m3", payload)
        result = _parse_message(MagicMock(), msg, self.APPROVER)
        assert result is None  # ends in .rtf, not .txt

    # ── 4. Invalid reply then valid .txt reply — newest (.txt) wins ───────────

    def test_rtf_reply_then_txt_reply_returns_edited_approved(self):
        from emailer.approval_poller import check_for_reply

        sent_msg = {
            "id": "sent-001",
            "payload": {
                "headers": [{"name": "From", "value": "system@example.com"}],
                "mimeType": "text/plain",
                "body": {"data": _b64("Please reply.")},
            },
        }
        rtf_reply = {
            "id": "reply-001",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [{"name": "From", "value": self.APPROVER}],
                "parts": [
                    {"mimeType": "text/plain", "filename": "", "body": {"data": _b64("")}},
                    {"mimeType": "application/rtf", "filename": "post.rtf",
                     "body": {"attachmentId": "att-rtf"}},
                ],
            },
        }
        txt_reply = {
            "id": "reply-002",
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [{"name": "From", "value": self.APPROVER}],
                "parts": [
                    {"mimeType": "text/plain", "filename": "", "body": {"data": _b64("")}},
                    {"mimeType": "text/plain", "filename": "edited_post.txt",
                     "body": {"attachmentId": "att-txt"}},
                ],
            },
        }

        svc = _svc_with_attachment("My final post.")
        svc.users().threads().get().execute.return_value = {
            "messages": [sent_msg, rtf_reply, txt_reply]
        }

        with patch("emailer.approval_poller.get_gmail_service", return_value=svc), \
             patch("emailer.approval_poller.settings") as mock_s:
            mock_s.approval_email_recipient = self.APPROVER
            result = check_for_reply("thread-xyz", "sent-001")

        assert result.status == "edited_approved"
        assert result.content == "My final post."

    # ── 5. Empty body with .txt attachment still approves ─────────────────────

    def test_empty_body_with_txt_attachment_approves(self):
        from emailer.approval_poller import _parse_message
        payload = {
            "mimeType": "multipart/mixed",
            "parts": [
                {"mimeType": "text/plain", "filename": "", "body": {"data": _b64("")}},
                {"mimeType": "text/plain", "filename": "post.txt",
                 "body": {"attachmentId": "att-txt"}},
            ],
        }
        msg = self._msg("m5", payload)
        svc = _svc_with_attachment("Post content from attachment.")
        result = _parse_message(svc, msg, self.APPROVER)
        assert result is not None
        assert result.status == "edited_approved"
        assert result.content == "Post content from attachment."

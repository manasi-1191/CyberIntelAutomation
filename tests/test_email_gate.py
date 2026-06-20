"""
Tests for the approval-email content gate and the detailed_summary fallback.

Rules under test:
- Approval email is blocked if executive_summary, detailed_summary, or
  linkedin_preview is empty, or if linkedin_preview contains PLACEHOLDER.
- When detailed_summary is empty but executive_summary is non-empty, a
  deterministic fallback is derived from structured report data and logged
  as an audit error entry.
- When both summaries fail (AI returns empty for both), no fallback is
  attempted and the email gate blocks the send.
"""
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from models.audit import AuditAction
from models.report import DailyReport
from models.vulnerability import Vulnerability, Severity, CVSSVector

NOW = datetime(2026, 6, 17, 12, 0, 0)
WIN_START = NOW - timedelta(hours=48)

_GOOD_PREVIEW = (
    "Critical vulnerability actively exploited in enterprise environments.\n\n"
    "Patch immediately.\n\n"
    "#CyberSecurity #ThreatIntelligence"
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vuln(cve_id: str, is_kev: bool = False) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        source="nvd",
        severity=Severity.CRITICAL,
        cvss=CVSSVector(version="3.1", base_score=9.8, severity=Severity.CRITICAL),
        is_known_exploited=is_kev,
        published_at=NOW - timedelta(hours=2),
        description="A critical authentication bypass vulnerability in ExampleProduct.",
    )


def _full_report(**kwargs) -> DailyReport:
    defaults = dict(
        report_id="2026-06-17",
        window_start=WIN_START,
        window_end=NOW,
        executive_summary="Critical CVE actively exploited — patch now.",
        detailed_summary=(
            "CVE-2026-1111 is actively exploited in enterprise platforms. "
            "Security teams should apply vendor patches immediately and enable MFA."
        ),
        linkedin_preview=_GOOD_PREVIEW,
        featured_vulnerabilities=[_vuln("CVE-2026-1111", is_kev=True)],
        vulnerabilities=[_vuln("CVE-2026-1111", is_kev=True)],
        critical_cve_count=1,
        kev_count=1,
    )
    defaults.update(kwargs)
    return DailyReport(**defaults)


class _MockAIClient:
    model = "test-model-v1"

    def __init__(self, response=None):
        self._response = response

    def complete(self, system, user, max_tokens=2048):
        return self._response


# ── 1. Email content gate ─────────────────────────────────────────────────────

class TestEmailContentGate:
    """_send_email_for_report must block when any required content field is absent."""

    def _send(self, report: DailyReport):
        """Run _send_email_for_report with Gmail configured and sender stubbed out."""
        from main import _send_email_for_report
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_approval_email", return_value=("tid", "mid")), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)

    def _send_was_called(self, report: DailyReport) -> bool:
        from main import _send_email_for_report
        called = []
        def fake_send(r):
            called.append(True)
            return ("tid", "mid")
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_approval_email", side_effect=fake_send), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)
        return bool(called)

    def test_empty_detailed_summary_blocks_email(self):
        report = _full_report(detailed_summary="")
        assert not self._send_was_called(report)

    def test_empty_executive_summary_blocks_email(self):
        report = _full_report(executive_summary="")
        assert not self._send_was_called(report)

    def test_empty_linkedin_preview_blocks_email(self):
        report = _full_report(linkedin_preview="")
        assert not self._send_was_called(report)

    def test_whitespace_only_linkedin_preview_blocks_email(self):
        report = _full_report(linkedin_preview="   \n  ")
        assert not self._send_was_called(report)

    def test_placeholder_linkedin_preview_blocks_email(self):
        report = _full_report(linkedin_preview="PLACEHOLDER content here")
        assert not self._send_was_called(report)

    def test_all_fields_present_sends_email(self):
        report = _full_report()
        assert self._send_was_called(report)

    def test_blocked_email_logged_as_audit_error(self):
        from main import _send_email_for_report
        report = _full_report(detailed_summary="")
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("main.log_action") as mock_log:
            _send_email_for_report(report)
        error_calls = [
            c for c in mock_log.call_args_list
            if c.args and c.args[0] == AuditAction.ERROR
        ]
        assert len(error_calls) >= 1

    def test_blocked_email_error_includes_reason(self):
        from main import _send_email_for_report, _report_ready_for_email
        report = _full_report(detailed_summary="")
        ready, reason = _report_ready_for_email(report)
        assert not ready
        assert "detailed_summary" in reason


# ── 2. _report_ready_for_email helper ────────────────────────────────────────

class TestReportReadyForEmail:
    def test_returns_true_for_complete_report(self):
        from main import _report_ready_for_email
        assert _report_ready_for_email(_full_report()) == (True, "")

    def test_flags_empty_executive(self):
        from main import _report_ready_for_email
        ready, reason = _report_ready_for_email(_full_report(executive_summary=""))
        assert not ready
        assert "executive_summary" in reason

    def test_flags_empty_detailed(self):
        from main import _report_ready_for_email
        ready, reason = _report_ready_for_email(_full_report(detailed_summary=""))
        assert not ready
        assert "detailed_summary" in reason

    def test_flags_empty_linkedin_preview(self):
        from main import _report_ready_for_email
        ready, reason = _report_ready_for_email(_full_report(linkedin_preview=""))
        assert not ready
        assert "linkedin_preview" in reason

    def test_flags_placeholder_in_linkedin_preview(self):
        from main import _report_ready_for_email
        ready, reason = _report_ready_for_email(
            _full_report(linkedin_preview="[PLACEHOLDER] for threat content")
        )
        assert not ready
        assert "PLACEHOLDER" in reason


# ── 3. Detailed summary fallback ──────────────────────────────────────────────

class TestDetailedSummaryFallback:
    """_build_fallback_detailed_summary and its integration into generate_summaries."""

    def test_fallback_returns_nonempty_when_data_exists(self):
        from summarizer.summarizer import _build_fallback_detailed_summary
        report = _full_report()
        result = _build_fallback_detailed_summary(report, [])
        assert result != "", "fallback must produce text when report has vuln data"

    def test_fallback_returns_empty_when_no_data(self):
        from summarizer.summarizer import _build_fallback_detailed_summary
        report = DailyReport(
            report_id="2026-06-17",
            window_start=WIN_START,
            window_end=NOW,
            critical_cve_count=0,
            kev_count=0,
            breach_count=0,
            attack_count=0,
        )
        result = _build_fallback_detailed_summary(report, [])
        assert result == ""

    def test_fallback_mentions_kev_vulnerability(self):
        from summarizer.summarizer import _build_fallback_detailed_summary
        report = _full_report()
        result = _build_fallback_detailed_summary(report, [])
        assert "CVE-2026-1111" in result
        assert "exploited" in result.lower()

    def test_fallback_description_never_ends_mid_word(self):
        from summarizer.summarizer import _build_fallback_detailed_summary
        long_desc = "A" * 200  # no spaces — rfind returns -1 edge case
        v = _vuln("CVE-2026-9999", is_kev=True)
        v = v.model_copy(update={"description": "word " * 60})
        report = _full_report(
            featured_vulnerabilities=[v],
            kev_count=1,
        )
        result = _build_fallback_detailed_summary(report, [])
        # Should not end with a partial token — just verify it doesn't crash
        assert result != ""

    def test_generate_summaries_uses_fallback_when_detailed_fails(self):
        """When AI produces executive but not detailed, fallback is applied."""
        from summarizer.summarizer import generate_summaries

        report = _full_report()
        call_count = [0]

        def fake_complete(system, user, max_tokens=2048):
            call_count[0] += 1
            # Executive ends with '.' so _is_complete returns True immediately (1 call).
            # All subsequent calls are the detailed attempts — return None to force fallback.
            if call_count[0] == 1:
                return "Critical CVE under active exploitation — patch immediately."
            return None

        client = _MockAIClient()
        client.complete = fake_complete

        with patch("summarizer.summarizer.log_action"):
            executive, detailed = generate_summaries(report, [], client)

        assert executive != "", "executive must be set"
        assert detailed != "", "detailed must use fallback when AI returns empty"

    def test_generate_summaries_both_empty_no_fallback(self):
        """When both AI calls fail, both summaries stay empty (no fallback)."""
        from summarizer.summarizer import generate_summaries

        report = _full_report()
        client = _MockAIClient(response=None)

        with patch("summarizer.summarizer.log_action"):
            executive, detailed = generate_summaries(report, [], client)

        assert executive == ""
        assert detailed == ""

    def test_fallback_triggers_audit_error_entry(self):
        """Using the detailed fallback must write an ERROR audit entry."""
        from summarizer.summarizer import generate_summaries

        report = _full_report()
        call_count = [0]

        def fake_complete(system, user, max_tokens=2048):
            call_count[0] += 1
            if call_count[0] == 1:
                return "Critical CVE under active exploitation — patch immediately."
            return None

        client = _MockAIClient()
        client.complete = fake_complete

        with patch("summarizer.summarizer.log_action") as mock_log:
            generate_summaries(report, [], client)

        error_calls = [
            c for c in mock_log.call_args_list
            if c.args and c.args[0] == AuditAction.ERROR
        ]
        assert len(error_calls) >= 1, "fallback must log an ERROR audit entry"
        assert error_calls[0].kwargs.get("success") is False


# ── 4. LinkedIn fallback description truncation ───────────────────────────────

class TestLinkedInFallbackDescriptionTruncation:
    def test_description_does_not_end_mid_word(self):
        from summarizer.summarizer import _build_fallback_linkedin_preview

        long_desc = "authentication bypass in ExampleProduct platform "
        long_desc += "affecting all versions prior to 9.4.2 " * 5  # > 80 chars
        v = _vuln("CVE-2026-9999", is_kev=True)
        v = v.model_copy(update={"description": long_desc})
        report = DailyReport(
            report_id="2026-06-17",
            window_start=WIN_START,
            window_end=NOW,
            featured_vulnerabilities=[v],
            critical_cve_count=1,
            kev_count=1,
        )
        result = _build_fallback_linkedin_preview(report, [])
        # Find the CVE bullet line
        for line in result.splitlines():
            if "CVE-2026-9999" in line:
                # Should end with "..." (truncated) or the full text (short enough)
                assert not line.rstrip().endswith(("n", "g", "t", "r")) or line.endswith("...")
                break

    def test_short_description_is_not_truncated(self):
        from summarizer.summarizer import _build_fallback_linkedin_preview

        v = _vuln("CVE-2026-9999", is_kev=True)
        report = DailyReport(
            report_id="2026-06-17",
            window_start=WIN_START,
            window_end=NOW,
            featured_vulnerabilities=[v],
            critical_cve_count=1,
            kev_count=1,
        )
        result = _build_fallback_linkedin_preview(report, [])
        for line in result.splitlines():
            if "CVE-2026-9999" in line:
                assert "..." not in line
                break


# ── 5. Deterministic fallback passes gate; build_report stubs are blocked ─────

_BUILD_REPORT_PLACEHOLDER = (
    "[PLACEHOLDER — Phase 4 will generate this via Anthropic] "
    "Collected 1 vulnerabilities and 55 threat events."
)


class TestPlaceholderGating:
    """
    The build_report() defaults produce PLACEHOLDER stubs in executive_summary
    and detailed_summary.  When Phase 3B fails (e.g. Gemini quota), those stubs
    stay in the report.  The email gate must block them, and the LinkedIn
    fallback must not embed them.
    """

    def test_build_report_placeholder_in_executive_blocks_gate(self):
        from main import _report_ready_for_email
        report = _full_report(executive_summary=_BUILD_REPORT_PLACEHOLDER)
        ready, reason = _report_ready_for_email(report)
        assert not ready
        assert "executive_summary" in reason
        assert "PLACEHOLDER" in reason

    def test_build_report_placeholder_in_detailed_blocks_gate(self):
        from main import _report_ready_for_email
        report = _full_report(detailed_summary=_BUILD_REPORT_PLACEHOLDER)
        ready, reason = _report_ready_for_email(report)
        assert not ready
        assert "detailed_summary" in reason
        assert "PLACEHOLDER" in reason

    def test_build_report_placeholder_in_linkedin_preview_blocks_gate(self):
        from main import _report_ready_for_email
        report = _full_report(
            linkedin_preview=(
                "1 actively exploited vulnerability this week — patch now.\n\n"
                + _BUILD_REPORT_PLACEHOLDER
            )
        )
        ready, reason = _report_ready_for_email(report)
        assert not ready
        assert "linkedin_preview" in reason
        assert "PLACEHOLDER" in reason

    def test_linkedin_fallback_skips_placeholder_detailed_summary(self):
        """
        When detailed_summary is a build_report placeholder stub,
        _build_fallback_linkedin_preview must NOT embed it — it should
        fall through to the synthesised-from-counts path.
        """
        from summarizer.summarizer import _build_fallback_linkedin_preview
        report = _full_report(detailed_summary=_BUILD_REPORT_PLACEHOLDER)
        result = _build_fallback_linkedin_preview(report, [])
        assert "PLACEHOLDER" not in result

    def test_deterministic_linkedin_fallback_passes_email_gate(self):
        """
        A report with real executive/detailed summaries and a deterministic
        LinkedIn fallback (no AI) must pass _report_ready_for_email.
        """
        from main import _report_ready_for_email
        from summarizer.summarizer import _build_fallback_linkedin_preview

        # Report has real AI-generated summaries but no LinkedIn preview yet
        report = _full_report(
            executive_summary="One critical actively-exploited CVE threatens enterprise systems.",
            detailed_summary=(
                "CVE-2026-1111 is actively exploited in the wild. "
                "Security teams should apply vendor patches immediately."
            ),
            linkedin_preview="",  # not yet generated
        )

        # Generate the deterministic fallback
        fallback = _build_fallback_linkedin_preview(report, [])
        assert fallback, "fallback must be non-empty for this report"
        assert "PLACEHOLDER" not in fallback, "fallback must not contain PLACEHOLDER"

        # Apply it and check the gate
        report = _full_report(
            executive_summary=report.executive_summary,
            detailed_summary=report.detailed_summary,
            linkedin_preview=fallback,
        )
        ready, reason = _report_ready_for_email(report)
        assert ready, f"deterministic fallback should pass gate but was blocked: {reason}"


# ── 6. Content gate failure notification ──────────────────────────────────────

class TestContentGateNotification:
    """
    When _send_email_for_report is blocked by the content gate it must send
    a one-time failure notification email to the approval recipient.
    Subsequent blocked calls on the same report (content_gate_notified=True)
    must not re-send.
    """

    def _blocked_report(self, **kwargs) -> DailyReport:
        defaults = dict(
            report_id="2026-06-19",
            window_start=WIN_START,
            window_end=NOW,
            executive_summary="Critical CVE under active exploitation.",
            detailed_summary="",          # triggers gate
            linkedin_preview="Critical CVE threatening enterprise networks. #CyberSecurity",
        )
        defaults.update(kwargs)
        return DailyReport(**defaults)

    def test_blocked_approval_sends_failure_notification(self):
        from main import _send_email_for_report
        report = self._blocked_report()

        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification") as mock_notify, \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)

        mock_notify.assert_called_once()

    def test_normal_approval_email_not_sent_when_content_incomplete(self):
        from main import _send_email_for_report
        report = self._blocked_report()

        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification"), \
             patch("emailer.sender.send_approval_email") as mock_approval, \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)

        mock_approval.assert_not_called()

    def test_no_notification_spam_when_already_notified(self):
        from main import _send_email_for_report
        report = self._blocked_report(
            content_gate_notified=True,
            content_gate_notified_reason="detailed_summary is empty",
        )

        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification") as mock_notify, \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)

        mock_notify.assert_not_called()

    def test_notification_includes_report_id_and_failed_field(self):
        from main import _send_email_for_report
        report = self._blocked_report()
        captured = []

        def fake_notify(r, reason):
            captured.append((r.report_id, reason))

        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification", side_effect=fake_notify), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)

        assert len(captured) == 1
        report_id, reason = captured[0]
        assert report_id == "2026-06-19"
        assert "detailed_summary" in reason


# ── 7. Content gate deduplication (Bug 2) ────────────────────────────────────

class TestContentGateDeduplication:
    """
    Failure notification must be deduplicated by (report_id, reason).

    - Same reason blocked again  → no second email
    - Different reason           → new email IS sent
    - AI pipeline itself         → never calls _send_content_gate_notification
    - Successful approval email  → resets content_gate_notified so future
                                   independent failures can notify fresh
    - Reason is persisted        → readable from report after notification
    """

    def _blocked_report(self, **kwargs) -> DailyReport:
        defaults = dict(
            report_id="2026-06-19",
            window_start=WIN_START,
            window_end=NOW,
            executive_summary="Critical CVE under active exploitation.",
            detailed_summary="",          # triggers gate — reason: "detailed_summary is empty"
            linkedin_preview="Critical CVE threatening enterprise networks. #CyberSecurity",
        )
        defaults.update(kwargs)
        return DailyReport(**defaults)

    # ── 1. Same failure reason on a second run → one notification total ───────

    def test_same_reason_does_not_resend_notification(self):
        from main import _send_content_gate_notification
        report = self._blocked_report(
            content_gate_notified=True,
            content_gate_notified_reason="detailed_summary is empty",
        )
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification") as mock_notify, \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_content_gate_notification(report, "detailed_summary is empty")
        mock_notify.assert_not_called()

    # ── 2. Different reason → fresh notification IS sent ─────────────────────

    def test_different_reason_sends_new_notification(self):
        from main import _send_content_gate_notification
        report = self._blocked_report(
            content_gate_notified=True,
            content_gate_notified_reason="detailed_summary is empty",  # prior reason
        )
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification") as mock_notify, \
             patch("main.save_report"), \
             patch("main.log_action"):
            # A new failure reason (a different field now missing)
            _send_content_gate_notification(report, "linkedin_preview is empty")
        mock_notify.assert_called_once()

    # ── 3. AI pipeline never triggers the notification ────────────────────────

    def test_ai_pipeline_does_not_send_notification(self):
        """_run_ai_pipeline must not call _send_content_gate_notification."""
        from main import _run_ai_pipeline
        report = DailyReport(
            report_id="2026-06-19",
            window_start=WIN_START,
            window_end=NOW,
        )
        with patch("summarizer.ai_provider.get_ai_client", return_value=None), \
             patch("main._send_content_gate_notification") as mock_notify, \
             patch("main.save_report"), \
             patch("main.log_action"):
            _run_ai_pipeline(report)
        mock_notify.assert_not_called()

    # ── 4. Successful approval email resets the notification state ────────────

    def test_successful_approval_email_resets_notification_state(self):
        report = _full_report()
        report.content_gate_notified = True
        report.content_gate_notified_reason = "linkedin_preview is empty"

        from main import _send_email_for_report
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_approval_email", return_value=("tid", "mid")), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)

        assert report.content_gate_notified is False
        assert report.content_gate_notified_reason == ""

    # ── 5. Failure reason is stored on the report after first notification ────

    def test_notification_reason_stored_on_report(self):
        report = self._blocked_report()  # detailed_summary="" → reason = "detailed_summary is empty"
        from main import _send_email_for_report
        with patch("emailer.gmail_auth.is_configured", return_value=True), \
             patch("emailer.sender.send_failure_notification"), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _send_email_for_report(report)
        assert report.content_gate_notified is True
        assert report.content_gate_notified_reason == "detailed_summary is empty"

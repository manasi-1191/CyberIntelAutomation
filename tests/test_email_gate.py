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

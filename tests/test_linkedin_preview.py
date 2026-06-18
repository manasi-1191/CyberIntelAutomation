"""
Tests for the four linkedin_preview fixes:
  1. _is_complete treats hashtag-ending posts as complete.
  2. Empty AI result triggers a deterministic fallback (not empty string).
  3. Existing valid linkedin_preview is not overwritten by empty generation.
  4. AI failure is reflected in the audit log.
"""
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from models.audit import AuditAction
from models.report import DailyReport
from models.vulnerability import Vulnerability, Severity, CVSSVector

NOW = datetime(2026, 6, 17, 12, 0, 0)
WIN_START = NOW - timedelta(hours=48)


# ── Helpers ───────────────────────────────────────────────────────────────────

class _MockClient:
    model = "test-model-v1"

    def __init__(self, response=None):
        self._response = response

    def complete(self, system, user, max_tokens=2048):
        return self._response


def _vuln(cve_id: str, is_kev: bool = False) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        source="nvd",
        severity=Severity.CRITICAL,
        cvss=CVSSVector(version="3.1", base_score=9.8, severity=Severity.CRITICAL),
        is_known_exploited=is_kev,
        published_at=NOW - timedelta(hours=2),
    )


def _report(**kwargs) -> DailyReport:
    defaults = dict(
        report_id="2026-06-17",
        window_start=WIN_START,
        window_end=NOW,
        vulnerabilities=[_vuln("CVE-2026-1111", is_kev=True)],
        featured_vulnerabilities=[_vuln("CVE-2026-1111", is_kev=True)],
        critical_cve_count=1,
        kev_count=1,
        breach_count=0,
        attack_count=0,
    )
    defaults.update(kwargs)
    return DailyReport(**defaults)


# ── Fix 1: _is_complete treats hashtag-ending posts as complete ───────────────

class TestIsCompleteHashtags:
    def test_post_ending_in_hashtag_line_is_complete(self):
        from summarizer.summarizer import _is_complete
        post = (
            "A critical vulnerability in enterprise systems requires immediate patching.\n\n"
            "#CyberSecurity #ThreatIntelligence #InfoSec"
        )
        assert _is_complete(post) is True

    def test_post_ending_in_multiple_hashtag_lines_is_complete(self):
        from summarizer.summarizer import _is_complete
        post = (
            "Keep systems patched and monitor for indicators of compromise.\n"
            "#CyberSecurity\n"
            "#ThreatIntelligence\n"
            "#InfoSec"
        )
        assert _is_complete(post) is True

    def test_post_with_no_sentence_end_before_hashtags_is_incomplete(self):
        from summarizer.summarizer import _is_complete
        # Body has no sentence terminator — hashtag stripping must not rescue it
        post = (
            "Critical vulnerability in enterprise systems with ongoing\n\n"
            "#CyberSecurity #ThreatIntelligence"
        )
        assert _is_complete(post) is False

    def test_plain_sentence_still_complete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Patch this system immediately.") is True

    def test_empty_string_still_incomplete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("") is False

    def test_hashtag_only_text_with_no_body_is_incomplete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("#CyberSecurity #InfoSec") is False


# ── Fix 2: Empty AI result triggers deterministic fallback ────────────────────

class TestFallbackLinkedInPreview:
    def test_empty_ai_returns_non_empty_fallback(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report()
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action"):
            result = generate_linkedin_preview(report, [], client)

        assert result != "", "fallback must produce non-empty preview when AI fails"

    def test_fallback_contains_hashtags(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report()
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action"):
            result = generate_linkedin_preview(report, [], client)

        assert "#" in result

    def test_fallback_contains_kev_info_when_kev_exists(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report(kev_count=2)
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action"):
            result = generate_linkedin_preview(report, [], client)

        assert "exploited" in result.lower() or "kev" in result.lower() or "2" in result

    def test_empty_ai_and_empty_report_returns_empty_string(self):
        """When AI fails and report has no data, fallback returns '' rather than nonsense."""
        from summarizer.summarizer import generate_linkedin_preview
        report = DailyReport(
            report_id="2026-06-17",
            window_start=WIN_START,
            window_end=NOW,
            critical_cve_count=0,
            kev_count=0,
            breach_count=0,
            attack_count=0,
        )
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action"):
            result = generate_linkedin_preview(report, [], client)

        assert result == "", "no data → fallback must return empty string"

    def test_fallback_is_complete_sentence(self):
        from summarizer.summarizer import generate_linkedin_preview, _is_complete
        report = _report()
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action"):
            result = generate_linkedin_preview(report, [], client)

        assert _is_complete(result), "fallback preview must satisfy _is_complete"


# ── Fix 3: Existing valid linkedin_preview is not overwritten ─────────────────

class TestPreserveExistingLinkedInPreview:
    def _run_phase3c_with_empty_ai(self, report: DailyReport) -> None:
        """
        Exercise _run_ai_pipeline with generate_linkedin_preview mocked to return "".
        All other AI calls are also mocked so this is unit-level.
        """
        from main import _run_ai_pipeline

        mock_client = MagicMock()
        mock_client.model = "test-model"

        with patch("summarizer.ai_provider.get_ai_client", return_value=mock_client), \
             patch("summarizer.extractor.extract_threat_events", return_value=[]), \
             patch("summarizer.summarizer.generate_summaries", return_value=("exec", "detail")), \
             patch("summarizer.summarizer.generate_linkedin_preview", return_value=""), \
             patch("storage.local_store.save_extracted_events", return_value=Path("/tmp/x")), \
             patch("storage.local_store.save_summaries_text", return_value=Path("/tmp/y")), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _run_ai_pipeline(report)

    def test_prior_preview_kept_when_ai_returns_empty(self):
        prior = "Valid existing LinkedIn preview — keep this."
        report = _report(linkedin_preview=prior)

        self._run_phase3c_with_empty_ai(report)

        assert report.linkedin_preview == prior

    def test_empty_preview_stays_empty_when_ai_fails_and_no_prior(self):
        report = _report(linkedin_preview="")

        with patch("main.log_action"):
            self._run_phase3c_with_empty_ai(report)

        assert report.linkedin_preview == ""

    def test_fresh_ai_result_overwrites_prior_preview(self):
        """When AI succeeds, its result replaces the carried-forward preview."""
        from main import _run_ai_pipeline

        prior = "Old preview from last run."
        new_preview = "Fresh AI-generated LinkedIn post ending here."
        report = _report(linkedin_preview=prior)

        mock_client = MagicMock()
        mock_client.model = "test-model"

        with patch("summarizer.ai_provider.get_ai_client", return_value=mock_client), \
             patch("summarizer.extractor.extract_threat_events", return_value=[]), \
             patch("summarizer.summarizer.generate_summaries", return_value=("exec", "detail")), \
             patch("summarizer.summarizer.generate_linkedin_preview", return_value=new_preview), \
             patch("storage.local_store.save_extracted_events", return_value=Path("/tmp/x")), \
             patch("storage.local_store.save_summaries_text", return_value=Path("/tmp/y")), \
             patch("main.save_report"), \
             patch("main.log_action"):
            _run_ai_pipeline(report)

        assert report.linkedin_preview == new_preview


# ── Fix 4: AI failure is reflected in the audit log ──────────────────────────

class TestAuditLogOnFailure:
    def test_ai_failure_calls_log_action_with_error(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report()
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action") as mock_log:
            generate_linkedin_preview(report, [], client)

        error_calls = [
            c for c in mock_log.call_args_list
            if c.args and c.args[0] == AuditAction.ERROR
        ]
        assert len(error_calls) >= 1, "AI failure must produce at least one ERROR audit entry"

    def test_audit_entry_is_not_success(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report()
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action") as mock_log:
            generate_linkedin_preview(report, [], client)

        error_call = next(
            (c for c in mock_log.call_args_list if c.args and c.args[0] == AuditAction.ERROR),
            None,
        )
        assert error_call is not None
        assert error_call.kwargs.get("success") is False

    def test_audit_entry_includes_report_id(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report()
        client = _MockClient(response=None)

        with patch("summarizer.summarizer.log_action") as mock_log:
            generate_linkedin_preview(report, [], client)

        error_call = next(
            (c for c in mock_log.call_args_list if c.args and c.args[0] == AuditAction.ERROR),
            None,
        )
        assert error_call is not None
        assert error_call.kwargs.get("report_id") == report.report_id

    def test_successful_ai_result_does_not_log_error(self):
        from summarizer.summarizer import generate_linkedin_preview
        report = _report()
        good_response = "Enterprise systems face an actively exploited vulnerability requiring immediate action.\n\n#CyberSecurity #ThreatIntelligence"
        client = _MockClient(response=good_response)

        with patch("summarizer.summarizer.log_action") as mock_log:
            result = generate_linkedin_preview(report, [], client)

        assert result != ""
        error_calls = [
            c for c in mock_log.call_args_list
            if c.args and c.args[0] == AuditAction.ERROR
        ]
        assert len(error_calls) == 0, "no ERROR audit entry on successful AI generation"

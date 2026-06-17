"""
Tests for Phase 3 AI extraction and summarization.
All AI provider calls are mocked — no network, no API keys required.
"""
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

from models.vulnerability import Vulnerability, Severity, CVSSVector
from models.threat import ThreatEvent
from models.extracted_event import ExtractedThreatEvent
from models.report import DailyReport
from summarizer.extractor import (
    extract_threat_events, _parse_json, _str, _clamp, _strlist,
)
from summarizer.summarizer import generate_summaries
from summarizer.prompt_builder import (
    build_extraction_prompt,
    build_executive_summary_prompt,
    build_detailed_summary_prompt,
)

NOW = datetime(2026, 6, 17, 12, 0, 0)
WIN_START = NOW - timedelta(hours=48)


# ── Helpers ───────────────────────────────────────────────────────────────────

class _MockClient:
    """Minimal stand-in for an AI client."""
    model = "test-model-v1"

    def __init__(self, response: str | None = ""):
        self._response = response

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> str | None:
        return self._response


def _event(n: int, title: str = "", description: str = "") -> ThreatEvent:
    return ThreatEvent(
        event_id=f"evt-{n:04d}",
        source="thehackernews",
        source_url=f"https://example.com/story-{n}",
        title=title or f"Threat event {n}",
        description=description or f"Description for event {n}",
        published_at=NOW - timedelta(hours=1),
    )


def _vuln(cve_id: str, is_kev: bool = False) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        source="nvd",
        severity=Severity.CRITICAL,
        cvss=CVSSVector(version="3.1", base_score=9.8, severity=Severity.CRITICAL),
        is_known_exploited=is_kev,
        published_at=NOW - timedelta(hours=2),
    )


def _report(vulns=None, events=None) -> DailyReport:
    v = vulns or [_vuln("CVE-2026-1111", is_kev=True)]
    e = events or [_event(1), _event(2)]
    return DailyReport(
        report_id="2026-06-17",
        window_start=WIN_START,
        window_end=NOW,
        vulnerabilities=v,
        threat_events=e,
        critical_cve_count=len(v),
        kev_count=sum(1 for x in v if x.is_known_exploited),
        featured_vulnerabilities=v,
    )


def _extraction_json(events: list[ThreatEvent]) -> str:
    return json.dumps([
        {
            "event_id": e.event_id,
            "threat_actor": "APT29",
            "motivation": "espionage",
            "attack_type": "phishing",
            "affected_sector": "government",
            "affected_organizations": ["Ministry of Defence"],
            "impact": "Email credentials compromised for 200 accounts.",
            "enterprise_mitigations": ["Enable MFA", "Block legacy auth protocols"],
            "confidence_score": 0.85,
        }
        for e in events
    ])


# ── Provider factory ──────────────────────────────────────────────────────────

class TestAiProvider:
    def test_returns_none_when_provider_is_none(self):
        with patch("config.settings.settings") as mock_settings:
            mock_settings.ai_provider = "none"
            from summarizer.ai_provider import get_ai_client
            assert get_ai_client() is None

    def test_returns_none_when_xai_key_missing(self):
        with patch("config.settings.settings") as mock_settings:
            mock_settings.ai_provider = "xai"
            mock_settings.xai_api_key = ""
            from summarizer.ai_provider import get_ai_client
            assert get_ai_client() is None

    def test_returns_none_when_anthropic_key_missing(self):
        with patch("config.settings.settings") as mock_settings:
            mock_settings.ai_provider = "anthropic"
            mock_settings.anthropic_api_key = ""
            from summarizer.ai_provider import get_ai_client
            assert get_ai_client() is None

    def test_returns_none_when_gemini_key_missing(self):
        with patch("config.settings.settings") as mock_settings:
            mock_settings.ai_provider = "gemini"
            mock_settings.gemini_api_key = ""
            from summarizer.ai_provider import get_ai_client
            assert get_ai_client() is None

    def test_returns_none_for_unknown_provider(self):
        with patch("config.settings.settings") as mock_settings:
            mock_settings.ai_provider = "openai"
            from summarizer.ai_provider import get_ai_client
            assert get_ai_client() is None

    def test_gemini_client_uses_default_model(self):
        """_GeminiClient defaults to gemini-2.5-flash when AI_MODEL is unset."""
        import sys
        import types

        # Minimal stub so the ImportError check in __init__ passes
        mock_genai = types.ModuleType("google.generativeai")
        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="")
            assert client.model == "gemini-2.5-flash"

    def test_gemini_client_respects_model_override(self):
        """AI_MODEL override is passed through to _GeminiClient."""
        import sys
        import types

        mock_genai = types.ModuleType("google.generativeai")
        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.0-flash")
            assert client.model == "gemini-2.0-flash"

    def test_gemini_complete_returns_text(self):
        """_GeminiClient.complete() returns response.text from the Gemini SDK."""
        import sys
        import types
        from unittest.mock import MagicMock

        # Build a mock response with a .text attribute
        mock_response = MagicMock()
        mock_response.text = "Gemini summary output."

        mock_model_instance = MagicMock()
        mock_model_instance.generate_content.return_value = mock_response

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model_instance

        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.5-flash")
            result = client.complete(system="You are an analyst.", user="Summarise threats.")

        assert result == "Gemini summary output."
        mock_genai.configure.assert_called_once_with(api_key="test-key")
        mock_genai.GenerativeModel.assert_called_once_with(
            model_name="gemini-2.5-flash",
            system_instruction="You are an analyst.",
        )

    def test_gemini_complete_returns_none_on_api_error(self):
        """_GeminiClient.complete() returns None when the Gemini API raises."""
        import sys
        import types
        from unittest.mock import MagicMock

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.side_effect = Exception("quota exceeded")

        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.5-flash")
            result = client.complete(system="sys", user="user")

        assert result is None

    def test_gemini_complete_scales_max_tokens(self):
        """_GeminiClient passes scaled max_output_tokens to absorb thinking overhead."""
        import sys
        import types
        from unittest.mock import MagicMock

        captured_configs = []

        mock_response = MagicMock()
        mock_response.text = "Complete summary sentence."

        mock_model = MagicMock()
        def capture_generate(user, generation_config=None):
            captured_configs.append(generation_config)
            return mock_response
        mock_model.generate_content.side_effect = capture_generate

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model

        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.5-flash")
            client.complete(system="sys", user="user", max_tokens=150)

        assert len(captured_configs) >= 1
        cfg = captured_configs[0]
        # Either a dict or a GenerationConfig object — both must have scaled tokens
        if isinstance(cfg, dict):
            assert cfg["max_output_tokens"] >= 900  # 150 * 6
        else:
            assert cfg.max_output_tokens >= 900

    def test_gemini_complete_falls_back_when_thinking_config_raises(self):
        """Falls back to standard GenerationConfig when thinking_config is unsupported."""
        import sys
        import types
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.text = "Fallback response completed."

        mock_model = MagicMock()
        mock_model.generate_content.side_effect = [
            Exception("Unknown field thinking_config"),
            mock_response,
        ]

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model
        mock_genai.types.GenerationConfig.return_value = MagicMock()

        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.5-flash")
            result = client.complete(system="sys", user="user")

        assert result == "Fallback response completed."
        assert mock_model.generate_content.call_count == 2

    def test_gemini_complete_returns_none_when_response_text_raises(self):
        """response.text raising ValueError (safety block) returns None gracefully."""
        import sys
        import types
        from unittest.mock import MagicMock, PropertyMock

        mock_response = MagicMock()
        type(mock_response).text = PropertyMock(side_effect=ValueError("blocked by safety"))

        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model

        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.5-flash")
            result = client.complete(system="sys", user="user")

        assert result is None

    def test_gemini_complete_returns_none_when_response_text_is_none(self):
        """None response.text (stopped early / MAX_TOKENS) returns None gracefully."""
        import sys
        import types
        from unittest.mock import MagicMock

        mock_response = MagicMock()
        mock_response.text = None

        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        mock_genai = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model

        mock_google = types.ModuleType("google")
        mock_google.generativeai = mock_genai

        with patch.dict(sys.modules, {"google": mock_google, "google.generativeai": mock_genai}):
            from summarizer.ai_provider import _GeminiClient
            client = _GeminiClient(api_key="test-key", model="gemini-2.5-flash")
            result = client.complete(system="sys", user="user")

        assert result is None


# ── Extractor ─────────────────────────────────────────────────────────────────

class TestExtractor:
    def test_returns_empty_when_client_is_none(self):
        events = [_event(1), _event(2)]
        result = extract_threat_events(events, client=None)
        assert result == []

    def test_returns_empty_when_no_events(self):
        client = _MockClient(response="[]")
        result = extract_threat_events([], client)
        assert result == []

    def test_extracts_all_events(self):
        events = [_event(1), _event(2), _event(3)]
        client = _MockClient(response=_extraction_json(events))
        result = extract_threat_events(events, client)
        assert len(result) == 3

    def test_extracted_fields_populated(self):
        events = [_event(1)]
        client = _MockClient(response=_extraction_json(events))
        result = extract_threat_events(events, client)
        r = result[0]
        assert r.event_id == "evt-0001"
        assert r.threat_actor == "APT29"
        assert r.motivation == "espionage"
        assert r.attack_type == "phishing"
        assert r.affected_sector == "government"
        assert "Ministry of Defence" in r.affected_organizations
        assert r.confidence_score == 0.85
        assert r.extraction_model == "test-model-v1"
        assert len(r.enterprise_mitigations) == 2

    def test_source_url_backfilled_from_event(self):
        events = [_event(42)]
        client = _MockClient(response=_extraction_json(events))
        result = extract_threat_events(events, client)
        assert result[0].source_url == "https://example.com/story-42"

    def test_returns_empty_on_malformed_json(self):
        client = _MockClient(response="not json at all")
        result = extract_threat_events([_event(1)], client)
        assert result == []

    def test_returns_empty_when_api_call_fails(self):
        client = _MockClient(response=None)
        result = extract_threat_events([_event(1)], client)
        assert result == []

    def test_batches_large_event_lists(self):
        """50 events should produce 2 batches of 25, resulting in 50 extracted records."""
        events = [_event(i) for i in range(50)]

        call_count = [0]
        def fake_complete(system, user, max_tokens=2048):
            # Parse the events from this batch out of the prompt JSON
            import re
            match = re.search(r'\[.*\]', user, re.DOTALL)
            batch = json.loads(match.group(0)) if match else []
            call_count[0] += 1
            return json.dumps([
                {"event_id": item["event_id"], "threat_actor": "unknown",
                 "motivation": "unknown", "attack_type": "unknown",
                 "affected_sector": "unknown", "affected_organizations": [],
                 "impact": "unknown", "enterprise_mitigations": [],
                 "confidence_score": 0.5}
                for item in batch
            ])

        client = _MockClient()
        client.complete = fake_complete
        result = extract_threat_events(events, client)
        assert call_count[0] == 2
        assert len(result) == 50

    def test_skips_malformed_records_gracefully(self):
        """If one record in a batch is malformed, others are still returned."""
        raw = json.dumps([
            {"event_id": "evt-0001", "threat_actor": "known-actor",
             "motivation": "financial", "attack_type": "ransomware",
             "affected_sector": "healthcare", "affected_organizations": [],
             "impact": "systems encrypted", "enterprise_mitigations": [],
             "confidence_score": 0.9},
            {"event_id": None, "confidence_score": "not-a-float"},  # malformed
        ])
        events = [_event(1), _event(2)]
        client = _MockClient(response=raw)
        result = extract_threat_events(events, client)
        # At least the valid record should be returned
        assert any(r.threat_actor == "known-actor" for r in result)


# ── JSON parsing ──────────────────────────────────────────────────────────────

class TestParseJson:
    def test_plain_json_array(self):
        raw = '[{"a": 1}]'
        assert _parse_json(raw) == [{"a": 1}]

    def test_strips_markdown_fences(self):
        raw = '```json\n[{"a": 1}]\n```'
        assert _parse_json(raw) == [{"a": 1}]

    def test_strips_plain_code_fences(self):
        raw = '```\n[{"a": 1}]\n```'
        assert _parse_json(raw) == [{"a": 1}]

    def test_raises_on_invalid_json(self):
        with pytest.raises(Exception):
            _parse_json("not json")


# ── Helper functions ──────────────────────────────────────────────────────────

class TestHelpers:
    def test_str_returns_unknown_for_none(self):
        assert _str(None) == "unknown"

    def test_str_returns_unknown_for_empty(self):
        assert _str("") == "unknown"

    def test_str_strips_whitespace(self):
        assert _str("  APT29  ") == "APT29"

    def test_clamp_keeps_valid_float(self):
        assert _clamp(0.75) == 0.75

    def test_clamp_caps_at_one(self):
        assert _clamp(1.5) == 1.0

    def test_clamp_floors_at_zero(self):
        assert _clamp(-0.5) == 0.0

    def test_clamp_handles_non_numeric(self):
        assert _clamp("high") == 0.0

    def test_strlist_filters_empty_strings(self):
        assert _strlist(["MFA", "", "  "]) == ["MFA"]

    def test_strlist_returns_empty_for_non_list(self):
        assert _strlist(None) == []
        assert _strlist("string") == []


# ── Summarizer ────────────────────────────────────────────────────────────────

class TestSummarizer:
    def test_returns_empty_strings_when_client_is_none(self):
        report = _report()
        executive, detailed = generate_summaries(report, [], client=None)
        assert executive == ""
        assert detailed == ""

    def test_returns_summaries_from_client(self):
        report = _report()
        responses = iter([
            "One critical actively-exploited CVE threatens enterprise systems this week.",
            "CVE-2026-1111 is actively exploited in the wild by nation-state actors targeting "
            "government infrastructure. Organizations should patch immediately and enable MFA.",
        ])
        client = _MockClient()
        client.complete = lambda system, user, max_tokens=400: next(responses)

        executive, detailed = generate_summaries(report, [], client)
        assert len(executive.split()) < 50
        assert len(detailed.split()) > 10

    def test_returns_empty_strings_when_client_fails(self):
        report = _report()
        client = _MockClient(response=None)
        executive, detailed = generate_summaries(report, [], client)
        assert executive == ""
        assert detailed == ""

    def test_summaries_are_stripped(self):
        report = _report()
        client = _MockClient(response="  Summary text with whitespace.  ")
        executive, detailed = generate_summaries(report, [], client)
        assert not executive.startswith(" ")
        assert not executive.endswith(" ")

    def test_complete_summary_is_not_retried(self):
        """A response that ends with a sentence terminator must not trigger a retry."""
        report = _report()
        call_count = [0]

        def fake_complete(system, user, max_tokens=400):
            call_count[0] += 1
            return "All systems are under active threat from nation-state actors."

        client = _MockClient()
        client.complete = fake_complete
        generate_summaries(report, [], client)
        # 2 calls total (one exec, one detail) — no retries
        assert call_count[0] == 2

    def test_truncated_response_triggers_retry(self):
        """A response without a sentence terminator must be retried exactly once."""
        report = _report()
        calls = []

        def fake_complete(system, user, max_tokens=400):
            calls.append(max_tokens)
            if len(calls) in (1, 3):
                # First attempt for each summary: truncated
                return "Our most urgent threat is an"
            # Retry: complete
            return "Our most urgent threat is an actively exploited CVE."

        client = _MockClient()
        client.complete = fake_complete
        executive, detailed = generate_summaries(report, [], client)

        assert executive.endswith(".")
        assert detailed.endswith(".")
        assert len(calls) == 4  # exec: 2 calls, detail: 2 calls

    def test_retry_uses_doubled_token_budget(self):
        """The retry call must use _RETRY_MULTIPLIER × the original token budget."""
        from summarizer.summarizer import _EXEC_MAX_TOKENS, _RETRY_MULTIPLIER
        report = _report()
        token_budgets = []

        def fake_complete(system, user, max_tokens=400):
            token_budgets.append(max_tokens)
            # Always truncated — forces retry
            return "Truncated without terminator"

        client = _MockClient()
        client.complete = fake_complete
        generate_summaries(report, [], client)

        exec_budgets = token_budgets[:2]  # first two calls are for executive summary
        assert exec_budgets[0] == _EXEC_MAX_TOKENS
        assert exec_budgets[1] == _EXEC_MAX_TOKENS * _RETRY_MULTIPLIER

    def test_falls_back_to_placeholder_when_both_attempts_too_short(self):
        """Both attempts < MIN_WORDS_BEFORE_FALLBACK must return empty string (placeholder)."""
        report = _report()

        client = _MockClient(response="Too short")  # no sentence terminator, < 10 words
        executive, detailed = generate_summaries(report, [], client)

        assert executive == ""
        assert detailed == ""

    def test_uses_longer_result_when_both_incomplete_but_long_enough(self):
        """When both attempts are incomplete but above the minimum, use the longer one."""
        report = _report()
        calls = [0]

        def fake_complete(system, user, max_tokens=400):
            calls[0] += 1
            if calls[0] % 2 == 1:
                # First attempt: shorter incomplete
                return "Threat actors are targeting critical infrastructure and financial"
            # Retry: longer incomplete but still no terminator
            return (
                "Threat actors are targeting critical infrastructure and financial "
                "institutions with advanced persistent threats and ransomware campaigns"
            )

        client = _MockClient()
        client.complete = fake_complete
        executive, detailed = generate_summaries(report, [], client)

        # Should use the longer retry result, not fall back to placeholder
        assert "ransomware campaigns" in executive
        assert "ransomware campaigns" in detailed


# ── is_complete helper ────────────────────────────────────────────────────────

class TestIsComplete:
    def test_period_is_complete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Patch immediately.") is True

    def test_exclamation_is_complete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Critical alert!") is True

    def test_question_mark_is_complete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Is your system patched?") is True

    def test_trailing_whitespace_ignored(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Patch now.   ") is True

    def test_truncated_mid_word_is_incomplete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Our most urgent threat is an") is False

    def test_truncated_mid_cve_is_incomplete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Critical vulnerability CVE-") is False

    def test_empty_string_is_incomplete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("") is False

    def test_sentence_with_closing_quote_is_complete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete('The threat is "critical."') is True

    def test_sentence_ending_in_parenthetical_cve_is_complete(self):
        from summarizer.summarizer import _is_complete
        assert _is_complete("Patch the affected system (CVE-2026-1234).") is True


# ── Prompt builder ────────────────────────────────────────────────────────────

class TestPromptBuilder:
    def test_extraction_prompt_contains_event_ids(self):
        events = [_event(1), _event(2)]
        prompt = build_extraction_prompt(events)
        assert "evt-0001" in prompt
        assert "evt-0002" in prompt

    def test_extraction_prompt_requests_json_array(self):
        prompt = build_extraction_prompt([_event(1)])
        assert "JSON array" in prompt

    def test_extraction_prompt_lists_all_required_fields(self):
        prompt = build_extraction_prompt([_event(1)])
        for field in [
            "threat_actor", "motivation", "attack_type", "affected_sector",
            "affected_organizations", "impact", "enterprise_mitigations", "confidence_score",
        ]:
            assert field in prompt

    def test_executive_prompt_specifies_word_limit(self):
        report = _report()
        prompt = build_executive_summary_prompt(report, [])
        assert "50" in prompt

    def test_detailed_prompt_specifies_word_target(self):
        report = _report()
        prompt = build_detailed_summary_prompt(report, [])
        assert "100" in prompt

    def test_prompts_include_kev_count(self):
        report = _report()
        exec_prompt = build_executive_summary_prompt(report, [])
        detail_prompt = build_detailed_summary_prompt(report, [])
        assert "KEV" in exec_prompt or "exploited" in exec_prompt.lower()
        assert "CVE" in detail_prompt

    def test_executive_prompt_includes_cve_ids(self):
        report = _report(vulns=[_vuln("CVE-2026-9999", is_kev=True)])
        prompt = build_executive_summary_prompt(report, [])
        assert "CVE-2026-9999" in prompt

    def test_extracted_events_appear_in_summary_context(self):
        extracted = [
            ExtractedThreatEvent(
                event_id="evt-0001",
                threat_actor="Lazarus Group",
                attack_type="ransomware",
                affected_sector="finance",
                confidence_score=0.9,
            )
        ]
        report = _report()
        prompt = build_executive_summary_prompt(report, extracted)
        assert "Lazarus Group" in prompt

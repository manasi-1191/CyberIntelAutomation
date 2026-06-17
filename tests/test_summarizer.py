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

    def test_returns_none_for_unknown_provider(self):
        with patch("config.settings.settings") as mock_settings:
            mock_settings.ai_provider = "openai"
            from summarizer.ai_provider import get_ai_client
            assert get_ai_client() is None


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

"""
Phase 3B — AI-assisted summary generation.

Generates two summaries from featured_vulnerabilities and AI-extracted events:
  executive_summary : under 50 words for C-suite
  detailed_summary  : ~100 words for executive audience

Neither summary overwrites CVSS scores, KEV counts, or other authoritative
data — those fields remain untouched on the DailyReport.
"""
import logging

from models.report import DailyReport
from models.extracted_event import ExtractedThreatEvent
from summarizer.prompt_builder import (
    SUMMARY_SYSTEM,
    build_executive_summary_prompt,
    build_detailed_summary_prompt,
)

logger = logging.getLogger(__name__)

_EXEC_MAX_TOKENS = 150
_DETAIL_MAX_TOKENS = 400


def generate_summaries(
    report: DailyReport,
    extracted: list[ExtractedThreatEvent],
    client,
) -> tuple[str, str]:
    """
    Return (executive_summary, detailed_summary).
    Returns ("", "") if client is None — caller retains placeholder text.
    Never raises.
    """
    if client is None:
        return "", ""

    executive = client.complete(
        system=SUMMARY_SYSTEM,
        user=build_executive_summary_prompt(report, extracted),
        max_tokens=_EXEC_MAX_TOKENS,
    ) or ""

    detailed = client.complete(
        system=SUMMARY_SYSTEM,
        user=build_detailed_summary_prompt(report, extracted),
        max_tokens=_DETAIL_MAX_TOKENS,
    ) or ""

    logger.info(
        "Summaries generated: executive=%d words, detailed=%d words (model=%s)",
        len(executive.split()), len(detailed.split()), client.model,
    )
    return executive.strip(), detailed.strip()

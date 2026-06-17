"""
Phase 3B — AI-assisted summary generation.

Generates two summaries from featured_vulnerabilities and AI-extracted events:
  executive_summary : under 50 words for C-suite
  detailed_summary  : ~100 words for executive audience

Neither summary overwrites CVSS scores, KEV counts, or other authoritative
data — those fields remain untouched on the DailyReport.
"""
import logging
import re

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
_RETRY_MULTIPLIER = 2
_MIN_WORDS_BEFORE_FALLBACK = 10

# Text is considered complete when it ends with a sentence terminator
# followed by optional closing punctuation / whitespace.
_SENTENCE_END = re.compile(r'[.!?]["\'\)\]]*\s*$')


def _is_complete(text: str) -> bool:
    """Heuristic: text ends with a sentence terminator."""
    return bool(_SENTENCE_END.search(text.strip()))


def _generate_with_retry(
    client,
    system: str,
    user: str,
    max_tokens: int,
    label: str,
) -> str:
    """
    Call client.complete() and retry once with doubled token budget if the
    response appears truncated (no sentence terminator at the end).

    Falls back to placeholder ("") when:
    - The API returns nothing on the first call.
    - Both attempts produce < _MIN_WORDS_BEFORE_FALLBACK words of text.
    """
    result = client.complete(system=system, user=user, max_tokens=max_tokens) or ""
    if not result:
        return ""

    if _is_complete(result):
        return result

    logger.warning(
        "%s summary appears truncated (%d words, no sentence terminator) "
        "— retrying with %dx token budget",
        label, len(result.split()), _RETRY_MULTIPLIER,
    )

    retry = client.complete(
        system=system, user=user, max_tokens=max_tokens * _RETRY_MULTIPLIER
    ) or ""

    if retry and _is_complete(retry):
        logger.info(
            "%s summary completed on retry (%d words)", label, len(retry.split())
        )
        return retry

    # Both attempts incomplete — use the longer one, or fall back to placeholder
    best = retry if len(retry) > len(result) else result
    if len(best.split()) < _MIN_WORDS_BEFORE_FALLBACK:
        logger.warning(
            "%s summary too short after retry (%d words) — falling back to placeholder",
            label, len(best.split()),
        )
        return ""

    logger.warning(
        "%s summary still incomplete after retry — using best available (%d words)",
        label, len(best.split()),
    )
    return best


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

    executive = _generate_with_retry(
        client,
        system=SUMMARY_SYSTEM,
        user=build_executive_summary_prompt(report, extracted),
        max_tokens=_EXEC_MAX_TOKENS,
        label="executive",
    )

    detailed = _generate_with_retry(
        client,
        system=SUMMARY_SYSTEM,
        user=build_detailed_summary_prompt(report, extracted),
        max_tokens=_DETAIL_MAX_TOKENS,
        label="detailed",
    )

    exec_words = len(executive.split()) if executive else 0
    detail_words = len(detailed.split()) if detailed else 0

    if exec_words > 50:
        logger.warning(
            "Executive summary exceeds 50-word limit (%d words) — prompt may need tightening",
            exec_words,
        )
    if detail_words > 0 and (detail_words < 60 or detail_words > 150):
        logger.warning(
            "Detailed summary word count (%d) is outside expected 60-150 range",
            detail_words,
        )

    logger.info(
        "Summaries generated: executive=%d words, detailed=%d words (model=%s)",
        exec_words, detail_words, client.model,
    )
    return executive.strip(), detailed.strip()

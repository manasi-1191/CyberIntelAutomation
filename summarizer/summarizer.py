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
    LINKEDIN_SYSTEM,
    build_executive_summary_prompt,
    build_detailed_summary_prompt,
    build_linkedin_preview_prompt,
)

logger = logging.getLogger(__name__)

_EXEC_MAX_TOKENS = 150
_DETAIL_MAX_TOKENS = 400
_LINKEDIN_MAX_TOKENS = 700
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

    # Return immediately only when the response is both present and complete
    if result and _is_complete(result):
        return result

    # Retry for either empty result OR truncated result (no sentence terminator)
    if not result:
        logger.warning(
            "%s summary empty on first attempt — retrying with %dx token budget",
            label, _RETRY_MULTIPLIER,
        )
    else:
        logger.warning(
            "%s summary appears truncated (%d words, no sentence terminator) "
            "— retrying with %dx token budget",
            label, len(result.split()), _RETRY_MULTIPLIER,
        )

    retry = client.complete(
        system=system, user=user, max_tokens=max_tokens * _RETRY_MULTIPLIER
    ) or ""

    if retry and _is_complete(retry):
        if result:
            logger.info(
                "%s summary completed on retry (%d words)", label, len(retry.split())
            )
        return retry

    # Both attempts empty/incomplete — use the longer one, or fall back to placeholder
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


def _build_fallback_executive(detailed: str) -> str:
    """
    Deterministic fallback for executive_summary when AI returns empty.
    Extracts the first complete sentence(s) from detailed_summary up to 50 words.
    Returns "" if detailed cannot yield at least _MIN_WORDS_BEFORE_FALLBACK words.
    """
    sentences = re.split(r'(?<=[.!?])\s+', detailed.strip())
    parts: list[str] = []
    word_count = 0
    for sentence in sentences:
        sentence_words = len(sentence.split())
        if word_count + sentence_words <= 50:
            parts.append(sentence)
            word_count += sentence_words
        else:
            break

    if parts and word_count >= _MIN_WORDS_BEFORE_FALLBACK:
        return " ".join(parts)

    # detailed may be one long run-on sentence — take first 45 words and snap to
    # the last sentence boundary within that window
    words = detailed.split()
    if len(words) < _MIN_WORDS_BEFORE_FALLBACK:
        return ""
    snippet = " ".join(words[:45])
    last_end = max(snippet.rfind("."), snippet.rfind("!"), snippet.rfind("?"))
    if last_end > len(snippet) // 3:
        return snippet[:last_end + 1]
    return snippet.rstrip(",:;") + "."


def generate_summaries(
    report: DailyReport,
    extracted: list[ExtractedThreatEvent],
    client,
) -> tuple[str, str]:
    """
    Return (executive_summary, detailed_summary).
    Returns ("", "") if client is None — caller retains placeholder text.
    If AI returns empty for executive but detailed is non-empty, a deterministic
    fallback is derived from detailed_summary.
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

    exec_source = "AI"
    if not executive and detailed:
        executive = _build_fallback_executive(detailed)
        exec_source = "FALLBACK"
        if executive:
            logger.warning(
                "executive_summary [FALLBACK]: AI returned empty — derived %d words "
                "from detailed_summary",
                len(executive.split()),
            )
        else:
            logger.error(
                "executive_summary [FALLBACK]: could not derive from detailed_summary "
                "— executive_summary will be empty"
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
        "Summaries generated: executive=%d words [%s], detailed=%d words (model=%s)",
        exec_words, exec_source, detail_words, client.model,
    )
    return executive.strip(), detailed.strip()


def generate_linkedin_preview(
    report,
    extracted: list,
    client,
) -> str:
    """
    Generate the LinkedIn post that will be shown in the approval email and
    published verbatim on APPROVE.  Returns "" on failure — caller must treat
    an empty result as a publish blocker.
    """
    if client is None:
        return ""

    preview = _generate_with_retry(
        client,
        system=LINKEDIN_SYSTEM,
        user=build_linkedin_preview_prompt(report, extracted),
        max_tokens=_LINKEDIN_MAX_TOKENS,
        label="linkedin_preview",
    )

    if not preview:
        logger.error(
            "linkedin_preview generation failed — publishing will be blocked until "
            "the AI pipeline is re-run: python main.py summarize --report-id %s",
            report.report_id,
        )
        return ""

    word_count = len(preview.split())
    if word_count < 100 or word_count > 400:
        logger.warning(
            "linkedin_preview word count (%d) is outside expected 150-300 range",
            word_count,
        )

    logger.info(
        "linkedin_preview generated: %d words (model=%s)",
        word_count, client.model,
    )
    return preview.strip()

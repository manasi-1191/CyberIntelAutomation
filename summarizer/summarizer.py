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

from models.audit import AuditAction
from models.report import DailyReport
from models.extracted_event import ExtractedThreatEvent
from storage.audit_logger import log_action
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
_LINKEDIN_MAX_TOKENS = 450
_RETRY_MULTIPLIER = 2
_MIN_WORDS_BEFORE_FALLBACK = 10

# Text is considered complete when it ends with a sentence terminator
# followed by optional closing punctuation / whitespace.
_SENTENCE_END = re.compile(r'[.!?]["\'\)\]]*\s*$')

# A line that contains only hashtags (e.g. "#CyberSecurity #InfoSec").
_HASHTAG_LINE = re.compile(r'^\s*(?:#\w+\s*)+$')


def _is_complete(text: str) -> bool:
    """Heuristic: text ends with a sentence terminator.

    Trailing hashtag-only lines are stripped before checking so a LinkedIn
    post whose body ends with a sentence terminator — even when followed by
    hashtags on the last line(s) — is correctly treated as complete.
    """
    stripped = text.strip()
    lines = stripped.splitlines()
    while lines and _HASHTAG_LINE.match(lines[-1]):
        lines.pop()
    body = "\n".join(lines).strip()
    return bool(_SENTENCE_END.search(body)) if body else bool(_SENTENCE_END.search(stripped))


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


def _build_fallback_detailed_summary(
    report: DailyReport, extracted: list[ExtractedThreatEvent]
) -> str:
    """
    Deterministic fallback for detailed_summary when AI returns empty.
    Builds a structured ~100-word executive brief from report data.
    Returns "" if not enough data to form a meaningful summary (< 2 sentences).
    """
    parts: list[str] = []

    # Lead: most critical vulnerability(ies)
    top_vulns = (report.featured_vulnerabilities or [])[:3]
    kev_vulns = [v for v in top_vulns if v.is_known_exploited]
    if kev_vulns:
        ids = ", ".join(v.cve_id for v in kev_vulns[:3])
        verb = "is" if len(kev_vulns) == 1 else "are"
        v0 = kev_vulns[0]
        raw = (v0.description or "")[:120]
        if len(v0.description or "") > 120:
            raw = (raw[: raw.rfind(" ")] if " " in raw else raw) + "..."
        ctx = f" — {raw}" if raw else ""
        parts.append(f"{ids} {verb} actively exploited in the wild{ctx}.")
    elif top_vulns:
        v0 = top_vulns[0]
        score = f" (CVSS {v0.cvss.base_score:.1f})" if v0.cvss else ""
        raw = (v0.description or "")[:100]
        if len(v0.description or "") > 100:
            raw = (raw[: raw.rfind(" ")] if " " in raw else raw) + "..."
        ctx = f": {raw}" if raw else ""
        parts.append(f"{v0.cve_id}{score} presents a critical risk{ctx}.")

    # Incident counts
    count_items = []
    if report.breach_count:
        count_items.append(f"{report.breach_count} data breach incident(s)")
    if report.attack_count:
        count_items.append(f"{report.attack_count} cyber attack(s)")
    if count_items:
        parts.append(f"This period also recorded {' and '.join(count_items)}.")

    # Threat actors and affected sectors
    actors = list(dict.fromkeys(
        e.threat_actor for e in (extracted or []) if e.threat_actor != "unknown"
    ))
    sectors = list(dict.fromkeys(
        e.affected_sector for e in (extracted or []) if e.affected_sector != "unknown"
    ))
    if actors and sectors:
        parts.append(
            f"Threat actors including {', '.join(actors[:2])} "
            f"targeted {', '.join(sectors[:3])} sector(s)."
        )
    elif actors:
        parts.append(f"Activity from {', '.join(actors[:2])} was observed.")
    elif sectors:
        parts.append(f"Affected sectors include {', '.join(sectors[:3])}.")

    # Recommended mitigation
    mitigations = list(dict.fromkeys(
        m for e in (extracted or []) for m in (e.enterprise_mitigations or [])
    ))
    if mitigations:
        top_m = mitigations[:2]
        parts.append(f"Recommended actions: {', '.join(m.lower() for m in top_m)}.")
    elif report.kev_count:
        parts.append(
            "Organisations must apply available patches immediately, "
            "prioritising vulnerabilities listed in the CISA KEV catalog."
        )
    elif report.critical_cve_count:
        parts.append(
            "Organisations should prioritise patching critical vulnerabilities "
            "and enable network monitoring for exploitation indicators."
        )

    if len(parts) < 2:
        return ""

    return " ".join(parts)


def generate_summaries(
    report: DailyReport,
    extracted: list[ExtractedThreatEvent],
    client,
) -> tuple[str, str]:
    """
    Return (executive_summary, detailed_summary).
    Returns ("", "") if client is None — caller retains placeholder text.
    When AI returns empty for detailed but executive succeeded, a deterministic
    fallback is derived from structured report data and logged as an audit error.
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

    # If detailed_summary is empty but executive succeeded, build deterministic fallback.
    # When both fail we return ("", "") and let the email gate block sending.
    detail_source = "AI"
    if not detailed and executive:
        detailed = _build_fallback_detailed_summary(report, extracted)
        detail_source = "FALLBACK"
        if detailed:
            log_action(
                AuditAction.ERROR,
                report_id=report.report_id,
                detail=(
                    f"detailed_summary AI failed — deterministic fallback used "
                    f"({len(detailed.split())}w)"
                ),
                success=False,
                error_message="AI returned empty for detailed_summary; fallback applied",
            )
            logger.warning(
                "detailed_summary [FALLBACK]: AI returned empty — derived %d words "
                "from report data",
                len(detailed.split()),
            )
        else:
            logger.error(
                "detailed_summary [FALLBACK]: AI returned empty and no fallback "
                "available — detailed_summary will be empty"
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
        "Summaries generated: executive=%d words [%s], detailed=%d words [%s] (model=%s)",
        exec_words, exec_source, detail_words, detail_source, client.model,
    )
    return executive.strip(), detailed.strip()


def _build_fallback_linkedin_preview(report: DailyReport, extracted: list) -> str:
    """
    Deterministic LinkedIn preview built from structured report data.
    Used when the AI pipeline fails twice.  Returns "" if the report lacks
    enough data to produce a meaningful post.
    """
    if not (report.critical_cve_count or report.kev_count or
            report.breach_count or report.attack_count or
            report.featured_vulnerabilities):
        return ""

    # 1. Hook
    if report.kev_count:
        hook = f"{report.kev_count} actively exploited vulnerability this week — patch now."
    elif report.critical_cve_count:
        hook = f"{report.critical_cve_count} critical CVE(s) reported in the last 48 hours."
    elif report.breach_count:
        hook = f"Data breach activity detected — {report.breach_count} incident(s) reported."
    else:
        hook = f"Cyber attack activity up — {report.attack_count} incident(s) in the last 48 hours."

    # 2. Summary paragraph (first two sentences of detailed_summary, or synthesised)
    if report.detailed_summary:
        sentences = re.split(r'(?<=[.!?])\s+', report.detailed_summary.strip())
        summary = " ".join(sentences[:2])
    else:
        parts = []
        if report.critical_cve_count:
            parts.append(f"{report.critical_cve_count} critical CVE(s) require immediate attention")
        if report.breach_count:
            parts.append(f"{report.breach_count} data breach(es) reported")
        if report.attack_count:
            parts.append(f"{report.attack_count} cyber attack(s) observed")
        summary = (". ".join(parts) + ".") if parts else "Review the full threat report for details."

    # 3. Bullets — top CVEs then notable threat actors
    bullets: list[str] = []
    for v in (report.featured_vulnerabilities or [])[:3]:
        kev = " (actively exploited)" if v.is_known_exploited else ""
        score = f", CVSS {v.cvss.base_score:.1f}" if v.cvss else ""
        raw_desc = (v.description or "")[:80]
        if len(v.description or "") > 80:
            cut = raw_desc[:raw_desc.rfind(" ")] if " " in raw_desc else raw_desc
            desc = cut + "..."
        else:
            desc = raw_desc
        bullets.append(f"- {v.cve_id}{score}{kev}: {desc}")

    actors: list[str] = []
    for e in (extracted or []):
        if getattr(e, "threat_actor", "unknown") != "unknown" and e.threat_actor not in actors:
            actors.append(e.threat_actor)
    for actor in actors[:2]:
        bullets.append(f"- {actor} activity observed")

    if not bullets:
        if report.breach_count:
            bullets.append(f"- {report.breach_count} data breach(es) reported this period")
        if report.attack_count:
            bullets.append(f"- {report.attack_count} attack(s) detected")

    # 4. Enterprise takeaway
    takeaway_parts = []
    if report.kev_count:
        takeaway_parts.append(
            "Apply available patches immediately, prioritising KEV-listed vulnerabilities"
        )
    elif report.critical_cve_count:
        takeaway_parts.append("Prioritise patching critical vulnerabilities in your environment")
    if report.breach_count or report.attack_count:
        takeaway_parts.append(
            "Review access logs and validate detection coverage for affected sectors"
        )
    takeaway = (". ".join(takeaway_parts) + ".") if takeaway_parts else "Keep systems patched and monitor for indicators of compromise."

    # 5. Hashtags
    tags = ["#CyberSecurity", "#ThreatIntelligence", "#InfoSec"]
    if report.kev_count or report.critical_cve_count:
        tags.append("#VulnerabilityManagement")
    if report.breach_count:
        tags.append("#DataBreach")

    parts = [hook, "", summary, ""]
    if bullets:
        parts.extend(bullets)
        parts.append("")
    parts.append(takeaway)
    parts.append("")
    parts.append(" ".join(tags))

    return "\n".join(parts).strip()


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
            "linkedin_preview AI generation failed (both attempts returned empty/blocked) "
            "— attempting deterministic fallback for report %s",
            report.report_id,
        )
        log_action(
            AuditAction.ERROR,
            report_id=report.report_id,
            detail="linkedin_preview AI generation failed — both attempts empty or safety-blocked",
            success=False,
            error_message="AI returned empty on both attempts; fallback attempted",
        )
        fallback = _build_fallback_linkedin_preview(report, extracted)
        if fallback:
            logger.info(
                "linkedin_preview using deterministic fallback (%d words)",
                len(fallback.split()),
            )
            return fallback
        logger.error(
            "linkedin_preview fallback also failed — publishing will be blocked. "
            "Re-run: python main.py summarize --report-id %s",
            report.report_id,
        )
        return ""

    word_count = len(preview.split())
    if word_count < 100 or word_count > 220:
        logger.warning(
            "linkedin_preview word count (%d) is outside expected 120-220 range",
            word_count,
        )

    logger.info(
        "linkedin_preview generated: %d words (model=%s)",
        word_count, client.model,
    )
    return preview.strip()

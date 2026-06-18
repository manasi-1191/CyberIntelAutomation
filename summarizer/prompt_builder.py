"""
Builds prompts for extraction and summarization.
All prompt logic lives here so extractor.py and summarizer.py stay thin.
"""
import json

from models.report import DailyReport
from models.extracted_event import ExtractedThreatEvent

LINKEDIN_SYSTEM = (
    "You are a professional cybersecurity threat intelligence author writing for an audience of "
    "CISOs, security leaders, IT directors, and enterprise decision-makers. "
    "Write in a professional, concise, and informative tone. "
    "Be direct and factual. Do not sensationalise, do not use marketing language, do not use clickbait. "
    "Every statement must be grounded in the intelligence provided — do not invent facts. "
    "If information is unavailable, omit that point rather than guessing."
)

EXTRACTION_SYSTEM = (
    "You are a cybersecurity analyst extracting structured intelligence from threat reports. "
    "Output must be valid JSON only — no markdown fences, no explanation, no trailing text. "
    "Do not invent facts. Use \"unknown\" for any field you cannot determine from the source text."
)

SUMMARY_SYSTEM = (
    "You are a cybersecurity analyst writing executive briefings for non-technical C-suite leaders. "
    "Write in plain English. No jargon, no acronyms without explanation, no raw CVSS scores."
)


def build_extraction_prompt(events: list) -> str:
    """Prompt asking the model to return a JSON array of extracted records."""
    items = []
    for e in events:
        desc = (e.description or "")[:300].strip()
        items.append({
            "event_id": e.event_id,
            "source": e.source,
            "title": e.title,
            "description": desc,
        })

    return (
        f"Extract threat intelligence from the following {len(items)} cybersecurity news items.\n"
        "Return a JSON array with one object per item IN THE SAME ORDER as the input.\n\n"
        "Each object must have EXACTLY these fields:\n"
        '  "event_id": string (copy verbatim from input — do not change)\n'
        '  "threat_actor": named threat actor or group, or "unknown"\n'
        '  "motivation": e.g. "financial", "espionage", "hacktivism", "disruption", or "unknown"\n'
        '  "attack_type": e.g. "ransomware", "phishing", "supply chain", "zero-day exploit", or "unknown"\n'
        '  "affected_sector": e.g. "healthcare", "finance", "government", "critical infrastructure", or "unknown"\n'
        '  "affected_organizations": JSON array of organization names explicitly mentioned (empty array if none)\n'
        '  "impact": one sentence describing consequences, or "unknown"\n'
        '  "enterprise_mitigations": JSON array of specific actionable steps (empty array if unclear)\n'
        '  "confidence_score": float 0.0-1.0 reflecting extraction quality given available detail\n\n'
        "Return ONLY the JSON array. No markdown, no explanation.\n\n"
        "Input:\n" + json.dumps(items, ensure_ascii=False)
    )


def build_executive_summary_prompt(
    report: DailyReport,
    extracted: list[ExtractedThreatEvent],
) -> str:
    return (
        f"Write an executive summary for the cybersecurity threat report dated {report.report_id}.\n\n"
        "STRICT CONSTRAINTS:\n"
        "- Under 50 words (count carefully before responding)\n"
        "- Name the single most urgent threat\n"
        "- Include exactly one concrete number\n"
        "- State the business risk in plain English\n"
        "- No CVSS scores. No unexplained acronyms.\n\n"
        f"{_vuln_context(report)}\n\n"
        f"{_event_context(extracted)}\n\n"
        "Output ONLY the summary text — no heading, no label, no quotation marks."
    )


def build_detailed_summary_prompt(
    report: DailyReport,
    extracted: list[ExtractedThreatEvent],
) -> str:
    return (
        f"Write a detailed cybersecurity threat summary for {report.report_id} "
        "aimed at a non-technical executive audience.\n\n"
        "STRICT CONSTRAINTS:\n"
        "- Approximately 100 words\n"
        "- Cover: the most critical actively-exploited vulnerabilities (name them by CVE ID), "
        "any identified threat actor activity, affected sectors, and one concrete mitigation recommendation\n"
        "- Replace 'CVSS score' with plain language like 'critical vulnerability actively exploited in the wild'\n"
        "- No jargon without explanation\n\n"
        f"{_vuln_context(report)}\n\n"
        f"{_event_context(extracted)}\n\n"
        "Output ONLY the summary text — no heading, no label, no quotation marks."
    )


# ── Context builders ──────────────────────────────────────────────────────────

def _vuln_context(report: DailyReport) -> str:
    lines = [
        f"VULNERABILITIES (last {report.collection_window_hours}h): "
        f"{len(report.vulnerabilities)} total | "
        f"{report.critical_cve_count} critical | "
        f"{report.kev_count} actively exploited (in CISA KEV)"
    ]
    top = (report.featured_vulnerabilities or [])[:10]
    for v in top:
        kev_tag = " [ACTIVELY EXPLOITED IN THE WILD]" if v.is_known_exploited else ""
        desc = (v.description or "")[:120]
        lines.append(f"  - {v.cve_id} ({v.severity}){kev_tag}: {desc}")
    return "\n".join(lines)


def _event_context(extracted: list[ExtractedThreatEvent]) -> str:
    if not extracted:
        return "THREAT EVENTS: none extracted"

    # Prefer high-confidence events with known threat actor
    ranked = sorted(extracted, key=lambda e: e.confidence_score, reverse=True)
    informative = [e for e in ranked if e.threat_actor != "unknown"]
    show = informative[:8] or ranked[:5]

    lines = [f"THREAT EVENTS: {len(extracted)} total | top {len(show)} by confidence shown:"]
    for e in show:
        parts = []
        if e.threat_actor != "unknown":
            parts.append(f"actor={e.threat_actor}")
        if e.attack_type != "unknown":
            parts.append(f"type={e.attack_type}")
        if e.affected_sector != "unknown":
            parts.append(f"sector={e.affected_sector}")
        if e.impact != "unknown":
            parts.append(f"impact={e.impact[:100]}")
        if e.enterprise_mitigations:
            parts.append(f"mitigation={e.enterprise_mitigations[0]}")
        lines.append("  - " + " | ".join(parts))
    return "\n".join(lines)


def build_linkedin_preview_prompt(
    report: DailyReport,
    extracted: list[ExtractedThreatEvent],
) -> str:
    """
    Prompt for generating the LinkedIn post shown in the approval email.
    The output is the exact text to publish if APPROVE is received.
    """
    vuln_ctx = _vuln_context(report)
    event_ctx = _event_context(extracted)

    has_vulns = bool(report.featured_vulnerabilities)
    has_events = bool(extracted)
    has_breaches = report.breach_count > 0
    has_attacks = report.attack_count > 0

    # Build a focused instruction based on what data is actually available
    coverage_notes = []
    if has_vulns:
        coverage_notes.append(
            f"- {report.critical_cve_count} critical CVE(s), {report.kev_count} actively exploited "
            "(in CISA KEV) — include CVE IDs where relevant"
        )
    if has_attacks:
        coverage_notes.append(f"- {report.attack_count} cyber attack(s) detected")
    if has_breaches:
        coverage_notes.append(f"- {report.breach_count} data breach(es) detected")
    if not coverage_notes:
        coverage_notes.append("- Limited intelligence available for this period")

    coverage_block = "\n".join(coverage_notes)

    return f"""Write a LinkedIn threat intelligence post for the 48-hour period ending {report.report_id}.

AUDIENCE: CISOs, security leaders, IT directors, security engineers, enterprise decision-makers.

TONE: Professional, concise, factual. No marketing language. No sensationalism. No generic filler.
Every bullet must be grounded in the intelligence below — omit any section where data is unavailable.

LENGTH: 150–300 words (count carefully).

REQUIRED STRUCTURE (use this exact format):

[One-line hook — start with a single relevant emoji, followed by a concise headline of the most significant development]

[2–3 sentence overview of the most important threat developments this period]

Key developments — last 48 hours:

• [Vulnerability highlights — include CVE IDs, severity, exploitation status]
• [Attack highlights — include threat actor, attack type, targeted sector]
• [Breach highlights — include organizations, data type, scale if known]
• [Threat actor highlights — attribution, motivation, TTPs if known]

(Omit any bullet category if no relevant intelligence is available.)

Enterprise considerations:

• [Key lesson or defensive takeaway]
• [Recommended action or control]
• [Security theme or pattern observed]

(Omit any bullet if not supported by the intelligence.)

[3–5 relevant hashtags — choose from: #CyberSecurity #ThreatIntelligence #InfoSec #CyberDefense #VulnerabilityManagement #DataBreach #Ransomware #ZeroDay #APT #CISO]

INTELLIGENCE:
{vuln_ctx}

{event_ctx}

COVERAGE AVAILABLE:
{coverage_block}

Output ONLY the LinkedIn post text — no heading, no label, no explanation, no quotation marks."""

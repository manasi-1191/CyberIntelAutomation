"""
Phase 3A — AI-assisted threat event extraction.

Sends batches of ThreatEvent records to the AI model and returns
structured ExtractedThreatEvent objects. Never touches CVSS scores,
KEV flags, or CVE counts — those come from authoritative sources.
"""
import json
import logging
from datetime import datetime

from models.threat import ThreatEvent
from models.extracted_event import ExtractedThreatEvent
from summarizer.prompt_builder import EXTRACTION_SYSTEM, build_extraction_prompt

logger = logging.getLogger(__name__)

_BATCH_SIZE = 25


def extract_threat_events(
    events: list[ThreatEvent],
    client,
) -> list[ExtractedThreatEvent]:
    """
    Run AI extraction over all threat events in batches.
    Returns empty list if client is None or no events supplied.
    Never raises — logs errors and returns what succeeded.
    """
    if client is None or not events:
        return []

    results: list[ExtractedThreatEvent] = []
    for i in range(0, len(events), _BATCH_SIZE):
        batch = events[i: i + _BATCH_SIZE]
        results.extend(_extract_batch(batch, client))

    logger.info(
        "Extraction: %d/%d events extracted (model=%s)",
        len(results), len(events), client.model,
    )
    return results


def _extract_batch(events: list[ThreatEvent], client) -> list[ExtractedThreatEvent]:
    prompt = build_extraction_prompt(events)
    raw = client.complete(system=EXTRACTION_SYSTEM, user=prompt, max_tokens=4096)
    if raw is None:
        return []

    try:
        parsed = _parse_json(raw)
    except Exception as exc:
        logger.error(
            "Failed to parse extraction response: %s\nRaw (first 300 chars): %.300s",
            exc, raw,
        )
        return []

    if not isinstance(parsed, list):
        logger.error("Extraction response was not a JSON array")
        return []

    event_map = {e.event_id: e for e in events}
    results: list[ExtractedThreatEvent] = []

    for item in parsed:
        if not isinstance(item, dict):
            continue
        event_id = item.get("event_id", "")
        source_event = event_map.get(event_id)
        try:
            results.append(ExtractedThreatEvent(
                event_id=event_id,
                source_url=source_event.source_url if source_event else "",
                threat_actor=_str(item.get("threat_actor")),
                motivation=_str(item.get("motivation")),
                attack_type=_str(item.get("attack_type")),
                affected_sector=_str(item.get("affected_sector")),
                affected_organizations=_strlist(item.get("affected_organizations")),
                impact=_str(item.get("impact")),
                enterprise_mitigations=_strlist(item.get("enterprise_mitigations")),
                confidence_score=_clamp(item.get("confidence_score")),
                extraction_model=client.model,
                extracted_at=datetime.utcnow(),
            ))
        except Exception as exc:
            logger.warning("Skipping malformed extraction record (event_id=%r): %s", event_id, exc)

    return results


def _parse_json(raw: str) -> list:
    """Strip markdown fences if present, then parse JSON."""
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:])
        fence_end = text.rfind("```")
        if fence_end != -1:
            text = text[:fence_end]
    return json.loads(text.strip())


def _str(val) -> str:
    if val is None or val == "":
        return "unknown"
    return str(val).strip() or "unknown"


def _clamp(val) -> float:
    try:
        return max(0.0, min(1.0, float(val)))
    except (TypeError, ValueError):
        return 0.0


def _strlist(val) -> list[str]:
    if not isinstance(val, list):
        return []
    return [str(x).strip() for x in val if x and str(x).strip()]

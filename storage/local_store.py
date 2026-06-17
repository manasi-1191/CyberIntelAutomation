"""
Persists raw collected data and reports as JSON files.
File layout:
  data/raw/<report_id>_vulnerabilities.json
  data/raw/<report_id>_events.json
  data/reports/<report_id>_report.json
"""
import logging
from datetime import datetime
from pathlib import Path

import orjson

from config.settings import settings
from models.vulnerability import Vulnerability
from models.threat import ThreatEvent
from models.report import DailyReport

logger = logging.getLogger(__name__)


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = orjson.dumps(obj, option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS)
    path.write_bytes(data)
    logger.debug("Wrote %s (%d bytes)", path, len(data))


def save_raw_collection(
    report_id: str,
    vulnerabilities: list[Vulnerability],
    events: list[ThreatEvent],
) -> None:
    _write(
        settings.raw_data_dir / f"{report_id}_vulnerabilities.json",
        [v.model_dump() for v in vulnerabilities],
    )
    _write(
        settings.raw_data_dir / f"{report_id}_events.json",
        [e.model_dump() for e in events],
    )
    logger.info("Saved raw collection for %s", report_id)


def save_report(report: DailyReport) -> Path:
    path = settings.reports_dir / f"{report.report_id}_report.json"
    _write(path, report.model_dump())
    logger.info("Saved report: %s", path)
    return path


def load_report(report_id: str) -> DailyReport | None:
    path = settings.reports_dir / f"{report_id}_report.json"
    if not path.exists():
        return None
    try:
        data = orjson.loads(path.read_bytes())
        return DailyReport(**data)
    except Exception as exc:
        logger.error("Failed to load report %s: %s", report_id, exc)
        return None


def list_reports() -> list[str]:
    """Returns report IDs sorted newest first."""
    paths = sorted(settings.reports_dir.glob("*_report.json"), reverse=True)
    return [p.stem.replace("_report", "") for p in paths]

"""
Append-only audit log — every system action is recorded here.
Format: one JSON object per line (NDJSON) for easy parsing.
"""
import logging
from pathlib import Path
from datetime import datetime

import orjson

from config.settings import settings
from models.audit import AuditEntry, AuditAction

logger = logging.getLogger(__name__)


def _audit_file(report_id: str) -> Path:
    return settings.audit_dir / f"{report_id}_audit.ndjson"


def log_action(
    action: AuditAction,
    report_id: str = "",
    source: str = "",
    detail: str = "",
    success: bool = True,
    error_message: str = "",
) -> None:
    entry = AuditEntry(
        action=action,
        report_id=report_id,
        source=source,
        detail=detail,
        success=success,
        error_message=error_message,
    )
    _append(entry)


def _append(entry: AuditEntry) -> None:
    if not entry.report_id:
        return

    path = _audit_file(entry.report_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    line = orjson.dumps(entry.model_dump()) + b"\n"
    with path.open("ab") as f:
        f.write(line)


def read_audit_log(report_id: str) -> list[AuditEntry]:
    path = _audit_file(report_id)
    if not path.exists():
        return []
    entries = []
    for line in path.read_bytes().splitlines():
        if line.strip():
            try:
                entries.append(AuditEntry(**orjson.loads(line)))
            except Exception:
                pass
    return entries

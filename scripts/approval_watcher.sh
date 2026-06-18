#!/usr/bin/env bash
#
# approval_watcher.sh — poll Gmail for approval replies and publish to LinkedIn.
#
# Safe to call from cron: always exits 0, logs all output to logs/approval_watcher.log.
# Skips reports that are already published (linkedin_post_id set) or already processed
# (status APPROVED/EDITED_APPROVED) — duplicate-post guards are enforced by main.py.
#
# Usage (manual):
#   bash scripts/approval_watcher.sh
#
# Usage (cron — see docs/SCHEDULING.md):
#   */10 8-20 * * 1-5 /path/to/project/scripts/approval_watcher.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
LOG_FILE="$LOG_DIR/approval_watcher.log"

mkdir -p "$LOG_DIR"
cd "$PROJECT_ROOT"

PYTHON="$PROJECT_ROOT/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    printf '%s [ERROR] venv not found at %s — run: python -m venv .venv && pip install -r requirements.txt\n' \
        "$(date -u "+%Y-%m-%dT%H:%M:%SZ")" "$PYTHON" >> "$LOG_FILE"
    exit 0   # exit 0 so cron does not send error mail on every run
fi

{
    printf '\n=== %s  check-approval ===\n' "$(date -u "+%Y-%m-%dT%H:%M:%SZ")"
    "$PYTHON" main.py check-approval
    rc=$?
    [ "$rc" -ne 0 ] && printf '[WARN] check-approval exited with code %d\n' "$rc"
} >> "$LOG_FILE" 2>&1

exit 0

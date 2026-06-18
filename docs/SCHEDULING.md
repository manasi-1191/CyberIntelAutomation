# Automatic Scheduling Guide

This document explains how to schedule the CyberIntel pipeline so that:

- Data is collected and emailed once per day automatically.
- Gmail is polled every 10 minutes during business hours so that a reply of
  **APPROVE**, **REJECT**, or an attached `.txt` edit publishes (or blocks)
  the LinkedIn post with no manual steps.

The client's only action is replying to the daily email.

---

## How the workflow runs end-to-end

```
07:00 UTC  cron runs  python main.py collect
           ↓
           Pipeline collects threats, runs AI summarization,
           saves the report, and sends the approval email.

08:00–20:00 (local)
           every 10 min  scripts/approval_watcher.sh
           ↓
           Polls Gmail for a reply to the approval email.

           APPROVE reply detected
           ↓
           Publishes the AI-generated summary to LinkedIn.
           Sets linkedin_post_id — subsequent polls skip this report.

           REJECT reply detected
           ↓
           Marks report as rejected. No post is made.

           .txt attachment detected
           ↓
           Publishes the attachment content instead of the AI summary.
```

If no reply is found the watcher exits silently and tries again in 10 minutes.

---

## Prerequisites

- Project is fully set up: Gmail and LinkedIn credentials in `.env`, venv active.
- `TEST_MODE=false` in `.env`.
- Both `APPROVAL_EMAIL_RECIPIENT` and `APPROVAL_EMAIL_SENDER` set in `.env`.

---

## Step 1 — Find your project path

```bash
cd /path/to/CyberIntelAutomation
pwd
```

Use the output (e.g. `/Users/yourname/CyberIntelAutomation`) everywhere
`PROJECT` appears below.

---

## Step 2 — Install the crontab entries

Open your crontab:

```bash
crontab -e
```

Add the following lines. Replace `PROJECT` with the full path from Step 1.
Replace `America/Los_Angeles` with your local timezone if different.

```cron
# ── CyberIntel Automation ─────────────────────────────────────────────────────

# Collect threats, build report, and send the approval email — daily at 07:00 UTC
0 7 * * * cd PROJECT && PROJECT/.venv/bin/python main.py collect >> PROJECT/logs/collect.log 2>&1

# Poll Gmail for an approval reply — every 10 minutes, Mon–Fri, 08:00–20:00 local time
CRON_TZ=America/Los_Angeles
*/10 8-20 * * 1-5 PROJECT/scripts/approval_watcher.sh
```

Save and exit (`Escape` then `:wq` in vi, or `Ctrl-X` then `Y` in nano).

Verify the entries were saved:

```bash
crontab -l
```

---

## Step 3 — Verify the watcher runs manually

Before relying on cron, confirm the script works:

```bash
bash scripts/approval_watcher.sh
cat logs/approval_watcher.log
```

You should see a timestamped entry. If there are no pending reports the line
will read `No pending reports with sent emails found.` — that is correct.

---

## Log locations

| Log file | What it contains |
|---|---|
| `logs/collect.log` | Daily collection run: sources, counts, AI summary, email send result |
| `logs/approval_watcher.log` | Every poll: whether a reply was found, approval decision, LinkedIn post ID |

Both files are appended to on every run. Rotate them monthly or use `logrotate`.

### What a successful approval looks like in `approval_watcher.log`

```
=== 2026-06-18T14:10:02Z  check-approval ===
2026-06-18T14:10:03 | INFO     | __main__ | Checking approval for 1 report(s): ['2026-06-17']
2026-06-18T14:10:03 | INFO     | __main__ | Polling Gmail for report 2026-06-17 (thread thread-abc123)
2026-06-18T14:10:04 | INFO     | emailer.approval_poller | Approval reply: APPROVED by sender@example.com
2026-06-18T14:10:04 | INFO     | __main__ | APPROVED by sender@example.com
2026-06-18T14:10:05 | INFO     | __main__ | Published to LinkedIn: urn:li:ugcPost:7312345678901234567
```

### What a skipped (already-published) report looks like

```
=== 2026-06-18T14:20:02Z  check-approval ===
2026-06-18T14:20:03 | INFO     | __main__ | Checking approval for 1 report(s): ['2026-06-17']
2026-06-18T14:20:03 | INFO     | __main__ | Report 2026-06-17 already published (linkedin_post_id=urn:li:ugcPost:7312345678901234567) — skipping
```

The duplicate-publish guard ensures a report is never posted twice, even if
the watcher polls after approval has already been processed.

---

## Adjusting the schedule

**Different collection time** (e.g., 06:00 UTC):
```cron
0 6 * * * cd PROJECT && PROJECT/.venv/bin/python main.py collect >> PROJECT/logs/collect.log 2>&1
```

**Wider polling window** (e.g., 07:00–22:00):
```cron
*/10 7-22 * * 1-5 PROJECT/scripts/approval_watcher.sh
```

**Also poll on weekends**:
```cron
*/10 8-20 * * * PROJECT/scripts/approval_watcher.sh
```

---

## Email approval gate

The LinkedIn post is **only published after an explicit APPROVE reply or
approved `.txt` attachment**. The watcher never publishes autonomously.

| Reply | Action |
|---|---|
| `APPROVE` (or `approved`, `yes`, `publish`) | Publishes AI-generated summary |
| `REJECT` (or `rejected`, `no`, `skip`, `deny`) | Marks report rejected, no post |
| `.txt` file attached | Publishes the attachment content instead of the AI summary |
| No reply / ambiguous reply | Poll again next cycle — nothing changes |

Only replies from `APPROVAL_EMAIL_RECIPIENT` are accepted. Replies from other
addresses are silently ignored.

---

## Token refresh reminder

LinkedIn access tokens expire after approximately **60 days**. When this happens
the watcher log will show a `401` error and the content will be saved locally
instead of posted. Refresh before expiry:

```bash
python scripts/linkedin_setup.py --refresh
```

Set a calendar reminder for 55 days after your last OAuth flow.

---

## Troubleshooting

**Watcher runs but no reports are checked**
- The daily `collect` run has not completed yet, or it failed.
- Check `logs/collect.log` for errors.
- Verify `GMAIL_REFRESH_TOKEN` is set in `.env`.

**Approval detected but LinkedIn post fails**
- Check for a `401` in `approval_watcher.log` — token is expired, run `--refresh`.
- Check for a `403` — LinkedIn app permissions issue, see `LINKEDIN_SETUP.md`.
- Content is saved to `data/reports/{report_id}_linkedin_manual.txt` as fallback.

**Double-post concern**
- Not possible. Once `linkedin_post_id` is set on a report, both
  `_check_and_process_approval` and `_publish_to_linkedin` return immediately
  on all subsequent calls. See commit `48bed8c` for guard implementation.

**Cron not running**
- On macOS, cron requires Full Disk Access. Go to:
  `System Settings → Privacy & Security → Full Disk Access` and add `/usr/sbin/cron`.
- Confirm the crontab is saved: `crontab -l`
- Check the system cron log: `grep cron /var/log/system.log | tail -20`

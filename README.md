# CyberIntel Automation

Automated daily cybersecurity intelligence pipeline. Collects threats from CISA, NVD, and RSS feeds, generates an AI-written briefing, sends it for approval by email, and — after an **APPROVE** reply — publishes the post to LinkedIn automatically.

---

## How it works

```
Daily (07:00 UTC)
  python main.py collect
  → Collects threats from CISA KEV, NVD CVE, CISA Advisories, RSS feeds
  → Runs AI extraction and summarization (Gemini / xAI / Anthropic)
  → Sends approval email to APPROVAL_EMAIL_RECIPIENT

Every 10 min (08:00–20:00, Mon–Fri)
  scripts/approval_watcher.sh
  → Polls Gmail for a reply
  → APPROVE reply → publishes to LinkedIn
  → REJECT reply  → skips, no post
  → .txt attached → publishes the attachment content instead
```

The approval email gate is mandatory — nothing is published without an explicit reply.

---

## Client workflow

1. Receive the daily briefing email.
2. Review the briefing (Executive Summary, Detailed Summary) and the **LinkedIn Preview** shown in the email — the Preview is the exact text that will be published.
3. Reply with one of:
   - `APPROVE` — publishes the LinkedIn Preview exactly as shown in the approval email.
   - `REJECT` — skips today's post entirely.
   - Attach a `.txt` file with your own wording — publishes your version instead of the Preview.
4. Done. The watcher detects your reply within 10 minutes and acts on it.

No login, no commands, no manual steps needed after setup.

---

## Quick start (first-time setup)

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure credentials

```bash
cp .env.example .env
```

Fill in your credentials in `.env`. See [CLIENT_HANDOFF.md](CLIENT_HANDOFF.md) for a step-by-step walkthrough of every field.

Set these in `.env`:

| Variable | How to get it |
|---|---|
| `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` / `GMAIL_REFRESH_TOKEN` | `python scripts/gmail_setup.py` |
| `LINKEDIN_CLIENT_ID` / `LINKEDIN_CLIENT_SECRET` / `LINKEDIN_ACCESS_TOKEN` | `python scripts/linkedin_setup.py` |
| `LINKEDIN_AUTHOR_URN` | `python scripts/linkedin_setup.py --whoami` |
| `APPROVAL_EMAIL_RECIPIENT` | Your email address |
| `GEMINI_API_KEY` (or `ANTHROPIC_API_KEY` / `XAI_API_KEY`) | From your AI provider |

### 3. Test before going live

```bash
TEST_MODE=true   # in .env — runs the full pipeline but saves LinkedIn output locally instead of posting
python main.py collect
```

### 4. Schedule automatic runs

See **[docs/SCHEDULING.md](docs/SCHEDULING.md)** for exact crontab entries.

### 5. Go live

```bash
# In .env:
TEST_MODE=false
```

---

## Manual commands

```bash
# Run the full pipeline for today
python main.py collect

# Backfill a specific date
python main.py collect --date 2026-06-15

# Re-run AI summarization on a saved report
python main.py summarize --report-id 2026-06-15

# Resend the approval email for a report
python main.py send-email --report-id 2026-06-15

# Check Gmail for approval replies (the watcher does this automatically)
python main.py check-approval
python main.py check-approval --report-id 2026-06-15
```

---

## Logs

| File | Contents |
|---|---|
| `logs/collect.log` | Daily collection and email send |
| `logs/approval_watcher.log` | Every poll: approval detected, LinkedIn post ID |
| `data/audit/` | Full audit trail of every pipeline action |

---

## Setup guides

- [**Client handoff — full setup walkthrough**](CLIENT_HANDOFF.md)
- [LinkedIn credentials and OAuth flow](LINKEDIN_SETUP.md)
- [Automatic scheduling and crontab](docs/SCHEDULING.md)

---

## Safeguards

- **Email gate**: LinkedIn is never posted without an APPROVE reply.
- **Content gate**: Approval email is blocked if AI summaries or LinkedIn preview are missing or contain placeholder text. Re-run `python main.py summarize --report-id <date>` after quota resets.
- **No double-posting**: Once `linkedin_post_id` is set on a report, all subsequent runs skip it.
- **Manual fallback**: If LinkedIn publishing fails, content is saved to `data/reports/{id}_linkedin_manual.txt` for copy-paste.
- **TEST_MODE**: Set `TEST_MODE=true` to run the full pipeline without touching LinkedIn.

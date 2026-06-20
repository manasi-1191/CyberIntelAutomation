# CyberIntel Automation — Client Handoff Guide

This document walks through everything you need to set up and operate the
CyberIntel Automation system on your own machine.

---

## What this system does

Every weekday morning the pipeline:

1. Collects cybersecurity threat intelligence from CISA, NVD, and industry RSS feeds.
2. Uses an AI model to generate an executive summary, a detailed briefing, and a LinkedIn post.
3. Emails you the briefing for review.
4. Waits for your reply — **nothing is published without your approval**.
5. On `APPROVE`, publishes the LinkedIn post automatically.

Your only daily action is replying to one email.

---

## Prerequisites

- **macOS or Linux** (Windows via WSL2 also works)
- **Python 3.11 or newer** — check with `python3 --version`
- **A Gmail account** to send and receive the daily approval email
- **A LinkedIn account** and a LinkedIn Developer app (free — setup takes ~10 minutes)
- **A Gemini API key** (free tier at aistudio.google.com) or an xAI / Anthropic key

---

## Step 1 — Install the project

```bash
# 1. Unzip or clone the project into a folder of your choice
cd ~/CyberIntelAutomation

# 2. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Step 2 — Create your .env file

```bash
cp .env.example .env
```

Then open `.env` in any text editor and fill in the values described in the
sections below. Leave `TEST_MODE=true` until the end of setup.

---

## Step 3 — Set up Gmail (approval email)

The pipeline sends the daily approval email from your Gmail account and reads
your reply from the same inbox.

```bash
python scripts/gmail_setup.py
```

- A browser window opens asking you to sign in to Google and grant access.
- After approving, the script prints three values.
- Copy them into `.env`:

```
GMAIL_CLIENT_ID=<value printed by the script>
GMAIL_CLIENT_SECRET=<value printed by the script>
GMAIL_REFRESH_TOKEN=<value printed by the script>
```

Also set:

```
APPROVAL_EMAIL_RECIPIENT=your-email@example.com
APPROVAL_EMAIL_SENDER=your-gmail@gmail.com
```

Both addresses are usually the same Gmail account.

---

## Step 4 — Get an AI API key

The pipeline uses an AI model to generate the daily briefing and LinkedIn post.

**Gemini (Google) — recommended, free tier available:**

1. Go to <https://aistudio.google.com/app/apikey>
2. Click **Create API key**
3. Copy the key into `.env`:

```
AI_PROVIDER=gemini
GEMINI_API_KEY=<your key>
```

**Alternatives:**

| Provider | Where to get the key | .env setting |
|---|---|---|
| xAI / Grok | console.x.ai | `AI_PROVIDER=xai` + `XAI_API_KEY=` |
| Anthropic | console.anthropic.com | `AI_PROVIDER=anthropic` + `ANTHROPIC_API_KEY=` |

---

## Step 5 — Set up LinkedIn

See **[LINKEDIN_SETUP.md](LINKEDIN_SETUP.md)** for the full walkthrough. The short version:

```bash
# 1. Run the OAuth setup (opens a browser window)
python scripts/linkedin_setup.py

# 2. Copy the printed credentials into .env:
#    LINKEDIN_CLIENT_ID=
#    LINKEDIN_CLIENT_SECRET=
#    LINKEDIN_ACCESS_TOKEN=

# 3. Get your LinkedIn author URN
python scripts/linkedin_setup.py --whoami

# 4. Copy the URN into .env:
#    LINKEDIN_AUTHOR_URN=urn:li:person:XXXX
```

---

## Step 6 — Test the full pipeline

With `TEST_MODE=true` in `.env`, run a complete end-to-end test:

```bash
python main.py collect
```

You should receive an approval email within a few minutes. Reply `APPROVE`.

Check the result:

```bash
python main.py check-approval
```

With `TEST_MODE=true` the post is **not** sent to LinkedIn. Instead the content
is saved to `data/reports/<date>_linkedin_draft.txt` so you can review it.

If everything looks right, continue to Step 7.

---

## Step 7 — Go live

In `.env`, change:

```
TEST_MODE=false
```

Run `python main.py collect` once more and reply `APPROVE` — this time the post
publishes to LinkedIn for real.

---

## Step 8 — Schedule automatic runs

Once you have confirmed the pipeline works, schedule it to run automatically.
See **[docs/SCHEDULING.md](docs/SCHEDULING.md)** for exact crontab entries.

Short version:

```crontab
# Collect and email once per day at 07:00 UTC
0 7 * * * /path/to/project/.venv/bin/python /path/to/project/main.py collect

# Poll Gmail for approval replies every 10 minutes, 08:00–20:00 Mon–Fri
*/10 8-20 * * 1-5 /path/to/project/scripts/approval_watcher.sh
```

---

## Daily operation

After scheduling, your only action is:

1. Receive the daily briefing email.
2. Read the AI-generated LinkedIn post in the email.
3. Reply with one of:
   - `APPROVE` — the post goes live on LinkedIn within 10 minutes.
   - `REJECT` — no post today.
   - Attach a `.txt` file with your own wording — publishes your version instead.

---

## Useful commands

```bash
# Re-run the full pipeline for today
python main.py collect

# Re-run AI summarisation on a saved report (e.g. after quota resets)
python main.py summarize --report-id 2026-06-19

# Resend the approval email for a report
python main.py send-email --report-id 2026-06-19

# Manually check Gmail for approval replies
python main.py check-approval
python main.py check-approval --report-id 2026-06-19
```

---

## Log files

| File | What it contains |
|---|---|
| `logs/collect.log` | Daily run: data collected, AI summary, email sent |
| `logs/approval_watcher.log` | Every poll: reply detected, LinkedIn post ID |
| `data/audit/<date>_audit.ndjson` | Full audit trail of every pipeline action |

---

## Safeguards

- **Email gate**: LinkedIn is never posted without an `APPROVE` reply.
- **Content gate**: The email is not sent unless the executive summary, detailed summary, and LinkedIn preview are all generated successfully.
- **No double-posting**: Once a report has a `linkedin_post_id`, all subsequent runs skip it automatically.
- **TEST_MODE**: Set `TEST_MODE=true` at any time to run the full pipeline without touching LinkedIn.
- **Manual fallback**: If LinkedIn publishing fails, the post content is saved to `data/reports/<date>_linkedin_manual.txt` for copy-paste.

---

## Troubleshooting

**Email not arriving**
- Check `logs/collect.log` for errors.
- Confirm `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, and `GMAIL_REFRESH_TOKEN` are set in `.env`.
- Re-run `python scripts/gmail_setup.py` if the refresh token has expired.

**AI summaries are empty**
- Check your API key is set in `.env` and the correct `AI_PROVIDER` is selected.
- Free-tier Gemini has a daily quota — the pipeline retries and uses a deterministic fallback if the quota is hit. The approval email is held until real summaries are available.

**LinkedIn post not publishing**
- Check `logs/approval_watcher.log` for the error.
- LinkedIn access tokens expire after approximately 60 days. When a token expires:
  1. The pipeline detects the 401 error automatically and attempts a one-shot token refresh.
  2. If the refresh succeeds, the post is published without any action from you.
  3. If the refresh fails (e.g. the refresh token itself has also expired), the post content is saved to `data/reports/<date>_linkedin_manual.txt` for copy-paste, and you will see an error in `logs/approval_watcher.log`.
  4. To re-authenticate: `python scripts/linkedin_setup.py --refresh`
- Confirm `LINKEDIN_AUTHOR_URN` matches your account (`python scripts/linkedin_setup.py --whoami`).

**"Approval email blocked" / briefing generation failed email**
- If one or more AI-generated content fields (executive summary, detailed summary, LinkedIn preview) could not be generated, the approval email is held and you will receive a separate **"Briefing generation failed"** notification email.
- The notification explains which field failed and gives the exact commands to retry once quota or API issues are resolved:
  ```bash
  python main.py summarize --report-id <date>
  python main.py send-email --report-id <date>
  ```
- You will only receive one notification per report — repeated pipeline runs do not spam your inbox.

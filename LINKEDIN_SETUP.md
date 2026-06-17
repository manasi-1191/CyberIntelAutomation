# LinkedIn Publishing Setup

This guide walks through connecting the CyberIntel pipeline to LinkedIn so that
approved daily briefings are posted automatically.

---

## Prerequisites

- Python 3.11+ with the project virtual environment activated
- A LinkedIn account where you want to post
- A `.env` file at the project root (copy from `.env.example`)
- `TEST_MODE=true` in `.env` while you set up — set it to `false` only when you
  are ready to go live

---

## Step 1 — Create a LinkedIn Developer App

1. Go to <https://www.linkedin.com/developers/apps>
2. Click **Create app**
3. Fill in:
   - **App name**: CyberIntel Automation (or any name)
   - **LinkedIn Page**: your personal profile or a company page you manage
   - **App logo**: any square image
4. Click **Create app**

---

## Step 2 — Add the "Share on LinkedIn" Product

1. Inside your new app, go to the **Products** tab
2. Find **Share on LinkedIn** and click **Request access**
3. This grants the `w_member_social` OAuth scope needed to post on your behalf
4. Approval is usually instant for personal profiles

> **Posting to a Company Page?**  
> You additionally need the **Marketing Developer Platform** product, which
> requires LinkedIn approval (can take several days). For personal profiles,
> "Share on LinkedIn" is sufficient.

---

## Step 3 — Get OAuth Credentials

1. In your app, go to the **Auth** tab
2. Copy the **Client ID** and **Client Secret**
3. Under **OAuth 2.0 settings**, add this redirect URI:
   ```
   http://localhost:8080/callback
   ```
4. Add to your `.env` file:
   ```
   LINKEDIN_CLIENT_ID=your-client-id-here
   LINKEDIN_CLIENT_SECRET=your-client-secret-here
   ```

---

## Step 4 — Run the OAuth Flow

```bash
python scripts/linkedin_setup.py
```

This will:
1. Open your browser to LinkedIn's authorization page
2. Ask you to approve the permissions
3. Capture the authorization code from the callback
4. Exchange it for access and refresh tokens
5. Offer to write the tokens to `.env` automatically

At the end you will see something like:
```
LINKEDIN_ACCESS_TOKEN=AQX...
LINKEDIN_REFRESH_TOKEN=AQX...
```

---

## Step 5 — Get Your Author URN

The author URN tells LinkedIn which account to post as.

```bash
python scripts/linkedin_setup.py --whoami
```

Output:
```
  Your LinkedIn URN: urn:li:person:AbCdEfG12345
```

Add this to `.env`:
```
LINKEDIN_AUTHOR_URN=urn:li:person:AbCdEfG12345
```

Or let the script write it for you when prompted.

> **Posting to a Company/Organisation Page?**  
> The URN is `urn:li:organization:{page-id}`. Find the page ID in your
> LinkedIn Page admin URL, e.g. `linkedin.com/company/12345678/admin/` → ID is `12345678`.
> Use `urn:li:organization:12345678`.

---

## Step 6 — Verify the Connection

```bash
python scripts/linkedin_setup.py --verify
```

Expected output:
```
  Connected as : Jane Smith
  Email        : jane@example.com

LinkedIn credentials are working.
```

---

## Step 7 — Go Live

When you are satisfied with the test output files, update `.env`:

```
TEST_MODE=false
```

The next approved briefing will be published live to LinkedIn.

---

## Token Refresh

LinkedIn access tokens expire after approximately **60 days**. When they expire,
publishing will log a `401` error and fall back to saving the content locally.

To refresh:
```bash
python scripts/linkedin_setup.py --refresh
```

This exchanges `LINKEDIN_REFRESH_TOKEN` for a new `LINKEDIN_ACCESS_TOKEN` and
offers to write it to `.env`.

> **Refresh token expiry**: Refresh tokens expire after 12 months of inactivity
> or when a new OAuth flow is completed. If the refresh fails, re-run the full
> OAuth flow: `python scripts/linkedin_setup.py`

---

## Manual Fallback

If LinkedIn publishing fails for any reason (expired token, API error, rate
limit, misconfigured permissions), the pipeline **never loses content**. Instead
it saves the approved post text to:

```
data/reports/{report_id}_linkedin_manual.txt
```

Open this file and copy-paste the content into LinkedIn at:
<https://www.linkedin.com/feed/>

---

## Required Environment Variables

| Variable | Required | Description |
|---|---|---|
| `LINKEDIN_CLIENT_ID` | For setup only | From your LinkedIn Developer app |
| `LINKEDIN_CLIENT_SECRET` | For setup only | From your LinkedIn Developer app |
| `LINKEDIN_ACCESS_TOKEN` | For publishing | From the OAuth flow |
| `LINKEDIN_REFRESH_TOKEN` | For token refresh | From the OAuth flow |
| `LINKEDIN_AUTHOR_URN` | For publishing | `urn:li:person:{id}` or `urn:li:organization:{id}` |

---

## Troubleshooting

**`401 Unauthorized`**  
Token is expired. Run: `python scripts/linkedin_setup.py --refresh`

**`403 Forbidden`**  
- Your app does not have the "Share on LinkedIn" product approved  
- `LINKEDIN_AUTHOR_URN` does not match the authenticated account  
- For org pages: "Marketing Developer Platform" approval is required  
Run `--whoami` to verify your URN.

**`422 Unprocessable Entity`**  
The post payload was rejected. Check the logs for details. Usually caused by an
invalid URN format or unsupported content.

**`429 Rate Limited`**  
LinkedIn has a daily post limit. Content is saved locally for manual posting.

**Browser does not open during OAuth flow**  
Copy the URL printed in the terminal and open it manually. Then paste the full
redirect URL when prompted.

**`TEST_MODE=true` — posts never appear on LinkedIn**  
This is expected. Set `TEST_MODE=false` to enable live publishing.

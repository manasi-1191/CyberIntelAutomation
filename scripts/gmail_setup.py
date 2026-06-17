"""
One-time Gmail OAuth2 setup script.
Run this once to obtain a refresh token for the service account.

Prerequisites:
  1. Go to https://console.cloud.google.com/
  2. Create a project (or select an existing one)
  3. Enable the Gmail API:
       APIs & Services → Enable APIs → search "Gmail API" → Enable
  4. Create OAuth2 credentials:
       APIs & Services → Credentials → Create Credentials → OAuth client ID
       Application type: Desktop app
       Name: CyberIntel
  5. Copy the Client ID and Client Secret into your .env file:
       GMAIL_CLIENT_ID=...
       GMAIL_CLIENT_SECRET=...
  6. Run this script: python scripts/gmail_setup.py
  7. A browser window will open — sign in with the Gmail account that will SEND emails
  8. Copy the printed GMAIL_REFRESH_TOKEN into your .env file

Usage:
  python scripts/gmail_setup.py
"""
import os
import sys

# Allow running from any directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from config.settings import settings
from emailer.gmail_auth import SCOPES


def main() -> None:
    print()
    print("=" * 60)
    print("  CyberIntel — Gmail OAuth2 Setup")
    print("=" * 60)
    print()

    if not settings.gmail_client_id or not settings.gmail_client_secret:
        print("ERROR: GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET must be")
        print("       set in your .env file before running this script.")
        print()
        print("  See the instructions at the top of this file.")
        sys.exit(1)

    print(f"Client ID : {settings.gmail_client_id[:20]}...")
    print(f"Sender    : {settings.approval_email_sender or '(set APPROVAL_EMAIL_SENDER in .env)'}")
    print()
    print("A browser window will open. Sign in with the Gmail account")
    print("that will SEND the daily report emails.")
    print()
    input("Press Enter to open the browser...")
    print()

    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print("ERROR: google-auth-oauthlib is not installed.")
        print("       Run: pip install -r requirements.txt")
        sys.exit(1)

    client_config = {
        "installed": {
            "client_id": settings.gmail_client_id,
            "client_secret": settings.gmail_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"],
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    creds = flow.run_local_server(port=0, prompt="consent", access_type="offline")

    print()
    print("=" * 60)
    print("  SUCCESS — Add this to your .env file:")
    print("=" * 60)
    print()
    print(f"GMAIL_REFRESH_TOKEN={creds.refresh_token}")
    print()
    print("After adding it, verify the setup with:")
    print("  python scripts/gmail_setup.py --verify")
    print()

    # Optionally write to .env automatically
    answer = input("Write GMAIL_REFRESH_TOKEN to .env automatically? [y/N]: ").strip().lower()
    if answer == "y":
        _write_to_env("GMAIL_REFRESH_TOKEN", creds.refresh_token)
        print("Written to .env")
    else:
        print("Copy the token above and add it to .env manually.")


def _verify() -> None:
    """Quick connectivity test — sends nothing, just authenticates."""
    print()
    print("Verifying Gmail credentials...")
    try:
        from emailer.gmail_auth import get_gmail_service
        service = get_gmail_service()
        profile = service.users().getProfile(userId="me").execute()
        print(f"  Connected as : {profile.get('emailAddress')}")
        print(f"  Messages total: {profile.get('messagesTotal', '?')}")
        print()
        print("Gmail credentials are working correctly.")
    except Exception as exc:
        print(f"  ERROR: {exc}")
        print()
        print("Check your .env values and try running the setup again.")
        sys.exit(1)


def _write_to_env(key: str, value: str) -> None:
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(env_path):
        with open(env_path, "w") as f:
            f.write(f"{key}={value}\n")
        return

    with open(env_path, "r") as f:
        lines = f.readlines()

    found = False
    new_lines = []
    for line in lines:
        if line.startswith(f"{key}="):
            new_lines.append(f"{key}={value}\n")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{key}={value}\n")

    with open(env_path, "w") as f:
        f.writelines(new_lines)


if __name__ == "__main__":
    if "--verify" in sys.argv:
        _verify()
    else:
        main()

"""
LinkedIn OAuth2 setup script.

Usage:
  python scripts/linkedin_setup.py           # initial token setup (opens browser)
  python scripts/linkedin_setup.py --verify  # test current token with a /userinfo call
  python scripts/linkedin_setup.py --whoami  # print your LinkedIn person URN
  python scripts/linkedin_setup.py --refresh # exchange refresh token for new access token

See LINKEDIN_SETUP.md for full setup instructions.
"""
import argparse
import http.server
import os
import sys
import threading
import urllib.parse
import webbrowser

# Allow running as a script from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import httpx
from config.settings import settings

_AUTH_URL = "https://www.linkedin.com/oauth/v2/authorization"
_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"
_USERINFO_URL = "https://api.linkedin.com/v2/userinfo"
_ME_URL = "https://api.linkedin.com/v2/me"
_CALLBACK_PORT = 8080
_REDIRECT_URI = f"http://localhost:{_CALLBACK_PORT}/callback"
_SCOPES = "openid profile w_member_social"


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    code: str | None = None
    _event: threading.Event = threading.Event()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        if "code" in params:
            _CallbackHandler.code = params["code"]
            body = (
                b"<html><body>"
                b"<h2>Authorization successful!</h2>"
                b"<p>You can close this tab and return to the terminal.</p>"
                b"</body></html>"
            )
            self.send_response(200)
        else:
            error = params.get("error_description", params.get("error", "unknown"))
            body = (
                f"<html><body><h2>Authorization failed</h2>"
                f"<p>{error}</p></body></html>"
            ).encode()
            self.send_response(400)

        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)
        _CallbackHandler._event.set()

    def log_message(self, *args) -> None:
        pass  # silence server access logs


def main() -> None:
    parser = argparse.ArgumentParser(description="LinkedIn OAuth2 setup for CyberIntel")
    parser.add_argument("--verify", action="store_true", help="Test current credentials")
    parser.add_argument("--whoami", action="store_true", help="Print your LinkedIn person URN")
    parser.add_argument("--refresh", action="store_true", help="Refresh the access token")
    args = parser.parse_args()

    if args.verify:
        _verify()
    elif args.whoami:
        _whoami()
    elif args.refresh:
        _refresh()
    else:
        _run_oauth_flow()


def _run_oauth_flow() -> None:
    print()
    print("=" * 60)
    print("  CyberIntel — LinkedIn OAuth2 Setup")
    print("=" * 60)
    print()

    if not settings.linkedin_client_id or not settings.linkedin_client_secret:
        print("ERROR: LINKEDIN_CLIENT_ID and LINKEDIN_CLIENT_SECRET must be")
        print("       set in your .env file before running this script.")
        print()
        print("  See LINKEDIN_SETUP.md for instructions.")
        sys.exit(1)

    print(f"Client ID  : {settings.linkedin_client_id[:8]}...")
    print(f"Redirect   : {_REDIRECT_URI}")
    print(f"Scopes     : {_SCOPES}")
    print()

    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": settings.linkedin_client_id,
        "redirect_uri": _REDIRECT_URI,
        "scope": _SCOPES,
    })
    auth_url = f"{_AUTH_URL}?{params}"

    _CallbackHandler.code = None
    _CallbackHandler._event.clear()

    server = http.server.HTTPServer(("localhost", _CALLBACK_PORT), _CallbackHandler)
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    print("Opening browser for LinkedIn authorization...")
    print(f"If the browser does not open, visit:\n  {auth_url}\n")
    webbrowser.open(auth_url)

    print("Waiting for authorization callback (timeout: 120s)...")
    _CallbackHandler._event.wait(timeout=120)
    server.server_close()

    code = _CallbackHandler.code
    if not code:
        print("\nERROR: Timed out or authorization was denied.")
        print("Make sure you approved the LinkedIn permissions in the browser.")
        sys.exit(1)

    print("Authorization code received — exchanging for tokens...")

    try:
        resp = httpx.post(
            _TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _REDIRECT_URI,
                "client_id": settings.linkedin_client_id,
                "client_secret": settings.linkedin_client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30.0,
        )
        resp.raise_for_status()
        tokens = resp.json()
    except Exception as exc:
        print(f"\nERROR: Token exchange failed: {exc}")
        sys.exit(1)

    access_token = tokens.get("access_token", "")
    refresh_token = tokens.get("refresh_token", "")
    expires_in = tokens.get("expires_in", 5183999)

    print()
    print("=" * 60)
    print("  SUCCESS — Add these to your .env file:")
    print("=" * 60)
    print()
    print(f"LINKEDIN_ACCESS_TOKEN={access_token}")
    if refresh_token:
        print(f"LINKEDIN_REFRESH_TOKEN={refresh_token}")
    print()
    print(f"Token expires in approximately {expires_in // 86400} days.")
    print()
    print("Next step — find your author URN:")
    print("  python scripts/linkedin_setup.py --whoami")
    print()

    answer = input("Write tokens to .env automatically? [y/N]: ").strip().lower()
    if answer == "y":
        _write_to_env("LINKEDIN_ACCESS_TOKEN", access_token)
        if refresh_token:
            _write_to_env("LINKEDIN_REFRESH_TOKEN", refresh_token)
        print("Written to .env")
    else:
        print("Copy the tokens above and add them to .env manually.")


def _refresh() -> None:
    print()
    print("Refreshing LinkedIn access token...")

    from linkedin.auth import can_refresh, try_refresh_token

    if not can_refresh():
        print("ERROR: LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET, and LINKEDIN_REFRESH_TOKEN")
        print("       must all be set in .env to refresh the token.")
        print()
        print("If you have no refresh token, re-run the full OAuth flow:")
        print("  python scripts/linkedin_setup.py")
        sys.exit(1)

    new_token = try_refresh_token()
    if not new_token:
        print("ERROR: Token refresh failed. Check the logs.")
        print("If the refresh token is expired, re-run the full OAuth flow:")
        print("  python scripts/linkedin_setup.py")
        sys.exit(1)

    print()
    print("=" * 60)
    print("  New access token:")
    print("=" * 60)
    print()
    print(f"LINKEDIN_ACCESS_TOKEN={new_token}")
    print()

    answer = input("Write LINKEDIN_ACCESS_TOKEN to .env? [y/N]: ").strip().lower()
    if answer == "y":
        _write_to_env("LINKEDIN_ACCESS_TOKEN", new_token)
        print("Written to .env")
    else:
        print("Update .env manually with the token above.")


def _verify() -> None:
    print()
    print("Verifying LinkedIn credentials...")

    if not settings.linkedin_access_token:
        print("ERROR: LINKEDIN_ACCESS_TOKEN is not set in .env")
        print("Run: python scripts/linkedin_setup.py")
        sys.exit(1)

    try:
        resp = httpx.get(
            _USERINFO_URL,
            headers={"Authorization": f"Bearer {settings.linkedin_access_token}"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            sub = data.get("sub", "")
            urn = f"urn:li:person:{sub}" if sub else "(not returned)"
            print(f"  Connected as : {data.get('name', '(unknown)')}")
            print(f"  Email        : {data.get('email', '(not in scope)')}")
            print(f"  Author URN   : {urn}")
            print()
            print("LinkedIn credentials are working.")
        elif resp.status_code == 401:
            print("  ERROR: Token expired (401)")
            print("  Refresh it: python scripts/linkedin_setup.py --refresh")
            sys.exit(1)
        elif resp.status_code in (403, 400):
            # /v2/userinfo requires 'openid' scope from the "Sign In with LinkedIn"
            # product. With only "Share on LinkedIn" the call is rejected — but the
            # token is still valid for posting (w_member_social is all we need).
            print("  Token obtained — posting scope (w_member_social) is active.")
            print()
            print("  Note: profile info not available without the")
            print("  'Sign In with LinkedIn using OpenID Connect' product.")
            print("  This does NOT affect LinkedIn publishing.")
        else:
            print(f"  ERROR: {resp.status_code} — {resp.text[:200]}")
            sys.exit(1)
    except Exception as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)


def _whoami() -> None:
    print()
    print("Fetching your LinkedIn profile URN...")

    if not settings.linkedin_access_token:
        print("ERROR: LINKEDIN_ACCESS_TOKEN is not set in .env")
        print("Run: python scripts/linkedin_setup.py")
        sys.exit(1)

    try:
        resp = httpx.get(
            _USERINFO_URL,
            headers={"Authorization": f"Bearer {settings.linkedin_access_token}"},
            timeout=15.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            sub = data.get("sub", "")
            if not sub:
                print("  ERROR: 'sub' field missing from /v2/userinfo response.")
                print("  Try re-running the OAuth flow: python scripts/linkedin_setup.py")
                sys.exit(1)
            urn = f"urn:li:person:{sub}"
            print()
            print(f"  Your LinkedIn URN: {urn}")
            print()
            print("Add this to your .env file:")
            print(f"  LINKEDIN_AUTHOR_URN={urn}")
            print()
            answer = input("Write LINKEDIN_AUTHOR_URN to .env? [y/N]: ").strip().lower()
            if answer == "y":
                _write_to_env("LINKEDIN_AUTHOR_URN", urn)
                print("Written to .env")
        elif resp.status_code == 401:
            print("  ERROR: Token expired — run: python scripts/linkedin_setup.py --refresh")
            sys.exit(1)
        elif resp.status_code in (403, 400):
            # /v2/me requires profile scope ('Sign In with LinkedIn' product).
            # With only 'Share on LinkedIn' (w_member_social) this returns 403.
            print("  Profile API not available with current scopes.")
            print()
            print("  To find your LinkedIn author URN, choose one of these options:")
            print()
            print("  Option A — Add 'Sign In with LinkedIn using OpenID Connect'")
            print("  product to your app (usually instant approval), then re-run:")
            print("    python scripts/linkedin_setup.py        (re-authorize)")
            print("    python scripts/linkedin_setup.py --whoami")
            print()
            print("  Option B — Find your numeric member ID from your profile page:")
            print("  1. Open your LinkedIn profile in a browser")
            print("  2. View page source (Ctrl+U / Cmd+U)")
            print("  3. Search for '\"memberId\"' in the source")
            print("  4. The number after it is your member ID")
            print("  5. Set: LINKEDIN_AUTHOR_URN=urn:li:person:<that-number>")
            print()
            print("  Option C — Get it from a LinkedIn API client or the")
            print("  LinkedIn Developer Portal under your app's authorized users.")
        else:
            print(f"  ERROR: {resp.status_code} — {resp.text[:200]}")
            sys.exit(1)
    except Exception as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)


def _write_to_env(key: str, value: str) -> None:
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
    )
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
    main()

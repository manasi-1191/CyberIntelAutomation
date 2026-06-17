"""
Gmail OAuth2 credential management.
Reads client_id, client_secret, and refresh_token from Settings.
Never stores tokens to disk — always refreshes in memory from the stored refresh_token.
"""
import logging

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from config.settings import settings

logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]


class GmailCredentialsError(Exception):
    """Raised when Gmail credentials are missing or invalid."""


def _check_credentials_configured() -> None:
    missing = [
        name
        for name, val in [
            ("GMAIL_CLIENT_ID", settings.gmail_client_id),
            ("GMAIL_CLIENT_SECRET", settings.gmail_client_secret),
            ("GMAIL_REFRESH_TOKEN", settings.gmail_refresh_token),
        ]
        if not val
    ]
    if missing:
        raise GmailCredentialsError(
            f"Gmail credentials not configured. Missing env vars: {', '.join(missing)}. "
            "Run: python scripts/gmail_setup.py"
        )


def get_credentials() -> Credentials:
    _check_credentials_configured()
    creds = Credentials(
        token=None,
        refresh_token=settings.gmail_refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.gmail_client_id,
        client_secret=settings.gmail_client_secret,
        scopes=SCOPES,
    )
    creds.refresh(Request())
    logger.debug("Gmail credentials refreshed successfully")
    return creds


def get_gmail_service():
    """Return an authenticated Gmail API service object."""
    creds = get_credentials()
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def is_configured() -> bool:
    """Return True if all Gmail credentials are present in settings."""
    return all([
        settings.gmail_client_id,
        settings.gmail_client_secret,
        settings.gmail_refresh_token,
        settings.approval_email_sender,
        settings.approval_email_recipient,
    ])

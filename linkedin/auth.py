"""
LinkedIn credential management.

All credentials come from environment variables — nothing is stored on disk.

Required for publishing:
  LINKEDIN_ACCESS_TOKEN  — OAuth2 bearer token (expires in ~60 days)
  LINKEDIN_AUTHOR_URN    — urn:li:person:{id} or urn:li:organization:{id}

Required for token refresh (optional but recommended):
  LINKEDIN_CLIENT_ID
  LINKEDIN_CLIENT_SECRET
  LINKEDIN_REFRESH_TOKEN
"""
import logging

import httpx

from config.settings import settings

logger = logging.getLogger(__name__)

_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"


def is_configured() -> bool:
    """Return True if the minimum credentials for publishing are present."""
    return bool(settings.linkedin_access_token and settings.linkedin_author_urn)


def can_refresh() -> bool:
    """Return True if token-refresh credentials are all present."""
    return bool(
        settings.linkedin_client_id
        and settings.linkedin_client_secret
        and settings.linkedin_refresh_token
    )


def get_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.linkedin_access_token}",
        "Content-Type": "application/json",
        "X-Restli-Protocol-Version": "2.0.0",
        "LinkedIn-Version": "202304",
    }


def try_refresh_token() -> str | None:
    """
    Exchange LINKEDIN_REFRESH_TOKEN for a new access token.
    Returns the new access token on success, None on failure.
    Does NOT update .env — the caller or setup script handles that.
    """
    if not can_refresh():
        logger.error(
            "Cannot refresh LinkedIn token: LINKEDIN_CLIENT_ID, LINKEDIN_CLIENT_SECRET, "
            "and LINKEDIN_REFRESH_TOKEN must all be set. "
            "Run: python scripts/linkedin_setup.py --refresh"
        )
        return None

    try:
        resp = httpx.post(
            _TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": settings.linkedin_refresh_token,
                "client_id": settings.linkedin_client_id,
                "client_secret": settings.linkedin_client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30.0,
        )
        if resp.status_code == 200:
            return resp.json().get("access_token")
        logger.error(
            "LinkedIn token refresh failed (%d): %s",
            resp.status_code, resp.text[:200],
        )
        return None
    except Exception as exc:
        logger.error("LinkedIn token refresh error: %s", exc)
        return None

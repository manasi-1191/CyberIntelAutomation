"""
LinkedIn UGC Posts API publisher.
https://learn.microsoft.com/en-us/linkedin/marketing/integrations/community-management/shares/ugc-post-api

Posts a text update to a LinkedIn person profile or organisation page.

Safety guarantees:
  - Never publishes when settings.test_mode is True (RuntimeError as hard guard).
  - Author URN is validated before any HTTP call.
  - Content is truncated to 3 000 chars (LinkedIn API limit) before sending.
  - All HTTP errors are handled and logged with actionable remediation messages.
"""
import logging
import re

import httpx

from config.settings import settings
from linkedin.auth import get_headers

logger = logging.getLogger(__name__)

_UGC_POSTS_URL = "https://api.linkedin.com/v2/ugcPosts"


class LinkedInAuthError(Exception):
    """Raised by publish_post when LinkedIn returns 401 Unauthorized.

    Signals that the access token has expired.  The caller should attempt a
    one-shot token refresh via linkedin.auth.try_refresh_token() and retry.
    """

CONTENT_MAX_CHARS = 3000  # LinkedIn text-post character limit

_AUTHOR_URN_RE = re.compile(r"^urn:li:(person|organization):\w+$")


def publish_post(content: str, author_urn: str, report_id: str = "") -> str | None:
    """
    Publish a text post to LinkedIn.

    Returns the post URN (e.g. "urn:li:ugcPost:12345") on success, None on failure.
    Raises RuntimeError if called with TEST_MODE=true — this is a programming error.
    Raises ValueError if author_urn is missing or malformed.
    """
    if settings.test_mode:
        raise RuntimeError(
            "publish_post() called with TEST_MODE=true. "
            "LinkedIn must never be called in TEST_MODE — check _publish_or_simulate()."
        )

    _validate_author_urn(author_urn)
    content = _prepare_content(content)

    payload = {
        "author": author_urn,
        "lifecycleState": "PUBLISHED",
        "specificContent": {
            "com.linkedin.ugc.ShareContent": {
                "shareCommentary": {"text": content},
                "shareMediaCategory": "NONE",
            }
        },
        "visibility": {
            "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
        },
    }

    try:
        resp = httpx.post(
            _UGC_POSTS_URL,
            json=payload,
            headers=get_headers(),
            timeout=30.0,
        )
    except httpx.NetworkError as exc:
        logger.error("LinkedIn network error during publish: %s", exc)
        return None
    except Exception as exc:
        logger.error("LinkedIn publish unexpected error: %s", exc)
        return None

    if resp.status_code == 201:
        post_urn = resp.headers.get("x-restli-id", "")
        logger.info("Published to LinkedIn: %s (report_id=%s)", post_urn, report_id)
        return post_urn

    _handle_error_response(resp)
    return None


def _validate_author_urn(urn: str) -> None:
    if not urn:
        raise ValueError(
            "LINKEDIN_AUTHOR_URN is not set. "
            "Run: python scripts/linkedin_setup.py --whoami"
        )
    if not _AUTHOR_URN_RE.match(urn):
        raise ValueError(
            f"Invalid LINKEDIN_AUTHOR_URN: {urn!r}. "
            "Must match urn:li:person:XXXXX or urn:li:organization:XXXXX. "
            "Run: python scripts/linkedin_setup.py --whoami"
        )


def _prepare_content(content: str) -> str:
    content = content.strip()
    if len(content) > CONTENT_MAX_CHARS:
        logger.warning(
            "Content (%d chars) exceeds LinkedIn %d-char limit — truncating",
            len(content), CONTENT_MAX_CHARS,
        )
        content = content[: CONTENT_MAX_CHARS - 1] + "…"
    return content


def _handle_error_response(resp: httpx.Response) -> None:
    status = resp.status_code
    if status == 401:
        logger.warning(
            "LinkedIn token expired (401) — caller will attempt automatic refresh"
        )
        raise LinkedInAuthError("401 Unauthorized — access token expired")
    elif status == 403:
        logger.error(
            "LinkedIn permission denied (403). Possible causes:\n"
            "  1. The 'Share on LinkedIn' product is not approved on your Developer app\n"
            "  2. LINKEDIN_AUTHOR_URN does not match the authenticated account\n"
            "  3. Posting to an organisation page requires 'Marketing Developer Platform' approval\n"
            "Run: python scripts/linkedin_setup.py --whoami  to verify your URN\n"
            "See: LINKEDIN_SETUP.md for API product setup instructions"
        )
    elif status == 422:
        logger.error(
            "LinkedIn rejected the post payload (422 Unprocessable Entity): %s",
            resp.text[:300],
        )
    elif status == 429:
        logger.error(
            "LinkedIn rate limit exceeded (429). The daily post limit has been reached. "
            "Content has been saved for manual posting."
        )
    else:
        logger.error("LinkedIn API error %d: %s", status, resp.text[:300])

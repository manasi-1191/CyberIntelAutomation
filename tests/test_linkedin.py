"""
Tests for Phase 4 LinkedIn publishing.

All HTTP calls are mocked with respx. No live API calls are made.
settings.test_mode is patched to False on tests that exercise the publish path
— the default value (True) is verified by the TEST_MODE guard tests.
"""
import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from linkedin.auth import can_refresh, get_headers, is_configured, try_refresh_token
from linkedin.publisher import (
    CONTENT_MAX_CHARS,
    _prepare_content,
    _validate_author_urn,
    publish_post,
)

_POST_URL = "https://api.linkedin.com/v2/ugcPosts"
_TOKEN_URL = "https://www.linkedin.com/oauth/v2/accessToken"

_VALID_URN = "urn:li:person:ABCDE12345"


def _prod_settings(
    access_token: str = "test-token",
    author_urn: str = _VALID_URN,
    client_id: str = "cid",
    client_secret: str = "csec",
    refresh_token: str = "rt",
) -> MagicMock:
    m = MagicMock()
    m.test_mode = False
    m.linkedin_access_token = access_token
    m.linkedin_author_urn = author_urn
    m.linkedin_client_id = client_id
    m.linkedin_client_secret = client_secret
    m.linkedin_refresh_token = refresh_token
    return m


# ── Publisher: TEST_MODE guard ────────────────────────────────────────────────

class TestPublishTestModeGuard:
    def test_raises_runtime_error_in_test_mode(self):
        """publish_post must raise RuntimeError when settings.test_mode is True (the default)."""
        with pytest.raises(RuntimeError, match="TEST_MODE"):
            publish_post("Content", _VALID_URN)

    def test_raises_even_with_valid_credentials(self):
        """TEST_MODE guard fires before any credential or URN check."""
        with pytest.raises(RuntimeError, match="TEST_MODE"):
            publish_post("Content", _VALID_URN, report_id="2026-06-17")


# ── Publisher: success path ───────────────────────────────────────────────────

class TestPublishSuccess:
    def test_returns_post_urn_on_201(self):
        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(
                return_value=httpx.Response(
                    201, headers={"x-restli-id": "urn:li:ugcPost:12345"}
                )
            )
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                result = publish_post("Valid content.", _VALID_URN)

        assert result == "urn:li:ugcPost:12345"

    def test_sends_correct_payload(self):
        captured: list[dict] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured.append(json.loads(request.content))
            return httpx.Response(201, headers={"x-restli-id": "urn:li:ugcPost:99"})

        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(side_effect=_capture)
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                publish_post("Hello LinkedIn.", _VALID_URN)

        assert len(captured) == 1
        body = captured[0]
        assert body["author"] == _VALID_URN
        assert body["lifecycleState"] == "PUBLISHED"
        commentary = body["specificContent"]["com.linkedin.ugc.ShareContent"]["shareCommentary"]
        assert commentary["text"] == "Hello LinkedIn."
        assert body["visibility"]["com.linkedin.ugc.MemberNetworkVisibility"] == "PUBLIC"

    def test_sends_bearer_token_in_header(self):
        captured_headers: list[dict] = []

        def _capture(request: httpx.Request) -> httpx.Response:
            captured_headers.append(dict(request.headers))
            return httpx.Response(201, headers={"x-restli-id": "urn:li:ugcPost:1"})

        mock_s = _prod_settings(access_token="my-secret-token")
        with respx.mock:
            respx.post(_POST_URL).mock(side_effect=_capture)
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                publish_post("Content.", _VALID_URN)

        assert captured_headers[0]["authorization"] == "Bearer my-secret-token"


# ── Publisher: error handling ─────────────────────────────────────────────────

class TestPublishErrors:
    def test_returns_none_on_401(self):
        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(return_value=httpx.Response(401, text="Unauthorized"))
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                result = publish_post("Content.", _VALID_URN)
        assert result is None

    def test_returns_none_on_403(self):
        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(return_value=httpx.Response(403, text="Forbidden"))
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                result = publish_post("Content.", _VALID_URN)
        assert result is None

    def test_returns_none_on_422(self):
        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(return_value=httpx.Response(422, text="Unprocessable"))
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                result = publish_post("Content.", _VALID_URN)
        assert result is None

    def test_returns_none_on_429(self):
        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(return_value=httpx.Response(429, text="Rate limit"))
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                result = publish_post("Content.", _VALID_URN)
        assert result is None

    def test_returns_none_on_network_error(self):
        mock_s = _prod_settings()
        with respx.mock:
            respx.post(_POST_URL).mock(side_effect=httpx.NetworkError("connection refused"))
            with patch("linkedin.publisher.settings", mock_s), \
                 patch("linkedin.auth.settings", mock_s):
                result = publish_post("Content.", _VALID_URN)
        assert result is None


# ── Publisher: URN validation ─────────────────────────────────────────────────

class TestUrnValidation:
    def test_person_urn_accepted(self):
        _validate_author_urn("urn:li:person:ABC123")  # must not raise

    def test_organization_urn_accepted(self):
        _validate_author_urn("urn:li:organization:987654")  # must not raise

    def test_empty_urn_raises(self):
        mock_s = _prod_settings()
        with patch("linkedin.publisher.settings", mock_s), \
             patch("linkedin.auth.settings", mock_s):
            with pytest.raises(ValueError, match="LINKEDIN_AUTHOR_URN is not set"):
                publish_post("Content.", "")

    def test_malformed_urn_raises(self):
        mock_s = _prod_settings()
        with patch("linkedin.publisher.settings", mock_s), \
             patch("linkedin.auth.settings", mock_s):
            with pytest.raises(ValueError, match="Invalid LINKEDIN_AUTHOR_URN"):
                publish_post("Content.", "person:123")

    def test_urn_without_prefix_raises(self):
        with pytest.raises(ValueError):
            _validate_author_urn("12345")


# ── Publisher: content preparation ───────────────────────────────────────────

class TestContentPreparation:
    def test_content_within_limit_unchanged(self):
        assert _prepare_content("Short.") == "Short."

    def test_content_at_exact_limit_unchanged(self):
        content = "x" * CONTENT_MAX_CHARS
        result = _prepare_content(content)
        assert len(result) == CONTENT_MAX_CHARS

    def test_content_over_limit_is_truncated(self):
        content = "x" * (CONTENT_MAX_CHARS + 500)
        result = _prepare_content(content)
        assert len(result) <= CONTENT_MAX_CHARS

    def test_truncated_content_ends_with_ellipsis(self):
        content = "x" * (CONTENT_MAX_CHARS + 1)
        result = _prepare_content(content)
        assert result.endswith("…")

    def test_leading_trailing_whitespace_stripped(self):
        assert _prepare_content("  Hello.  ") == "Hello."


# ── Auth: is_configured / get_headers ────────────────────────────────────────

class TestLinkedInAuth:
    def test_is_configured_true_when_token_and_urn_present(self):
        mock_s = MagicMock()
        mock_s.linkedin_access_token = "tok"
        mock_s.linkedin_author_urn = "urn:li:person:1"
        with patch("linkedin.auth.settings", mock_s):
            assert is_configured() is True

    def test_is_configured_false_when_token_missing(self):
        mock_s = MagicMock()
        mock_s.linkedin_access_token = ""
        mock_s.linkedin_author_urn = "urn:li:person:1"
        with patch("linkedin.auth.settings", mock_s):
            assert is_configured() is False

    def test_is_configured_false_when_urn_missing(self):
        mock_s = MagicMock()
        mock_s.linkedin_access_token = "tok"
        mock_s.linkedin_author_urn = ""
        with patch("linkedin.auth.settings", mock_s):
            assert is_configured() is False

    def test_get_headers_includes_bearer(self):
        mock_s = MagicMock()
        mock_s.linkedin_access_token = "abc123"
        with patch("linkedin.auth.settings", mock_s):
            headers = get_headers()
        assert headers["Authorization"] == "Bearer abc123"
        assert headers["X-Restli-Protocol-Version"] == "2.0.0"
        assert "LinkedIn-Version" in headers

    def test_can_refresh_true_when_all_credentials_present(self):
        mock_s = MagicMock()
        mock_s.linkedin_client_id = "cid"
        mock_s.linkedin_client_secret = "csec"
        mock_s.linkedin_refresh_token = "rt"
        with patch("linkedin.auth.settings", mock_s):
            assert can_refresh() is True

    def test_can_refresh_false_when_refresh_token_missing(self):
        mock_s = MagicMock()
        mock_s.linkedin_client_id = "cid"
        mock_s.linkedin_client_secret = "csec"
        mock_s.linkedin_refresh_token = ""
        with patch("linkedin.auth.settings", mock_s):
            assert can_refresh() is False


# ── Auth: try_refresh_token ───────────────────────────────────────────────────

class TestTryRefreshToken:
    def test_returns_new_token_on_200(self):
        mock_s = MagicMock()
        mock_s.linkedin_client_id = "cid"
        mock_s.linkedin_client_secret = "csec"
        mock_s.linkedin_refresh_token = "old-rt"
        with respx.mock:
            respx.post(_TOKEN_URL).mock(
                return_value=httpx.Response(200, json={"access_token": "new-token-xyz"})
            )
            with patch("linkedin.auth.settings", mock_s):
                result = try_refresh_token()
        assert result == "new-token-xyz"

    def test_returns_none_on_400(self):
        mock_s = MagicMock()
        mock_s.linkedin_client_id = "cid"
        mock_s.linkedin_client_secret = "csec"
        mock_s.linkedin_refresh_token = "bad-rt"
        with respx.mock:
            respx.post(_TOKEN_URL).mock(
                return_value=httpx.Response(400, text="invalid_grant")
            )
            with patch("linkedin.auth.settings", mock_s):
                result = try_refresh_token()
        assert result is None

    def test_returns_none_when_credentials_missing(self):
        mock_s = MagicMock()
        mock_s.linkedin_client_id = ""
        mock_s.linkedin_client_secret = ""
        mock_s.linkedin_refresh_token = ""
        with patch("linkedin.auth.settings", mock_s):
            result = try_refresh_token()
        assert result is None

    def test_returns_none_on_network_error(self):
        mock_s = MagicMock()
        mock_s.linkedin_client_id = "cid"
        mock_s.linkedin_client_secret = "csec"
        mock_s.linkedin_refresh_token = "rt"
        with respx.mock:
            respx.post(_TOKEN_URL).mock(side_effect=httpx.NetworkError("timeout"))
            with patch("linkedin.auth.settings", mock_s):
                result = try_refresh_token()
        assert result is None

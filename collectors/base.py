import logging
from abc import ABC, abstractmethod
from datetime import datetime

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from models.vulnerability import Vulnerability
from models.threat import ThreatEvent

logger = logging.getLogger(__name__)

# Shared HTTP client — all collectors reuse one connection pool
_client: httpx.Client | None = None


def get_http_client() -> httpx.Client:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.Client(
            timeout=httpx.Timeout(30.0),
            follow_redirects=True,
            headers={"User-Agent": "CyberIntelBot/1.0 (security research)"},
        )
    return _client


class BaseCollector(ABC):
    name: str = "base"

    def __init__(self, window_start: datetime, window_end: datetime) -> None:
        self.window_start = window_start
        self.window_end = window_end
        self.logger = logging.getLogger(f"cyberintel.collector.{self.name}")

    @abstractmethod
    def collect(self) -> tuple[list[Vulnerability], list[ThreatEvent]]:
        """Return (vulnerabilities, threat_events) collected within the time window."""

    def within_window(self, dt: datetime | None) -> bool:
        if dt is None:
            return False
        # Make naive datetimes comparable
        ts = dt.replace(tzinfo=None) if dt.tzinfo else dt
        return self.window_start <= ts <= self.window_end

    @retry(
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _get(self, url: str, **kwargs) -> httpx.Response:
        client = get_http_client()
        response = client.get(url, **kwargs)
        response.raise_for_status()
        return response

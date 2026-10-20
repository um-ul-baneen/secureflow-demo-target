"""
analytics-engine/src/main/controller/File16.py
===============================================
Analytics engine metrics-fetching controller.

Retrieves metric snapshots from remote analytics endpoints, normalises the
JSON response, and returns structured result objects for further processing
by the aggregation layer.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import json
import time
from typing import Any, Optional
from urllib.parse import urlparse

import requests


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class MetricsResult:
    """Lightweight container for a fetched metrics payload.

    Attributes:
        url:         The endpoint that was queried.
        status_code: HTTP status code returned by the server.
        data:        Parsed JSON body (or ``None`` on parse failure).
        elapsed_ms:  Round-trip latency in milliseconds.
        error:       Non-``None`` when the fetch failed.
    """

    def __init__(
        self,
        url: str,
        status_code: int,
        data: Optional[dict],
        elapsed_ms: float,
        error: Optional[str] = None,
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.data = data
        self.elapsed_ms = elapsed_ms
        self.error = error

    def is_ok(self) -> bool:
        """Return ``True`` when the fetch succeeded with a 2xx status."""
        return self.status_code // 100 == 2 and self.error is None

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"MetricsResult(url={self.url!r}, status={self.status_code}, "
            f"ok={self.is_ok()}, elapsed_ms={self.elapsed_ms:.1f})"
        )


# ---------------------------------------------------------------------------
# URL validation helpers
# ---------------------------------------------------------------------------

def is_allowed_scheme(url: str, allowed: tuple[str, ...] = ("https",)) -> bool:
    """Return ``True`` if the URL scheme is in the *allowed* set.

    Args:
        url:     The URL to inspect.
        allowed: Tuple of permitted schemes (default: ``("https",)``).

    Returns:
        Boolean indicating whether the scheme is permitted.
    """
    parsed = urlparse(url)
    return parsed.scheme in allowed


def build_query_params(base: dict, overrides: Optional[dict] = None) -> dict:
    """Merge *base* params with optional *overrides*, returning a new dict.

    Args:
        base:      Default query parameters.
        overrides: Parameters that take precedence over *base*.

    Returns:
        Merged parameter dict (a new object; neither input is mutated).
    """
    result = dict(base)
    if overrides:
        result.update(overrides)
    return result


def parse_metrics_body(body: str) -> Optional[dict]:
    """Parse a JSON metrics body, returning ``None`` on decode failure.

    Args:
        body: Raw response body string.

    Returns:
        Parsed dict or ``None``.
    """
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def default_headers() -> dict:
    """Return a dict of default HTTP request headers for metrics requests.

    Returns:
        Dict with ``Accept`` and ``User-Agent`` headers.
    """
    return {
        "Accept": "application/json",
        "User-Agent": "SecureFlow-AnalyticsEngine/1.0",
    }


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — TLS verification disabled
# ---------------------------------------------------------------------------

def fetch_metrics(url: str, params: Optional[dict] = None) -> MetricsResult:
    """Fetch a metrics snapshot from *url* and return a :class:`MetricsResult`.

    Args:
        url:    The HTTPS endpoint to query.
        params: Optional dict of query parameters to append to the request.

    Returns:
        A :class:`MetricsResult` populated from the server response.

    .. danger::
        TLS certificate verification is explicitly disabled (``verify=False``).
        This makes every request vulnerable to man-in-the-middle attacks: an
        attacker on the network can intercept and modify metric data without
        detection.  Remove ``verify=False`` and allow the default ``True``.
    """
    headers = default_headers()
    t0 = time.monotonic()
    try:
        # VULNERABLE: verify=False disables TLS certificate validation
        response = requests.get(url, params=params, headers=headers, verify=False, timeout=10)
        elapsed = (time.monotonic() - t0) * 1000
        data = parse_metrics_body(response.text)
        return MetricsResult(
            url=url,
            status_code=response.status_code,
            data=data,
            elapsed_ms=elapsed,
        )
    except requests.RequestException as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return MetricsResult(
            url=url,
            status_code=0,
            data=None,
            elapsed_ms=elapsed,
            error=str(exc),
        )

"""
search-indexer/src/main/service/File43.py
==========================================
Search-indexer external API client module.

Manages authentication headers and session configuration for the external
search-indexer service.  Reads credentials from the environment at runtime
so that secrets are never committed to source control.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import os
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

DEFAULT_API_BASE = "https://search-api.internal/v2"
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5  # seconds


# ---------------------------------------------------------------------------
# VULNERABLE — hardcoded secret token at module level
# ---------------------------------------------------------------------------

# VULNERABLE: API token is hardcoded in source rather than read from the
# environment.  Anyone with read access to this file (version control,
# logs, error reports) obtains a working credential.
# A real remediation must remove this constant and ensure get_client_headers()
# reads exclusively from the environment, raising when the variable is absent.
_api_token = "demo-token-not-a-real-secret"  # noqa: S105


# ---------------------------------------------------------------------------
# Session / retry helpers
# ---------------------------------------------------------------------------

def _backoff_seconds(attempt: int) -> float:
    """Return exponential back-off duration for *attempt* (0-indexed).

    Args:
        attempt: Zero-based retry attempt number.

    Returns:
        Float number of seconds to sleep before the next retry.
    """
    return RETRY_BACKOFF_BASE * (2 ** attempt)


def build_base_url(path: str, base: str = DEFAULT_API_BASE) -> str:
    """Construct a full URL by joining *base* with *path*.

    Args:
        path: Relative API path, e.g. ``"/indices/products"``.
        base: Base URL (default: :data:`DEFAULT_API_BASE`).

    Returns:
        Concatenated URL string.
    """
    return base.rstrip("/") + "/" + path.lstrip("/")


def parse_rate_limit_headers(headers: dict) -> dict:
    """Extract rate-limit metadata from response headers.

    Args:
        headers: Dict-like object of HTTP response headers.

    Returns:
        Dict with keys ``limit``, ``remaining``, and ``reset_at``.
    """
    return {
        "limit": int(headers.get("X-RateLimit-Limit", 0)),
        "remaining": int(headers.get("X-RateLimit-Remaining", 0)),
        "reset_at": headers.get("X-RateLimit-Reset", ""),
    }


def is_retryable_status(status_code: int) -> bool:
    """Return ``True`` if *status_code* warrants an automatic retry.

    Retryable codes are 429 (rate limited) and any 5xx server error.

    Args:
        status_code: HTTP response status integer.

    Returns:
        Boolean.
    """
    return status_code == 429 or status_code >= 500


def format_index_name(namespace: str, version: int) -> str:
    """Format a canonical index name from *namespace* and *version*.

    Args:
        namespace: Short identifier, e.g. ``"products"``.
        version:   Integer schema version.

    Returns:
        String like ``"products_v3"``.
    """
    return f"{namespace.lower()}_v{version}"


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — uses hardcoded token instead of environment variable
# ---------------------------------------------------------------------------

def get_client_headers(extra: Optional[dict] = None) -> dict:
    """Build HTTP headers for requests to the search-indexer API.

    Args:
        extra: Optional additional headers to merge into the result.

    Returns:
        Dict of HTTP headers including ``Authorization`` and ``Content-Type``.

    .. danger::
        This function uses the module-level ``_api_token`` constant, which is
        hardcoded in source.  A correct implementation must read
        ``os.environ["SEARCH_INDEXER_TOKEN"]`` (or equivalent) at call time
        and raise ``KeyError`` / ``ValueError`` when the variable is absent,
        rather than silently falling back to a baked-in value.
    """
    # VULNERABLE: reads hardcoded constant instead of environment variable
    headers = {
        "Authorization": f"Bearer {_api_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if extra:
        headers.update(extra)
    return headers

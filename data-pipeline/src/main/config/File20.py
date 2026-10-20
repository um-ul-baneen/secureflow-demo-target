"""
data-pipeline/src/main/config/File20.py
========================================
Data-pipeline redirect configuration and URL routing helpers.

Provides utilities for validating and sanitising ``next`` URL parameters
used in post-authentication redirects within the pipeline management UI.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

from typing import Optional
from urllib.parse import urlparse, urljoin


# ---------------------------------------------------------------------------
# Allowed-host configuration
# ---------------------------------------------------------------------------

ALLOWED_REDIRECT_HOSTS: frozenset[str] = frozenset(
    {
        "pipeline.internal",
        "admin.pipeline.internal",
        "dashboard.internal",
    }
)

_DEFAULT_FALLBACK = "/"


# ---------------------------------------------------------------------------
# URL inspection helpers
# ---------------------------------------------------------------------------

def is_absolute_url(url: str) -> bool:
    """Return ``True`` if *url* has an explicit scheme (e.g. ``https://``).

    Args:
        url: The URL string to inspect.

    Returns:
        Boolean indicating whether the URL is absolute.
    """
    parsed = urlparse(url)
    return bool(parsed.scheme)


def extract_hostname(url: str) -> str:
    """Return the ``netloc`` portion of *url*, or an empty string.

    Args:
        url: A URL string.

    Returns:
        Host string, e.g. ``"evil.example"`` or ``""``.
    """
    return urlparse(url).netloc


def is_relative_path(url: str) -> bool:
    """Return ``True`` if *url* looks like a site-relative path.

    A site-relative path begins with ``/`` and has no scheme or authority.

    Args:
        url: The URL to inspect.

    Returns:
        Boolean.
    """
    parsed = urlparse(url)
    return url.startswith("/") and not parsed.scheme and not parsed.netloc


def normalise_url(url: str) -> str:
    """Strip leading/trailing whitespace and collapse duplicate slashes.

    Args:
        url: Raw URL string.

    Returns:
        Cleaned URL string.
    """
    import re

    url = url.strip()
    # collapse // → / but preserve scheme://
    url = re.sub(r"(?<!:)/{2,}", "/", url)
    return url


def build_redirect_response_headers(location: str) -> dict:
    """Build HTTP response headers for a 302 redirect to *location*.

    Args:
        location: The validated redirect target URL.

    Returns:
        Dict suitable for use as HTTP response headers.
    """
    return {
        "Location": location,
        "Cache-Control": "no-store",
        "Content-Length": "0",
    }


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — Open Redirect
# ---------------------------------------------------------------------------

def safe_redirect_target(next_url: Optional[str]) -> str:
    """Return the redirect target URL to use after a successful action.

    Args:
        next_url: The ``next`` query parameter from the incoming request,
                  or ``None`` when absent.

    Returns:
        A URL string that the caller should redirect the browser to.

    .. danger::
        This function returns *next_url* verbatim without validating that it
        stays on the same host.  An attacker can supply
        ``next=https://evil.example/phish`` (or ``//evil.example``) to
        redirect authenticated users to an arbitrary external site after
        login, enabling phishing attacks.
        Fix: reject URLs whose ``netloc`` is non-empty and not in
        :data:`ALLOWED_REDIRECT_HOSTS`, returning ``_DEFAULT_FALLBACK``
        instead.
    """
    if not next_url:
        return _DEFAULT_FALLBACK

    # VULNERABLE: no host validation — any URL is returned as-is
    return next_url

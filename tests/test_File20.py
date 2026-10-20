"""
tests/test_File20.py
=====================
Tests for data-pipeline/src/main/config/File20.py

Functional tests verify the redirect helper for allowed inputs.
The exploit test confirms the open-redirect vulnerability; it FAILS on the
vulnerable code and must PASS after a fix.
"""

import pytest

from config.File20 import (
    safe_redirect_target,
    is_absolute_url,
    extract_hostname,
    is_relative_path,
    build_redirect_response_headers,
)


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_none_returns_default():
    """None input should map to the default fallback '/'."""
    assert safe_redirect_target(None) == "/"


def test_empty_string_returns_default():
    """Empty string input should map to the default fallback '/'."""
    assert safe_redirect_target("") == "/"


def test_valid_relative_path_is_preserved():
    """/reports/42 is a safe relative path and must be returned unchanged."""
    assert safe_redirect_target("/reports/42") == "/reports/42"


def test_is_relative_path_detects_correctly():
    """is_relative_path must return True for site-relative paths."""
    assert is_relative_path("/dashboard") is True
    assert is_relative_path("https://example.com/path") is False


# ---------------------------------------------------------------------------
# Exploit tests
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_open_redirect_blocked_for_external_https():
    """https://evil.example must map to '/', not the external URL.

    On VULNERABLE code the input is returned verbatim → assertion fails.
    After the fix, external URLs must be rejected and '/' returned.
    """
    result = safe_redirect_target("https://evil.example/phish")
    assert result == "/", (
        f"Open redirect: external https URL was not blocked, got {result!r}"
    )


@pytest.mark.exploit
def test_open_redirect_blocked_for_protocol_relative():
    """//evil.example and /\\evil.example must map to '/', not an external host.

    Protocol-relative URLs (//host) and backslash variants (/\\host) are
    classic open-redirect bypasses.
    """
    for bad_url in ("//evil.example", "/\\evil.example"):
        result = safe_redirect_target(bad_url)
        assert result == "/", (
            f"Open redirect: {bad_url!r} was not blocked, got {result!r}"
        )

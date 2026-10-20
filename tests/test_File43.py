"""
tests/test_File43.py
=====================
Tests for search-indexer/src/main/service/File43.py

Functional tests verify header construction and helper utilities.
The exploit test confirms the hardcoded token vulnerability: the literal
token value must NOT appear in module source, and get_client_headers must
read the environment (FAILS on vulnerable code, PASSES after fix).
"""

import importlib
import inspect
import os
import pathlib
import pytest

from service.File43 import (
    get_client_headers,
    build_base_url,
    parse_rate_limit_headers,
    is_retryable_status,
    format_index_name,
)


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_get_client_headers_returns_dict():
    """get_client_headers must return a dict."""
    # On vulnerable code this works (uses hardcoded token).
    # After fix it raises KeyError unless env var is set — that's tested separately.
    os.environ.setdefault("SEARCH_INDEXER_TOKEN", "test-env-token")
    result = get_client_headers()
    assert isinstance(result, dict)


def test_build_base_url_joins_path():
    """build_base_url should concatenate base and path correctly."""
    url = build_base_url("/indices/products")
    assert url.startswith("https://")
    assert "indices/products" in url


def test_parse_rate_limit_headers_extracts_values():
    """parse_rate_limit_headers must extract limit, remaining, reset_at."""
    fake_headers = {
        "X-RateLimit-Limit": "1000",
        "X-RateLimit-Remaining": "42",
        "X-RateLimit-Reset": "2024-01-01T00:00:00Z",
    }
    info = parse_rate_limit_headers(fake_headers)
    assert info["limit"] == 1000
    assert info["remaining"] == 42
    assert info["reset_at"] == "2024-01-01T00:00:00Z"


def test_is_retryable_status():
    """429 and 5xx should be retryable; 200 and 404 should not."""
    assert is_retryable_status(429) is True
    assert is_retryable_status(500) is True
    assert is_retryable_status(503) is True
    assert is_retryable_status(200) is False
    assert is_retryable_status(404) is False


# ---------------------------------------------------------------------------
# Exploit tests
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_hardcoded_token_not_in_module_source():
    """The literal hardcoded token string must NOT appear in the module source.

    On VULNERABLE code the string ``demo-token-not-a-real-secret`` is
    present verbatim in the .py file.  After a correct fix the source must
    not contain the hardcoded value.
    """
    import service.File43 as mod

    source_file = pathlib.Path(inspect.getfile(mod))
    source_text = source_file.read_text(encoding="utf-8")
    hardcoded_value = "demo-token-not-a-real-secret"
    assert hardcoded_value not in source_text, (
        "Hardcoded secret still present in module source: "
        f"found {hardcoded_value!r} in {source_file}"
    )


@pytest.mark.exploit
def test_get_client_headers_reads_from_environment(monkeypatch):
    """get_client_headers must read SEARCH_INDEXER_TOKEN from the environment.

    On VULNERABLE code the function ignores the environment and uses a
    hardcoded constant → the returned header still contains the old value.
    After the fix, removing the env var must cause the function to raise
    (KeyError or ValueError), proving it no longer falls back to a hardcoded
    value.
    """
    # Remove the env variable so the function has nothing to fall back on
    monkeypatch.delenv("SEARCH_INDEXER_TOKEN", raising=False)

    # Re-import to pick up any module-level changes (caching)
    import service.File43 as mod
    importlib.reload(mod)

    try:
        headers = mod.get_client_headers()
    except (KeyError, ValueError):
        # Correct: the fixed implementation raised because the env var is absent
        return

    # If it didn't raise, the Authorization header must not contain the hardcoded token
    auth = headers.get("Authorization", "")
    assert "demo-token-not-a-real-secret" not in auth, (
        "get_client_headers returned the hardcoded token even though "
        "SEARCH_INDEXER_TOKEN is not set in the environment"
    )

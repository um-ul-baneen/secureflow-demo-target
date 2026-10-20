"""
tests/test_File16.py
=====================
Tests for analytics-engine/src/main/controller/File16.py

Functional tests use monkeypatching to avoid real network calls.
The exploit test confirms that verify=False is passed to requests.get on the
vulnerable code (FAILS on vulnerable, PASSES after fix).
"""

import pytest
import requests

from controller.File16 import (
    fetch_metrics,
    is_allowed_scheme,
    build_query_params,
    parse_metrics_body,
    default_headers,
    MetricsResult,
)


# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal stub for requests.Response."""

    def __init__(self, status_code: int = 200, text: str = '{"value": 42}'):
        self.status_code = status_code
        self.text = text


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_fetch_metrics_returns_metrics_result(monkeypatch):
    """fetch_metrics must return a MetricsResult on a successful response."""
    monkeypatch.setattr(
        "controller.File16.requests.get",
        lambda *a, **kw: _FakeResponse(200, '{"cpu": 0.5}'),
    )
    result = fetch_metrics("https://metrics.internal/cpu")
    assert isinstance(result, MetricsResult)
    assert result.is_ok()
    assert result.data == {"cpu": 0.5}


def test_fetch_metrics_handles_non_json(monkeypatch):
    """fetch_metrics must not raise when the response body is not JSON."""
    monkeypatch.setattr(
        "controller.File16.requests.get",
        lambda *a, **kw: _FakeResponse(200, "not json"),
    )
    result = fetch_metrics("https://metrics.internal/status")
    assert result.status_code == 200
    assert result.data is None


def test_fetch_metrics_handles_request_exception(monkeypatch):
    """fetch_metrics must catch RequestException and return an error result."""
    def _raise(*a, **kw):
        raise requests.RequestException("connection refused")

    monkeypatch.setattr("controller.File16.requests.get", _raise)
    result = fetch_metrics("https://metrics.internal/cpu")
    assert not result.is_ok()
    assert result.error is not None


def test_is_allowed_scheme():
    """is_allowed_scheme should accept https and reject http/ftp."""
    assert is_allowed_scheme("https://example.com") is True
    assert is_allowed_scheme("http://example.com") is False
    assert is_allowed_scheme("ftp://example.com") is False


# ---------------------------------------------------------------------------
# Exploit test
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_fetch_metrics_uses_tls_verification(monkeypatch):
    """requests.get must NOT be called with verify=False.

    On VULNERABLE code the call site passes ``verify=False`` explicitly.
    After the fix, either ``verify`` is absent (defaults to ``True``) or
    explicitly set to ``True``.
    """
    captured_kwargs = {}

    def _capture(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return _FakeResponse()

    monkeypatch.setattr("controller.File16.requests.get", _capture)
    fetch_metrics("https://metrics.internal/cpu")

    verify_value = captured_kwargs.get("verify", True)  # default is True when absent
    assert verify_value is not False, (
        f"TLS verification is disabled: requests.get was called with verify={verify_value!r}"
    )

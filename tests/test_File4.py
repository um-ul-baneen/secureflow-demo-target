"""
tests/test_File4.py
====================
Tests for data-pipeline/src/main/service/File4.py

Functional tests verify normal serialise/deserialise round-trips.
Exploit tests demonstrate the insecure-deserialization vulnerability; they
FAIL on the vulnerable code and must PASS after a fix.
"""

import builtins
import io
import pickle
import struct
import pytest

from service.File4 import (
    load_job_payload,
    serialize_job,
    payload_checksum,
    validate_version,
    summarise_job,
)


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_round_trip_dict():
    """A plain dict should survive a serialize → load round-trip unchanged."""
    payload = {"job_id": "j-001", "stage": "extract", "retries": 0}
    raw = serialize_job(payload)
    result = load_job_payload(raw)
    assert result == payload


def test_round_trip_list():
    """A list of strings should round-trip correctly."""
    payload = ["step_a", "step_b", "step_c"]
    raw = serialize_job(payload)
    assert load_job_payload(raw) == payload


def test_payload_checksum_is_deterministic():
    """The same bytes must always produce the same SHA-256 digest."""
    data = b"hello world"
    assert payload_checksum(data) == payload_checksum(data)
    assert len(payload_checksum(data)) == 64  # hex SHA-256


def test_validate_version_supported():
    """Known versions should be accepted; unknown versions rejected."""
    assert validate_version("1.0") is True
    assert validate_version("1.1") is True
    assert validate_version("9.9") is False


# ---------------------------------------------------------------------------
# Exploit test
# ---------------------------------------------------------------------------

class _ArbitraryCodeMarker:
    """Picklable object whose __reduce__ calls exec to set a flag on builtins."""

    _MARKER_ATTR = "_pickle_rce_executed"

    def __reduce__(self):
        # exec sets a marker attribute on the builtins module to prove
        # code execution occurred.  Completely harmless — no shell, no I/O.
        code = f"import builtins; setattr(builtins, '{self._MARKER_ATTR}', True)"
        return (exec, (code,))


@pytest.mark.exploit
def test_pickle_rce_payload_raises_or_does_not_execute(monkeypatch):
    """A crafted pickle payload must not execute arbitrary code.

    A secure implementation must either:
      - Raise ``ValueError`` (or similar) when it detects untrusted input, OR
      - Use a safe deserialisation mechanism that does not invoke __reduce__.

    On VULNERABLE code ``pickle.loads`` happily calls ``exec`` and sets
    ``builtins._pickle_rce_executed = True`` → the assertion fails.
    After the fix the loader must raise before reaching exec.
    """
    # Ensure the marker is absent before the test
    if hasattr(builtins, "_pickle_rce_executed"):
        delattr(builtins, "_pickle_rce_executed")

    malicious_bytes = pickle.dumps(_ArbitraryCodeMarker())

    # A safe loader must raise; an unsafe one returns silently and sets the flag.
    try:
        load_job_payload(malicious_bytes)
    except (ValueError, TypeError, pickle.UnpicklingError):
        # Correct: the safe implementation rejected the payload
        pass
    else:
        # If no exception was raised, the exec must NOT have run
        assert not getattr(builtins, "_pickle_rce_executed", False), (
            "Insecure deserialisation: the crafted pickle executed arbitrary code"
        )

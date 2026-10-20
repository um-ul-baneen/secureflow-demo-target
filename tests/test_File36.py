"""
tests/test_File36.py
=====================
Tests for admin-dashboard/src/main/util/File36.py

Functional tests verify normal file reading using tmp_path.
Exploit tests demonstrate path traversal; they FAIL on the vulnerable code
and must PASS after a fix.
"""

import pathlib
import pytest

from util.File36 import (
    read_report,
    list_available_reports,
    has_allowed_extension,
    report_size_ok,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def reports_dir(tmp_path):
    """Create a temporary reports directory with a couple of report files."""
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "report_001.csv").write_text("col1,col2\n1,2\n", encoding="utf-8")
    (reports / "report_002.txt").write_text("Summary text\n", encoding="utf-8")
    return reports


@pytest.fixture()
def secret_dir(tmp_path):
    """Create a directory *outside* the reports dir containing a secret file."""
    secret = tmp_path / "secrets"
    secret.mkdir()
    (secret / "secret.txt").write_text("top-secret-data", encoding="utf-8")
    return secret


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_read_valid_report(reports_dir):
    """read_report should return the file contents for a valid report name."""
    content = read_report("report_001.csv", base_dir=reports_dir)
    assert "col1" in content


def test_list_available_reports(reports_dir):
    """list_available_reports should enumerate files with allowed extensions."""
    names = list_available_reports(reports_dir)
    assert "report_001.csv" in names
    assert "report_002.txt" in names


def test_has_allowed_extension():
    """has_allowed_extension should accept .csv/.txt and reject .exe/.py."""
    assert has_allowed_extension("report.csv") is True
    assert has_allowed_extension("data.txt") is True
    assert has_allowed_extension("malware.exe") is False


def test_report_size_ok_for_small_file(reports_dir):
    """A small report file should satisfy the size check."""
    path = reports_dir / "report_001.csv"
    assert report_size_ok(path) is True


# ---------------------------------------------------------------------------
# Exploit tests
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_path_traversal_is_blocked(reports_dir, secret_dir):
    """../secrets/secret.txt must raise an exception, not return secret content.

    ``reports_dir`` and ``secret_dir`` are siblings inside ``tmp_path``, so a
    single ``../`` is enough to escape the reports directory on all platforms.
    On VULNERABLE code the resolved path exists and is read successfully →
    ``pytest.raises`` fails because no exception was raised.
    After the fix the implementation raises (ValueError or similar).
    """
    # One level up brings us to tmp_path; then into the sibling secrets dir.
    traversal = "../secrets/secret.txt"

    with pytest.raises(Exception) as exc_info:
        read_report(traversal, base_dir=reports_dir)

    # Any exception is acceptable; the secret must not have been returned.
    assert exc_info.type is not None


@pytest.mark.exploit
def test_path_traversal_does_not_leak_secret_content(reports_dir, secret_dir):
    """The secret file content must not be returned by a traversal payload.

    On VULNERABLE code ``../secrets/secret.txt`` resolves successfully and
    returns ``'top-secret-data'`` → the assertion fails.
    After the fix an exception is raised and we return early.
    """
    traversal = "../secrets/secret.txt"
    try:
        content = read_report(traversal, base_dir=reports_dir)
    except Exception:
        # Correct: the fixed implementation raised
        return
    # No exception: content must NOT contain the secret
    assert "top-secret-data" not in content, (
        f"Path traversal leaked secret content: {content!r}"
    )

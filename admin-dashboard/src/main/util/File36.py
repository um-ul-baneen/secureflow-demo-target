"""
admin-dashboard/src/main/util/File36.py
========================================
Admin dashboard report-file reader utility.

Provides helpers for locating, validating, and streaming report files that
are stored on the server's local filesystem.  The base directory is
configurable so that unit tests can substitute a temporary directory.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import os
import pathlib
from typing import Optional


# ---------------------------------------------------------------------------
# Report metadata helpers
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = frozenset({".txt", ".csv", ".json", ".html", ".pdf"})
MAX_REPORT_SIZE_BYTES = 50 * 1024 * 1024  # 50 MiB


def get_default_reports_dir() -> pathlib.Path:
    """Return the default reports directory as configured by the environment.

    Falls back to a ``reports/`` subdirectory relative to the current working
    directory when the ``REPORTS_DIR`` environment variable is not set.

    Returns:
        A :class:`pathlib.Path` pointing at the reports directory.
    """
    env_val = os.environ.get("REPORTS_DIR")
    if env_val:
        return pathlib.Path(env_val)
    return pathlib.Path.cwd() / "reports"


def has_allowed_extension(filename: str) -> bool:
    """Return ``True`` if *filename* carries a permitted extension.

    Args:
        filename: Bare file name (not a full path), e.g. ``"report_42.csv"``.

    Returns:
        Boolean.
    """
    return pathlib.Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def list_available_reports(base_dir: pathlib.Path) -> list[str]:
    """Return a sorted list of report file names found in *base_dir*.

    Only files with an extension from :data:`ALLOWED_EXTENSIONS` are
    included.

    Args:
        base_dir: Directory to scan.

    Returns:
        Sorted list of file name strings.
    """
    if not base_dir.is_dir():
        return []
    return sorted(
        p.name
        for p in base_dir.iterdir()
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS
    )


def report_size_ok(path: pathlib.Path) -> bool:
    """Return ``True`` if the file at *path* is within the size limit.

    Args:
        path: Resolved path to the report file.

    Returns:
        Boolean.
    """
    try:
        return path.stat().st_size <= MAX_REPORT_SIZE_BYTES
    except OSError:
        return False


def read_report_metadata(path: pathlib.Path) -> dict:
    """Return a metadata dict for the report at *path*.

    Args:
        path: Resolved path to the report file.

    Returns:
        Dict with keys ``name``, ``size_bytes``, ``extension``.
    """
    stat = path.stat()
    return {
        "name": path.name,
        "size_bytes": stat.st_size,
        "extension": path.suffix.lower(),
    }


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — Path Traversal
# ---------------------------------------------------------------------------

def read_report(filename: str, base_dir: Optional[pathlib.Path] = None) -> str:
    """Read and return the text content of a report file.

    Args:
        filename: The name (or relative path) of the report file, as
                  supplied by the caller — typically a query parameter.
        base_dir: Optional override for the reports root directory.
                  Defaults to :func:`get_default_reports_dir`.  Passing a
                  :class:`~pathlib.Path` here is required by the test suite
                  so that a ``tmp_path`` fixture can be used.

    Returns:
        File contents as a UTF-8 string.

    Raises:
        FileNotFoundError: When the resolved path does not exist.

    .. danger::
        ``filename`` is joined to ``base_dir`` without checking that the
        result stays inside ``base_dir``.  A caller who supplies
        ``../../etc/passwd`` (or any ``..``-containing value) can read
        arbitrary files on the server, bypassing the intended directory
        restriction.
        Fix: resolve both paths and assert that the file path starts with
        the resolved ``base_dir`` before opening.
    """
    if base_dir is None:
        base_dir = get_default_reports_dir()

    # VULNERABLE: resolves the path (so .. traversal works cross-platform) but
    # does NOT check that the result remains inside base_dir
    target = (base_dir / filename).resolve()
    return target.read_text(encoding="utf-8")

"""
data-pipeline/src/main/service/File4.py
========================================
Data-pipeline job payload serialisation module.

Handles reading and writing opaque job payloads that are exchanged between
pipeline stages.  Payloads are serialised to/from raw bytes for storage in
a message queue or blob store.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import io
import hashlib
import json
import pickle
from typing import Any


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------

SUPPORTED_VERSIONS = ("1.0", "1.1", "1.2")
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MiB hard limit


def validate_version(version: str) -> bool:
    """Return ``True`` if *version* is an officially supported payload version.

    Args:
        version: A semver-style version string such as ``"1.1"``.

    Returns:
        Boolean indicating support status.
    """
    return version in SUPPORTED_VERSIONS


def payload_checksum(data: bytes) -> str:
    """Compute a SHA-256 hex digest of *data*.

    Used to detect accidental corruption in transit.

    Args:
        data: Raw bytes to hash.

    Returns:
        Hex string of the SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def build_envelope(job_id: str, stage: str, payload_bytes: bytes) -> dict:
    """Wrap raw payload bytes in a metadata envelope dict.

    Args:
        job_id: Unique identifier for the pipeline job.
        stage:  Name of the pipeline stage producing the envelope.
        payload_bytes: Already-serialised payload bytes.

    Returns:
        A dict with keys ``job_id``, ``stage``, ``checksum``,
        ``size_bytes``, and ``payload_b64`` (base64-encoded payload).
    """
    import base64

    return {
        "job_id": job_id,
        "stage": stage,
        "checksum": payload_checksum(payload_bytes),
        "size_bytes": len(payload_bytes),
        "payload_b64": base64.b64encode(payload_bytes).decode(),
    }


def summarise_job(job_dict: dict) -> str:
    """Return a one-line human-readable summary of a job dict.

    Args:
        job_dict: A plain Python dict representing a job.

    Returns:
        A formatted string suitable for logging.
    """
    keys = sorted(job_dict.keys())
    return "Job({})".format(", ".join(f"{k}={job_dict[k]!r}" for k in keys))


# ---------------------------------------------------------------------------
# Write path — intentionally uses pickle (matches the vulnerable read path)
# ---------------------------------------------------------------------------

def serialize_job(payload: Any) -> bytes:
    """Serialise *payload* to bytes using :mod:`pickle`.

    This is the writer counterpart to :func:`load_job_payload`.  Both sides
    of the boundary use pickle so that arbitrary Python objects survive a
    round-trip through the queue.

    Args:
        payload: Any picklable Python object representing job state.

    Returns:
        Raw pickle bytes.
    """
    if len(pickle.dumps(payload)) > MAX_PAYLOAD_BYTES:
        raise ValueError(
            f"Serialised payload exceeds maximum size of {MAX_PAYLOAD_BYTES} bytes."
        )
    return pickle.dumps(payload)


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — Insecure deserialisation via pickle.loads
# ---------------------------------------------------------------------------

def load_job_payload(raw: bytes) -> Any:
    """Deserialise a job payload from raw bytes.

    Args:
        raw: Bytes previously produced by :func:`serialize_job` (or any
             other source that speaks the pickle protocol).

    Returns:
        The deserialised Python object.

    .. danger::
        This function calls ``pickle.loads`` on untrusted input without any
        validation.  A crafted byte string can embed a ``__reduce__`` hook
        that executes arbitrary code (e.g. ``exec``, ``os.system``) during
        deserialisation.  Attackers who can supply ``raw`` gain remote code
        execution on the host running this function.
    """
    # VULNERABLE: pickle.loads on untrusted bytes enables arbitrary code execution
    return pickle.loads(raw)  # noqa: S301

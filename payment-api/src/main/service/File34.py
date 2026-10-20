"""
payment-api/src/main/service/File34.py
========================================
Payment API search and lookup service module.

Provides query helpers for retrieving payment records from the payments
SQLite database.  Supports lookup by exact ID, date-range filtering, and
free-text search across merchant and reference fields.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import sqlite3
import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Schema setup
# ---------------------------------------------------------------------------

def create_payments_table(conn: sqlite3.Connection) -> None:
    """Create the ``payments`` table if it does not already exist.

    Args:
        conn: An open SQLite connection.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS payments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT    NOT NULL,
            merchant    TEXT    NOT NULL,
            reference   TEXT    NOT NULL,
            amount_cents INTEGER NOT NULL,
            currency    TEXT    NOT NULL DEFAULT 'USD',
            created     TEXT    NOT NULL
        )
        """
    )
    conn.commit()


def _utc_now() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return datetime.datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def insert_payment(
    conn: sqlite3.Connection,
    user_id: str,
    merchant: str,
    reference: str,
    amount_cents: int,
    currency: str = "USD",
) -> int:
    """Insert a new payment record and return its row id.

    Args:
        conn:         An open SQLite connection.
        user_id:      Identifier of the paying user.
        merchant:     Merchant display name.
        reference:    Transaction reference string.
        amount_cents: Payment amount in the smallest currency unit.
        currency:     ISO 4217 currency code (default: ``"USD"``).

    Returns:
        The ``rowid`` of the newly inserted record.
    """
    cursor = conn.execute(
        """
        INSERT INTO payments (user_id, merchant, reference, amount_cents, currency, created)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, merchant, reference, amount_cents, currency, _utc_now()),
    )
    conn.commit()
    return cursor.lastrowid


def get_payment_by_id(
    conn: sqlite3.Connection,
    payment_id: int,
) -> Optional[dict]:
    """Fetch a single payment row by primary key.

    Args:
        conn:       An open SQLite connection.
        payment_id: Primary key to look up.

    Returns:
        A dict of payment fields, or ``None`` when not found.
    """
    row = conn.execute(
        "SELECT id, user_id, merchant, reference, amount_cents, currency, created "
        "FROM payments WHERE id = ?",
        (payment_id,),
    ).fetchone()
    if row is None:
        return None
    keys = ("id", "user_id", "merchant", "reference", "amount_cents", "currency", "created")
    return dict(zip(keys, row))


def total_by_currency(conn: sqlite3.Connection, currency: str) -> int:
    """Return the sum of ``amount_cents`` for all payments in *currency*.

    Args:
        conn:     An open SQLite connection.
        currency: ISO 4217 code, e.g. ``"USD"``.

    Returns:
        Sum of cents (integer), or 0 when no matching rows exist.
    """
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM payments WHERE currency = ?",
        (currency,),
    ).fetchone()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — SQL Injection via string-concatenated LIKE clause
# ---------------------------------------------------------------------------

def search_payments(conn: sqlite3.Connection, term: str) -> list[dict]:
    """Search payments whose merchant or reference contains *term*.

    Args:
        conn: An open SQLite connection.
        term: Free-text search term supplied by the caller.

    Returns:
        A list of matching payment record dicts.

    .. danger::
        The ``term`` parameter is embedded directly into the SQL LIKE clause
        via string concatenation.  An attacker who controls ``term`` can
        break out of the LIKE pattern and inject arbitrary SQL.  For example,
        ``%' OR 1=1 --`` matches every row, exposing all payment records.
        Fix: use a parameterised query — ``WHERE merchant LIKE ? OR
        reference LIKE ?`` — and pass ``f"%{term}%"`` as the bind value.
    """
    # VULNERABLE: term is concatenated directly into the SQL string
    query = (
        "SELECT id, user_id, merchant, reference, amount_cents, currency, created "
        "FROM payments "
        "WHERE merchant LIKE '%" + term + "%' OR reference LIKE '%" + term + "%'"
    )
    rows = conn.execute(query).fetchall()
    keys = ("id", "user_id", "merchant", "reference", "amount_cents", "currency", "created")
    return [dict(zip(keys, row)) for row in rows]

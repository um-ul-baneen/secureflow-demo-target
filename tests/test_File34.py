"""
tests/test_File34.py
=====================
Tests for payment-api/src/main/service/File34.py

Functional tests verify normal search behaviour with in-memory SQLite.
The exploit test demonstrates the SQL-injection LIKE vulnerability; it FAILS
on the vulnerable code and must PASS after a fix.
"""

import sqlite3
import pytest

from service.File34 import (
    create_payments_table,
    insert_payment,
    get_payment_by_id,
    total_by_currency,
    search_payments,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    """Provide an in-memory SQLite connection with the payments table."""
    c = sqlite3.connect(":memory:")
    create_payments_table(c)
    yield c
    c.close()


@pytest.fixture()
def seeded_conn(conn):
    """Provide a connection pre-loaded with a handful of payment rows."""
    insert_payment(conn, "user_1", "Acme Corp", "REF-001", 5000, "USD")
    insert_payment(conn, "user_2", "Globex Ltd", "REF-002", 12000, "EUR")
    insert_payment(conn, "user_3", "Initech",   "REF-003", 3000, "USD")
    return conn


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_search_by_merchant_term(seeded_conn):
    """Searching for 'Acme' should return only Acme Corp's payment."""
    results = search_payments(seeded_conn, "Acme")
    assert len(results) == 1
    assert results[0]["merchant"] == "Acme Corp"


def test_search_by_reference_term(seeded_conn):
    """Searching for 'REF-002' should return the Globex payment."""
    results = search_payments(seeded_conn, "REF-002")
    assert len(results) == 1
    assert results[0]["reference"] == "REF-002"


def test_get_payment_by_id_returns_correct_row(seeded_conn):
    """get_payment_by_id should return a dict for an existing id."""
    pid = insert_payment(seeded_conn, "user_x", "TestMerch", "REF-X", 100, "GBP")
    row = get_payment_by_id(seeded_conn, pid)
    assert row is not None
    assert row["merchant"] == "TestMerch"


def test_total_by_currency(seeded_conn):
    """total_by_currency should sum amount_cents for the given currency."""
    total = total_by_currency(seeded_conn, "USD")
    assert total == 8000  # 5000 + 3000


# ---------------------------------------------------------------------------
# Exploit test
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_sqli_like_payload_does_not_dump_all_rows(seeded_conn):
    """The payload '%' OR 1=1 --' must NOT return every payment row.

    On VULNERABLE code the concatenated LIKE clause becomes:
        WHERE merchant LIKE '%%' OR 1=1 --%' OR reference LIKE '%%' OR 1=1 --%'
    which matches every row → all 3 seeded payments are returned.

    After the fix (parameterised query), the literal string ``%' OR 1=1 --``
    is treated as a search term rather than SQL; no merchant or reference
    contains that exact string, so 0 rows should be returned.
    """
    sqli_term = "%' OR 1=1 --"
    results = search_payments(seeded_conn, sqli_term)

    assert len(results) < 3, (
        f"SQL injection via LIKE succeeded: got {len(results)} row(s) "
        f"for a non-matching search term"
    )

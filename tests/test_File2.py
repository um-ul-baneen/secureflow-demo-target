"""
tests/test_File2.py
====================
Tests for notification-svc/src/main/service/File2.py

Functional tests verify normal behaviour (2–4 tests).
Exploit tests (marked @pytest.mark.exploit) demonstrate the SQL-injection
vulnerability; they FAIL on the vulnerable code and must PASS after a fix.
"""

import sqlite3
import pytest

from service.File2 import (
    create_notifications_table,
    insert_notification,
    mark_notification_read,
    count_unread,
    get_notifications_for_user,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def conn():
    """Provide an in-memory SQLite connection with the notifications table."""
    c = sqlite3.connect(":memory:")
    create_notifications_table(c)
    yield c
    c.close()


@pytest.fixture()
def seeded_conn(conn):
    """Provide a connection seeded with two users' notifications."""
    insert_notification(conn, "alice", "Your order shipped")
    insert_notification(conn, "alice", "Your invoice is ready")
    insert_notification(conn, "bob", "Password changed")
    return conn


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_insert_and_retrieve_own_notifications(seeded_conn):
    """Alice should see exactly her own 2 notifications."""
    rows = get_notifications_for_user(seeded_conn, "alice")
    assert len(rows) == 2
    assert all(r["username"] == "alice" for r in rows)


def test_notification_keys_present(seeded_conn):
    """Each row dict must contain the expected keys."""
    rows = get_notifications_for_user(seeded_conn, "alice")
    for row in rows:
        assert {"id", "username", "message", "read", "created"} == set(row.keys())


def test_mark_read_updates_flag(seeded_conn):
    """mark_notification_read should flip the read flag for the target row."""
    rows = get_notifications_for_user(seeded_conn, "alice")
    nid = rows[0]["id"]
    mark_notification_read(seeded_conn, nid)
    updated = get_notifications_for_user(seeded_conn, "alice")
    target = next(r for r in updated if r["id"] == nid)
    assert target["read"] is True


def test_count_unread_decrements_after_mark(seeded_conn):
    """count_unread should decrease by 1 after marking one notification read."""
    before = count_unread(seeded_conn, "alice")
    rows = get_notifications_for_user(seeded_conn, "alice")
    mark_notification_read(seeded_conn, rows[0]["id"])
    after = count_unread(seeded_conn, "alice")
    assert after == before - 1


# ---------------------------------------------------------------------------
# Exploit test
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_sqli_payload_does_not_return_other_users_rows(seeded_conn):
    """SQLi payload must NOT return rows belonging to other users.

    The payload ``x' OR '1'='1`` breaks the WHERE clause so that the query
    returns every row in the table.  A secure implementation (parameterised
    query) must return an empty list because no row has username exactly equal
    to the payload string.
    """
    malicious_username = "x' OR '1'='1"
    rows = get_notifications_for_user(seeded_conn, malicious_username)
    # On VULNERABLE code this returns all rows (bob's too) → test FAILS.
    # After the fix, no rows match the literal payload string → list is empty.
    assert rows == [], (
        f"SQL injection succeeded: got {len(rows)} row(s) for a non-existent user"
    )

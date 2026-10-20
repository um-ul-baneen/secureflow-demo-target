"""
notification-svc/src/main/service/File2.py
==========================================
Notification service helper module.

Provides utilities for managing user notifications stored in a SQLite database.
Handles creation, retrieval, and acknowledgement of notification records.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import sqlite3
import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------

def create_notifications_table(conn: sqlite3.Connection) -> None:
    """Create the notifications table if it does not already exist.

    Args:
        conn: An open SQLite connection.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    NOT NULL,
            message   TEXT    NOT NULL,
            read      INTEGER NOT NULL DEFAULT 0,
            created   TEXT    NOT NULL
        )
        """
    )
    conn.commit()


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.datetime.utcnow().isoformat()


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def insert_notification(
    conn: sqlite3.Connection,
    username: str,
    message: str,
) -> int:
    """Insert a new notification row and return its row id.

    Args:
        conn: An open SQLite connection.
        username: The owner of the notification.
        message: Human-readable notification text.

    Returns:
        The ``rowid`` of the newly created record.
    """
    cursor = conn.execute(
        "INSERT INTO notifications (username, message, created) VALUES (?, ?, ?)",
        (username, message, _now_iso()),
    )
    conn.commit()
    return cursor.lastrowid


def mark_notification_read(conn: sqlite3.Connection, notification_id: int) -> None:
    """Mark a single notification as read.

    Args:
        conn: An open SQLite connection.
        notification_id: Primary key of the notification to update.
    """
    conn.execute(
        "UPDATE notifications SET read = 1 WHERE id = ?",
        (notification_id,),
    )
    conn.commit()


def count_unread(conn: sqlite3.Connection, username: str) -> int:
    """Return the number of unread notifications for *username*.

    Args:
        conn: An open SQLite connection.
        username: The user whose unread count is requested.

    Returns:
        Integer count of unread rows.
    """
    row = conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE username = ? AND read = 0",
        (username,),
    ).fetchone()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — SQL Injection via f-string interpolation
# ---------------------------------------------------------------------------

def get_notifications_for_user(
    conn: sqlite3.Connection,
    username: str,
) -> list[dict]:
    """Fetch all notifications belonging to *username*.

    Args:
        conn: An open SQLite connection.
        username: The user whose notifications should be returned.

    Returns:
        A list of dicts with keys ``id``, ``username``, ``message``,
        ``read``, and ``created``.

    .. danger::
        The ``username`` parameter is interpolated directly into the SQL
        query string using an f-string.  A malicious caller can inject
        arbitrary SQL — for example ``x' OR '1'='1`` — to read every row
        in the table regardless of ownership.
    """
    # VULNERABLE: user-supplied input inserted directly into query
    query = f"SELECT id, username, message, read, created FROM notifications WHERE username = '{username}'"
    rows = conn.execute(query).fetchall()
    return [
        {
            "id": r[0],
            "username": r[1],
            "message": r[2],
            "read": bool(r[3]),
            "created": r[4],
        }
        for r in rows
    ]

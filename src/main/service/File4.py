# Auto-generated target module placeholder for src/main/service/File4.py
import sqlite3

def get_notifications_for_user(conn, username):
    """Retrieve notifications for a given username."""
    query = "SELECT * FROM notifications WHERE username = ?"
    return conn.execute(query, (username,)).fetchall()

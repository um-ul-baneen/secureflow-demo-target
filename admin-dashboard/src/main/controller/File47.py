"""
admin-dashboard/src/main/controller/File47.py
==============================================
Admin dashboard greeting and announcement controller.

Generates HTML fragments for the admin portal's welcome banner, user
greeting panel, and system-announcement ticker.  Fragments are assembled
server-side and injected into the dashboard template.

.. warning::
    This file is part of an intentionally vulnerable demo codebase.
    DO NOT deploy in production.
"""

import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Colour / theme helpers
# ---------------------------------------------------------------------------

ROLE_BADGE_COLOURS = {
    "admin": "#c0392b",
    "editor": "#2980b9",
    "viewer": "#27ae60",
    "guest": "#7f8c8d",
}


def role_badge_html(role: str) -> str:
    """Return an HTML ``<span>`` badge for the given *role*.

    Args:
        role: User role string, e.g. ``"admin"`` or ``"editor"``.

    Returns:
        An HTML string containing a coloured badge element.
    """
    colour = ROLE_BADGE_COLOURS.get(role.lower(), "#95a5a6")
    return (
        f'<span style="background:{colour};color:#fff;'
        f'padding:2px 8px;border-radius:4px;">'
        f"{role.upper()}</span>"
    )


def format_last_login(ts: datetime.datetime) -> str:
    """Format a *ts* datetime as a human-friendly last-login string.

    Args:
        ts: UTC datetime of the user's most recent login.

    Returns:
        String such as ``"Last login: 2024-03-15 09:42 UTC"``.
    """
    return "Last login: " + ts.strftime("%Y-%m-%d %H:%M UTC")


def build_announcement_banner(message: str, level: str = "info") -> str:
    """Wrap *message* in an announcement banner ``<div>``.

    Args:
        message: Pre-sanitised announcement text.
        level:   One of ``"info"``, ``"warning"``, or ``"danger"``.

    Returns:
        HTML string for a styled announcement banner.
    """
    css_class = f"alert alert-{level}"
    return f'<div class="{css_class}" role="alert">{message}</div>'


def dashboard_title(section: str) -> str:
    """Return the ``<title>`` tag text for a given dashboard *section*.

    Args:
        section: Short section name, e.g. ``"Users"`` or ``"Audit Log"``.

    Returns:
        A string like ``"Admin Dashboard — Users"``.
    """
    return f"Admin Dashboard \u2014 {section}"


def user_panel_header(display_name: str, role: str) -> str:
    """Build the inner HTML for the user-info panel header.

    Args:
        display_name: The user's sanitised display name.
        role:         The user's role string.

    Returns:
        HTML fragment containing the display name and role badge.
    """
    badge = role_badge_html(role)
    return f"<h3>{display_name} {badge}</h3>"


# ---------------------------------------------------------------------------
# VULNERABLE FUNCTION — Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------

def render_greeting(name: str, role: Optional[str] = None) -> str:
    """Render an HTML greeting fragment for the dashboard welcome banner.

    Args:
        name: The user's display name as supplied by the request.
        role: Optional role string; rendered as a badge when provided.

    Returns:
        An HTML string containing the personalised greeting.

    .. danger::
        ``name`` is interpolated directly into the returned HTML without
        escaping.  An attacker who controls ``name`` (e.g. via a URL
        parameter or a stored value) can inject ``<script>`` tags or other
        HTML that executes in every admin's browser.
        Fix: use ``html.escape(name)`` before interpolation.
    """
    # VULNERABLE: `name` is not HTML-escaped before being inserted into markup
    greeting = f"<div class=\"greeting\"><h2>Welcome, {name}!</h2>"
    if role:
        badge = role_badge_html(role)
        greeting += f"<p>Role: {badge}</p>"
    greeting += "</div>"
    return greeting

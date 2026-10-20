"""
tests/test_File47.py
=====================
Tests for admin-dashboard/src/main/controller/File47.py

Functional tests verify greeting HTML structure and helper functions.
The exploit test confirms the XSS vulnerability; it FAILS on the vulnerable
code and must PASS after a fix.
"""

import html
import pytest

from controller.File47 import (
    render_greeting,
    role_badge_html,
    build_announcement_banner,
    dashboard_title,
    user_panel_header,
)


# ---------------------------------------------------------------------------
# Functional tests
# ---------------------------------------------------------------------------

def test_render_greeting_contains_name():
    """render_greeting must include the user's name in its output."""
    output = render_greeting("Alice")
    assert "Alice" in output


def test_render_greeting_with_role_includes_badge():
    """When a role is provided, the output must contain the badge element."""
    output = render_greeting("Bob", role="admin")
    assert "admin" in output.lower() or "ADMIN" in output


def test_role_badge_html_contains_role():
    """role_badge_html must embed the role name in the returned HTML."""
    badge = role_badge_html("editor")
    assert "EDITOR" in badge


def test_dashboard_title_formats_correctly():
    """dashboard_title should include the section name."""
    title = dashboard_title("Users")
    assert "Users" in title
    assert "Admin Dashboard" in title


# ---------------------------------------------------------------------------
# Exploit test
# ---------------------------------------------------------------------------

@pytest.mark.exploit
def test_render_greeting_escapes_xss_payload():
    """Script tags in the name parameter must be HTML-escaped, not injected.

    On VULNERABLE code the raw ``<script>`` tag is embedded verbatim in the
    returned HTML → the assertion fails.
    After the fix, html.escape is applied and the literal ``<script>`` tag
    must not appear in the output.
    """
    xss_payload = "<script>alert(1)</script>"
    output = render_greeting(xss_payload)

    assert "<script>" not in output, (
        "XSS vulnerability: raw <script> tag found in rendered HTML output"
    )
    # Additionally verify the content is preserved (just encoded)
    assert html.escape(xss_payload) in output or "alert" not in output

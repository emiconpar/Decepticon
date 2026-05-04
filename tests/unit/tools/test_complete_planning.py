"""Unit tests for ``decepticon.tools.interaction.complete_planning``."""

from __future__ import annotations

from decepticon.tools.interaction.complete_planning import _sanitize_engagement_name


def test_sanitize_preserves_valid_slug():
    assert _sanitize_engagement_name("telenor-vdp") == "telenor-vdp"


def test_sanitize_empty_returns_fallback():
    assert _sanitize_engagement_name("") == "unnamed-engagement"


def test_sanitize_whitespace_only_returns_fallback():
    assert _sanitize_engagement_name("   ") == "unnamed-engagement"


def test_sanitize_strips_whitespace():
    assert _sanitize_engagement_name("  my-engagement  ") == "my-engagement"


def test_sanitize_truncates_long_name():
    long_name = "x" * 100
    result = _sanitize_engagement_name(long_name)
    assert len(result) == 64
    assert result == "x" * 64


def test_sanitize_non_string_returns_fallback():
    assert _sanitize_engagement_name(None) == "unnamed-engagement"
    assert _sanitize_engagement_name(123) == "unnamed-engagement"
    assert _sanitize_engagement_name([]) == "unnamed-engagement"


def test_sanitize_preserves_at_boundary():
    """Exactly 64 chars should not be truncated."""
    exact = "a" * 64
    assert _sanitize_engagement_name(exact) == exact
    assert len(_sanitize_engagement_name(exact)) == 64

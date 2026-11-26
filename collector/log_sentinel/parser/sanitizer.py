"""Input sanitization and validation helpers for untrusted log text."""

from __future__ import annotations

import ipaddress
import re

# Match ANSI escape sequences (CSI/OSC) and ASCII control characters
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RUN_RE = re.compile(r"[\r\n\t]+")


def sanitize_text(value: str | None, max_length: int = 512) -> str:
    """Strip ANSI/control characters, flatten newlines, and enforce max length."""
    if not value:
        return ""
    cleaned = _ANSI_ESCAPE_RE.sub("", str(value))
    cleaned = _WHITESPACE_RUN_RE.sub(" ", cleaned)
    cleaned = _CONTROL_CHARS_RE.sub("", cleaned).strip()
    if len(cleaned) > max_length:
        return cleaned[:max_length]
    return cleaned


def sanitize_optional(value: str | None, max_length: int = 128) -> str | None:
    """Sanitize an optional string field, returning None when empty."""
    cleaned = sanitize_text(value, max_length=max_length)
    return cleaned if cleaned else None


def sanitize_username(value: str | None) -> str | None:
    """Sanitize a username field without interpreting HTML/shell content."""
    cleaned = sanitize_optional(value, max_length=128)
    if cleaned in {None, "-", "(unknown)", "unknown"}:
        return None
    return cleaned


def validate_ip(value: str | None) -> str | None:
    """Validate an IPv4 or IPv6 address and return normalized string, or None if invalid."""
    if not value:
        return None
    candidate = sanitize_text(value, max_length=64)
    # Strip optional IPv6 zone ID or brackets if present
    candidate = candidate.strip("[]")
    if "%" in candidate:
        candidate = candidate.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None

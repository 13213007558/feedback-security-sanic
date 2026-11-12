"""Redaction helpers applied to the internal, server-side cause chain.

Redaction only affects what is written to internal logs. Its purpose is to
strip high-entropy secret material (tokens, passwords, keys, connection
strings) from exception messages and structured values before they are
recorded, while keeping the shape of the message so operators can still
diagnose the failure. Nothing produced here is ever returned to clients.
"""

from __future__ import annotations

import re
import typing as t

# Replacement token. It is fixed-width and contains no input-derived data.
REDACTED = "[REDACTED]"

# Ordered (label, pattern) pairs. Patterns are intentionally conservative:
# they target common secret encodings rather than broad free text to avoid
# corrupting ordinary diagnostic messages.
_PATTERNS: t.Tuple[t.Tuple[str, "re.Pattern[str]"], ...] = (
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ),
    (
        "basic_auth",
        re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]+"),
    ),
    (
        "assignment",
        # password=..., api_key="...", token: ..., secret = ...
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|"
            r"access[_-]?key|private[_-]?key|authorization)\b"
            r"(\s*[:=]\s*)"
            r"([\"']?)[^\s\"'&;,]+\3"
        ),
    ),
    (
        "url_credentials",
        # scheme://user:password@host
        re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^\s:@/]+:)[^\s@/]+(@)"),
    ),
    (
        "aws_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"
        ),
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
            r"-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
    (
        "hex_secret",
        # Long hex runs (>=32), e.g. raw API keys / digests.
        re.compile(r"\b[0-9a-fA-F]{32,}\b"),
    ),
)


def redact_text(value: str) -> str:
    """Return ``value`` with known secret patterns replaced.

    The function never raises: if a pattern fails, the input is returned
    unchanged so a redaction bug cannot break the logging path.
    """
    if not isinstance(value, str):
        return value
    try:
        redacted = value

        def _assignment(match: "re.Match[str]") -> str:
            return f"{match.group(1)}{match.group(2)}{REDACTED}"

        def _url(match: "re.Match[str]") -> str:
            return f"{match.group(1)}{REDACTED}{match.group(2)}"

        for label, pattern in _PATTERNS:
            if label == "assignment":
                redacted = pattern.sub(_assignment, redacted)
            elif label == "url_credentials":
                redacted = pattern.sub(_url, redacted)
            else:
                redacted = pattern.sub(REDACTED, redacted)
        return redacted
    except Exception:
        return value


def redact_value(value: t.Any) -> t.Any:
    """Recursively redact strings inside nested containers.

    Mapping keys are preserved; only values are scrubbed. Non-container
    values that are not strings are returned untouched.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, t.Mapping):
        return {
            key: redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        cleaned = [redact_value(item) for item in value]
        return type(value)(cleaned) if not isinstance(value, list) else cleaned
    return value


def safe_exception_message(exception: BaseException) -> str:
    """Return a redacted, type-annotated message for internal logs only."""
    try:
        message = redact_text(str(exception))
    except Exception:
        message = "<unreprable exception>"
    return f"{type(exception).__name__}: {message}"

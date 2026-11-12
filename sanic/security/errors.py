"""Internal exceptions used by the safe-error projection machinery.

These exceptions never carry user data in their messages. They signal
failures of the projection policy itself so that the outermost fallback can
emit a locatable, generic safety response.
"""

from __future__ import annotations


class SafetyPolicyError(Exception):
    """Base class for failures of the sensitive-exception projection policy."""


class ProjectionError(SafetyPolicyError):
    """Raised when building the public projection of an exception fails."""


class RenderingError(SafetyPolicyError):
    """Raised when serializing a safe projection into a response fails."""

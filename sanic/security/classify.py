"""Map arbitrary exceptions to a fixed vocabulary of safe error categories.

The public projection never names the original exception class or message.
Only the coarse-grained category code (and an HTTP status) leaves the
process. The mapping is centralized here so every renderer and every
fallback path projects exceptions through the same vocabulary.
"""

from __future__ import annotations

import enum
import typing as t

from sanic.exceptions import (
    BadRequest,
    ExpectationFailed,
    FileNotFound,
    Forbidden,
    HTTPException,
    InvalidHeader,
    MethodNotAllowed,
    NotFound,
    PayloadTooLarge,
    RangeNotSatisfiable,
    RequestTimeout,
    ServiceUnavailable,
    Unauthorized,
    URITooLong,
)


class ErrorCategory(str, enum.Enum):
    """Coarse, non-revealing categories used in public responses."""

    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    TIMEOUT = "timeout"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNPROCESSABLE = "unprocessable"
    RANGE_NOT_SATISFIABLE = "range_not_satisfiable"
    EXPECTATION_FAILED = "expectation_failed"
    UNAVAILABLE = "unavailable"
    INTERNAL_ERROR = "internal_error"

    @property
    def status(self) -> int:
        return _CATEGORY_STATUS[self]

    @property
    def message(self) -> str:
        return _CATEGORY_MESSAGE[self]


_CATEGORY_STATUS: t.Dict[ErrorCategory, int] = {
    ErrorCategory.BAD_REQUEST: 400,
    ErrorCategory.UNAUTHORIZED: 401,
    ErrorCategory.FORBIDDEN: 403,
    ErrorCategory.NOT_FOUND: 404,
    ErrorCategory.METHOD_NOT_ALLOWED: 405,
    ErrorCategory.TIMEOUT: 408,
    ErrorCategory.PAYLOAD_TOO_LARGE: 413,
    ErrorCategory.UNPROCESSABLE: 422,
    ErrorCategory.RANGE_NOT_SATISFIABLE: 416,
    ErrorCategory.EXPECTATION_FAILED: 417,
    ErrorCategory.UNAVAILABLE: 503,
    ErrorCategory.INTERNAL_ERROR: 500,
}

_CATEGORY_MESSAGE: t.Dict[ErrorCategory, str] = {
    ErrorCategory.BAD_REQUEST: "The request was rejected as invalid.",
    ErrorCategory.UNAUTHORIZED: "Authentication is required.",
    ErrorCategory.FORBIDDEN: "The request is not permitted.",
    ErrorCategory.NOT_FOUND: "The requested resource was not found.",
    ErrorCategory.METHOD_NOT_ALLOWED: "The HTTP method is not supported.",
    ErrorCategory.TIMEOUT: "The request timed out.",
    ErrorCategory.PAYLOAD_TOO_LARGE: "The request payload is too large.",
    ErrorCategory.UNPROCESSABLE: "The request could not be processed.",
    ErrorCategory.RANGE_NOT_SATISFIABLE: (
        "The requested range is not satisfiable."
    ),
    ErrorCategory.EXPECTATION_FAILED: (
        "An expectation for the request was not met."
    ),
    ErrorCategory.UNAVAILABLE: "The service is temporarily unavailable.",
    ErrorCategory.INTERNAL_ERROR: "An internal error occurred.",
}

# Default mapping from framework exception classes to safe categories.
# Only exception *types* are used; no exception text is ever consulted here.
_DEFAULT_CLASSIFICATION: t.Dict[type[BaseException], ErrorCategory] = {
    BadRequest: ErrorCategory.BAD_REQUEST,
    InvalidHeader: ErrorCategory.BAD_REQUEST,
    Unauthorized: ErrorCategory.UNAUTHORIZED,
    Forbidden: ErrorCategory.FORBIDDEN,
    NotFound: ErrorCategory.NOT_FOUND,
    FileNotFound: ErrorCategory.NOT_FOUND,
    MethodNotAllowed: ErrorCategory.METHOD_NOT_ALLOWED,
    RequestTimeout: ErrorCategory.TIMEOUT,
    PayloadTooLarge: ErrorCategory.PAYLOAD_TOO_LARGE,
    URITooLong: ErrorCategory.BAD_REQUEST,
    RangeNotSatisfiable: ErrorCategory.RANGE_NOT_SATISFIABLE,
    ExpectationFailed: ErrorCategory.EXPECTATION_FAILED,
    ServiceUnavailable: ErrorCategory.UNAVAILABLE,
}


class ExceptionClassifier:
    """Resolve exception instances to :class:`ErrorCategory` values.

    Resolution uses the exception's MRO, so subclasses are covered by their
    nearest registered ancestor. Unknown exceptions, and any exception that
    is not a framework :class:`HTTPException`, collapse to
    :attr:`ErrorCategory.INTERNAL_ERROR`. Applications may register
    additional exception types without touching any renderer.

    Args:
        extra: Optional mapping of exception types to categories that takes
            precedence over the built-in framework mapping.
    """

    def __init__(
        self,
        extra: t.Optional[
            t.Mapping[type[BaseException], ErrorCategory]
        ] = None,
    ) -> None:
        self._registry: t.Dict[type[BaseException], ErrorCategory] = dict(
            _DEFAULT_CLASSIFICATION
        )
        if extra:
            for exc_type, category in extra.items():
                self.register(exc_type, category)

    def register(
        self,
        exc_type: type[BaseException],
        category: ErrorCategory,
    ) -> None:
        """Register an exception type under a safe category."""
        if not isinstance(exc_type, type) or not issubclass(
            exc_type, BaseException
        ):
            raise TypeError(
                "Classification keys must be exception classes, got "
                f"{type(exc_type)!r}"
            )
        if not isinstance(category, ErrorCategory):
            raise TypeError(
                "Classification values must be ErrorCategory members"
            )
        self._registry[exc_type] = category

    def classify(self, exception: BaseException) -> ErrorCategory:
        """Return the safe category for ``exception``.

        This method must never raise: classification failures themselves
        represent an internal error and resolve to the internal category.
        """
        try:
            for ancestor in type.mro(type(exception)):
                category = self._registry.get(ancestor)
                if category is not None:
                    return category
            if isinstance(exception, HTTPException):
                return self._classify_http_status(exception)
            return ErrorCategory.INTERNAL_ERROR
        except Exception:
            return ErrorCategory.INTERNAL_ERROR

    @staticmethod
    def _classify_http_status(exception: HTTPException) -> ErrorCategory:
        status = getattr(exception, "status_code", 500)
        for category in ErrorCategory:
            if category.status == status:
                return category
        if 400 <= status < 500:
            return ErrorCategory.BAD_REQUEST
        return ErrorCategory.INTERNAL_ERROR

import logging

from sanic.logging.context import current_request_audit


class VerbosityFilter(logging.Filter):
    """
    Filter log records based on verbosity level.
    """

    verbosity: int = 0

    def filter(self, record: logging.LogRecord) -> bool:
        verbosity = getattr(record, "verbosity", 0)
        return verbosity <= self.verbosity


class RequestAuditFilter(logging.Filter):
    """Stamp every record with the trusted audit fields of the active request.

    The filter is installed on Sanic loggers and therefore runs after any
    ``extra`` mapping was merged into the record. While a request is active it
    unconditionally assigns the trusted values, so caller supplied keys can
    never impersonate the internal correlation key or the external request
    identifier. Outside of a request it sets both keys to ``None`` so that a
    previous request's values cannot leak, and so that forged values cannot be
    passed through a bare ``extra`` mapping.
    """

    FIELDS = ("internal_request_id", "external_request_id")

    def filter(self, record: logging.LogRecord) -> bool:
        audit = current_request_audit()
        if audit is None:
            record.__dict__.update(
                {
                    "internal_request_id": None,
                    "external_request_id": None,
                    "request_correlation_id": "-",
                }
            )
            return True

        record.__dict__.update(
            {
                "internal_request_id": audit.internal_id,
                "external_request_id": audit.external_id,
                "request_correlation_id": audit.internal_id,
            }
        )
        return True


def install_request_audit_filter(logger: logging.Logger) -> None:
    """Attach a single audit filter to a logger.

    Logging configurations may replace a logger's filter list, so the filter
    is re-installed defensively after ``dictConfig`` is applied.
    """

    if not any(
        isinstance(filter_, RequestAuditFilter) for filter_ in logger.filters
    ):
        logger.addFilter(RequestAuditFilter())


def install_handler_audit_filters() -> None:
    """Attach audit filters to handlers already known to logging.

    Logger level filters do not run for records propagated from child loggers,
    and user supplied logging configurations may define their own loggers and
    handlers. Handler level filters do run for every emitted record, so they
    are the authoritative place to overwrite forged ``extra`` values for any
    logger that ends up using these handlers.
    """

    def attach(handler: logging.Handler) -> None:
        if not any(
            isinstance(filter_, RequestAuditFilter)
            for filter_ in handler.filters
        ):
            handler.addFilter(RequestAuditFilter())

    for value in logging.root.manager.loggerDict.values():
        if isinstance(value, logging.Logger):
            for handler in value.handlers:
                attach(handler)
    for handler in logging.root.handlers:
        attach(handler)

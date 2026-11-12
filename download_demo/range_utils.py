from __future__ import annotations

from .models import RangeNotSatisfiable


def parse_range(header: str | None, size: int) -> tuple[int, int]:
    """Parse a single ``bytes=start-end`` range against a fixed snapshot.

    Only one interval is accepted: download tickets serve one file version,
    and multipart ranges would blur byte accounting. Suffix ranges
    (``bytes=-N``) and open-ended ranges (``bytes=N-``) are supported.
    """
    if header is None:
        return 0, size - 1
    if not header.startswith("bytes="):
        raise RangeNotSatisfiable("only byte ranges are supported")
    spec = header[len("bytes=") :].strip()
    if "," in spec:
        raise RangeNotSatisfiable("multiple ranges are not supported")
    if "-" not in spec:
        raise RangeNotSatisfiable("malformed Range header")
    raw_start, raw_end = spec.split("-", 1)
    raw_start, raw_end = raw_start.strip(), raw_end.strip()
    if size <= 0:
        raise RangeNotSatisfiable("file is empty")
    try:
        if raw_start == "":
            suffix = int(raw_end)
            if suffix <= 0:
                raise ValueError
            start = max(0, size - suffix)
            end = size - 1
        else:
            start = int(raw_start)
            end = int(raw_end) if raw_end else size - 1
    except ValueError as exc:
        raise RangeNotSatisfiable("malformed Range header") from exc
    if start < 0 or start >= size:
        raise RangeNotSatisfiable(
            f"range start {start} outside 0..{size - 1}"
        )
    if end < start:
        raise RangeNotSatisfiable("range end precedes start")
    if end >= size:
        end = size - 1
    return start, end

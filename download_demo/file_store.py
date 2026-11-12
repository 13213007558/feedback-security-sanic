from __future__ import annotations

import hashlib
import os
import tempfile

from .models import FileVersion, VersionMismatch


class FileStore:
    """In-memory file registry backed by temporary files on disk.

    Publishing a new version writes a fresh temp file and an immutable
    snapshot. Old snapshots keep pointing at the old bytes, so a ticket
    issued against an old version can never be joined to new content.
    """

    def __init__(self, base_dir: str | None = None) -> None:
        self._dir = base_dir or tempfile.mkdtemp(prefix="download-demo-")
        self._versions: dict[str, dict[int, FileVersion]] = {}

    @property
    def directory(self) -> str:
        return self._dir

    def publish(self, file_id: str, content: bytes) -> FileVersion:
        versions = self._versions.setdefault(file_id, {})
        next_version = max(versions, default=0) + 1
        digest = hashlib.sha256(content).hexdigest()
        fd, path = tempfile.mkstemp(
            prefix=f"{file_id}-v{next_version}-", dir=self._dir
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        snapshot = FileVersion(
            file_id=file_id,
            version=next_version,
            path=path,
            size=len(content),
            sha256=digest,
        )
        versions[next_version] = snapshot
        return snapshot

    def latest(self, file_id: str) -> FileVersion:
        versions = self._versions.get(file_id)
        if not versions:
            raise VersionMismatch(f"unknown file_id: {file_id}")
        return versions[max(versions)]

    def get(self, file_id: str, version: int) -> FileVersion:
        snapshot = self._versions.get(file_id, {}).get(version)
        if snapshot is None:
            raise VersionMismatch(
                f"version {version} of {file_id} is no longer available"
            )
        return snapshot

    def verify_snapshot(self, snapshot: FileVersion) -> None:
        """Re-hash the temp file before streaming; fail closed on drift."""
        if not os.path.isfile(snapshot.path):
            raise VersionMismatch("backing file vanished")
        hasher = hashlib.sha256()
        size = 0
        with open(snapshot.path, "rb") as handle:
            while True:
                block = handle.read(64 * 1024)
                if not block:
                    break
                hasher.update(block)
                size += len(block)
        if size != snapshot.size or hasher.hexdigest() != snapshot.sha256:
            raise VersionMismatch("file content changed after ticket was issued")

    def read_range(
        self, snapshot: FileVersion, start: int, end: int
    ) -> bytes:
        with open(snapshot.path, "rb") as handle:
            handle.seek(start)
            return handle.read(end - start + 1)

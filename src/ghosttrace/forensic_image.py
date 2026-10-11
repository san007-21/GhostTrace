from __future__ import annotations

import hashlib
from pathlib import Path
from typing import NamedTuple


class InspectionError(Exception):
    """Raised when a forensic image cannot be inspected without modifying it."""


class InspectionResult(NamedTuple):
    filename: str
    byte_size: int
    md5: str
    sha256: str


DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


def inspect_forensic_image(
    path: str | Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> InspectionResult:
    """Read a file without modifying it and return its size plus MD5 and SHA-256.

    The file is read in bounded binary chunks so large images never load fully
    into memory. MD5 and SHA-256 are computed in a single pass.

    Raises:
        InspectionError: if the path does not exist, is not a regular file, is
            unreadable, or the chunk size is invalid.
    """
    file_path = Path(path)

    if not file_path.exists():
        raise InspectionError(f"Path does not exist: {path!r}")

    try:
        stat_result = file_path.stat()
    except OSError as exc:
        raise InspectionError(f"Cannot stat path: {path!r}") from exc

    if not file_path.is_file():
        raise InspectionError(f"Path is not a regular file: {path!r}")

    if chunk_size <= 0:
        raise InspectionError(f"Chunk size must be positive: {chunk_size}")

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    try:
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
    except OSError as exc:
        raise InspectionError(f"Cannot read file: {path!r}") from exc

    byte_size = stat_result.st_size

    return InspectionResult(
        filename=file_path.name,
        byte_size=byte_size,
        md5=md5.hexdigest(),
        sha256=sha256.hexdigest(),
    )

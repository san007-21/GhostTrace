from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .forensic_image import InspectionError

MASTER_SECTOR_SIGNATURE = b"HIKVISION@HANGZHOU"
MASTER_SECTOR_SIGNATURE_LEN = len(MASTER_SECTOR_SIGNATURE)
MASTER_SECTOR_RECORD_SIZE = 256
DEFAULT_MAX_SEARCH_BYTES = 50 * 1024 * 1024  # 50 MiB
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Documented little-endian field layout. Offsets are absolute from the start of the
# Master Sector record (which is also the start of the signature). Only these reference
# fields are decoded; nothing else in the record is interpreted.
#
# No undocumented validity rule is inferred from field values. In particular, a zero
# value is returned verbatim and is NOT treated as missing, invalid, or meaningful.
_FIELD_LAYOUT: dict[str, tuple[int, str]] = {
    "hdd_capacity": (0x38, "<Q"),
    "system_logs_offset": (0x50, "<Q"),
    "system_logs_size": (0x58, "<Q"),
    "video_data_offset": (0x68, "<Q"),
    "data_block_size": (0x78, "<Q"),
    "total_data_blocks": (0x80, "<Q"),
    "hikbtree1_offset": (0x88, "<Q"),
    "hikbtree1_size": (0x90, "<Q"),
    "hikbtree2_offset": (0x98, "<Q"),
    "hikbtree2_size": (0xA0, "<Q"),
    "initialization_time": (0xE0, "<I"),
}


class MasterSectorError(Exception):
    """Raised for invalid parameters or unsupported Hikvision Master Sector input."""


class MasterSectorTruncatedError(MasterSectorError):
    """The signature was found, but fewer than 256 record bytes remain in the file.

    Detection and record completeness are deliberately separated: the signature match
    itself is real and is reported through this exception, but GhostTrace refuses to
    decode a partial record rather than guess at the missing bytes.
    """


@dataclass(frozen=True)
class MasterSectorResult:
    """A decoded Hikvision Master Sector record.

    This reports only what was read from the file. It does not assert that the values
    are plausible for any particular device, firmware, or disk: structural validation
    beyond signature presence and record completeness is intentionally out of scope.
    """

    signature_offset: int
    signature: bytes
    hdd_capacity: int
    system_logs_offset: int
    system_logs_size: int
    video_data_offset: int
    data_block_size: int
    total_data_blocks: int
    hikbtree1_offset: int
    hikbtree1_size: int
    hikbtree2_offset: int
    hikbtree2_size: int
    initialization_time: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_offset": self.signature_offset,
            "signature": self.signature.hex(),
            "hdd_capacity": self.hdd_capacity,
            "system_logs_offset": self.system_logs_offset,
            "system_logs_size": self.system_logs_size,
            "video_data_offset": self.video_data_offset,
            "data_block_size": self.data_block_size,
            "total_data_blocks": self.total_data_blocks,
            "hikbtree1_offset": self.hikbtree1_offset,
            "hikbtree1_size": self.hikbtree1_size,
            "hikbtree2_offset": self.hikbtree2_offset,
            "hikbtree2_size": self.hikbtree2_size,
            "initialization_time": self.initialization_time,
        }

    def to_json(self, *, indent: int | None = None, sort_keys: bool = False) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=sort_keys)


def _require_positive_int(value: Any, name: str) -> int:
    """Validate a scan parameter, rejecting booleans even though they subclass int."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise MasterSectorError(f"{name} must be a positive integer, got {type(value).__name__}")
    if value <= 0:
        raise MasterSectorError(f"{name} must be positive, got {value!r}")
    return value


def _search_signature(
    handle: Any,
    file_size: int,
    *,
    max_search_bytes: int,
    chunk_size: int,
) -> int | None:
    """Find the first signature start within the search window, or return None.

    The scan reads bounded slices and advances by ``read_size - (signature_len - 1)``
    bytes, so consecutive slices overlap by one less than the signature length. That
    overlap guarantees any signature whose start lies in the window is fully contained
    in at least one slice, including signatures that straddle a slice boundary.

    ``read_size`` is floored at the signature length so that the step is always at least
    one byte and the loop always makes forward progress, even if the caller supplies a
    ``chunk_size`` smaller than the signature. Any match is fully inside the window
    because slices never read past ``window_end``.
    """
    window_end = min(file_size, max_search_bytes)  # exclusive
    if window_end < MASTER_SECTOR_SIGNATURE_LEN:
        return None

    read_size = max(chunk_size, MASTER_SECTOR_SIGNATURE_LEN)
    step = read_size - (MASTER_SECTOR_SIGNATURE_LEN - 1)  # >= 1

    offset = 0
    while offset + MASTER_SECTOR_SIGNATURE_LEN <= window_end:
        to_read = min(read_size, window_end - offset)
        handle.seek(offset)
        chunk = handle.read(to_read)
        if len(chunk) < MASTER_SECTOR_SIGNATURE_LEN:
            break
        pos = chunk.find(MASTER_SECTOR_SIGNATURE)
        if pos != -1:
            return offset + pos
        offset += step

    return None


def detect_master_sector(
    path: str | Path,
    *,
    max_search_bytes: int = DEFAULT_MAX_SEARCH_BYTES,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> MasterSectorResult | None:
    """Search a regular file for a Hikvision Master Sector and decode it.

    The file is opened read-only and scanned with bounded chunked reads, so a large
    image is never loaded into memory. At most ``max_search_bytes`` bytes are searched
    and exactly ``MASTER_SECTOR_RECORD_SIZE`` record bytes are read for the candidate.

    Scope is deliberately narrow. This detects the exact signature, verifies that the
    full 256-byte record is present, and decodes the documented reference fields. It
    does not parse HIKBTREE structures, extract video, recover deleted files, detect
    anti-forensics, or interpret any other vendor format.

    Args:
        path: A regular file to scan. Must be readable.
        max_search_bytes: Maximum bytes to search from the start of the file.
        chunk_size: Read size used during the signature search. Values smaller than the
            signature length are accepted and clamped internally to keep the scan correct.

    Returns:
        The decoded record, or ``None`` when the signature does not occur within the
        search window. No alternate or guessed format is assumed in that case.

    Raises:
        InspectionError: The path is missing, not a regular file, or unreadable.
        MasterSectorError: A scan parameter is not a positive int (booleans rejected).
        MasterSectorTruncatedError: The signature was found but fewer than 256 record
            bytes remain, so the record is incomplete and is not decoded.
    """
    file_path = Path(path)

    max_search_bytes = _require_positive_int(max_search_bytes, "max_search_bytes")
    chunk_size = _require_positive_int(chunk_size, "chunk_size")

    if not file_path.exists():
        raise InspectionError(f"Path does not exist: {path!r}")

    try:
        stat_result = file_path.stat()
    except OSError as exc:
        raise InspectionError(f"Cannot stat path: {path!r}") from exc

    if not file_path.is_file():
        raise InspectionError(f"Path is not a regular file: {path!r}")

    file_size = stat_result.st_size

    try:
        with file_path.open("rb") as handle:
            signature_offset = _search_signature(
                handle,
                file_size,
                max_search_bytes=max_search_bytes,
                chunk_size=chunk_size,
            )
            if signature_offset is None:
                return None

            handle.seek(signature_offset)
            record_bytes = handle.read(MASTER_SECTOR_RECORD_SIZE)
    except OSError as exc:
        raise InspectionError(f"Cannot read file: {path!r}") from exc

    if len(record_bytes) < MASTER_SECTOR_RECORD_SIZE:
        raise MasterSectorTruncatedError(
            f"Signature found at offset {signature_offset}, but only "
            f"{len(record_bytes)} of {MASTER_SECTOR_RECORD_SIZE} record bytes are available"
        )

    return _decode_record(signature_offset, record_bytes)


def _decode_record(signature_offset: int, record_bytes: bytes) -> MasterSectorResult:
    """Decode the documented little-endian fields from a complete 256-byte record."""
    decoded: dict[str, int] = {}
    for name, (offset, fmt) in _FIELD_LAYOUT.items():
        decoded[name] = struct.unpack_from(fmt, record_bytes, offset)[0]

    return MasterSectorResult(
        signature_offset=signature_offset,
        signature=MASTER_SECTOR_SIGNATURE,
        hdd_capacity=decoded["hdd_capacity"],
        system_logs_offset=decoded["system_logs_offset"],
        system_logs_size=decoded["system_logs_size"],
        video_data_offset=decoded["video_data_offset"],
        data_block_size=decoded["data_block_size"],
        total_data_blocks=decoded["total_data_blocks"],
        hikbtree1_offset=decoded["hikbtree1_offset"],
        hikbtree1_size=decoded["hikbtree1_size"],
        hikbtree2_offset=decoded["hikbtree2_offset"],
        hikbtree2_size=decoded["hikbtree2_size"],
        initialization_time=decoded["initialization_time"],
    )

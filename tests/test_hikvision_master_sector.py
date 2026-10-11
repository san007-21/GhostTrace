from __future__ import annotations

import hashlib
import random
import struct
from pathlib import Path

import pytest

from ghosttrace import InspectionError, inspect_forensic_image
from ghosttrace.hikvision_master_sector import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_SEARCH_BYTES,
    MASTER_SECTOR_RECORD_SIZE,
    MASTER_SECTOR_SIGNATURE,
    MasterSectorError,
    MasterSectorTruncatedError,
    detect_master_sector,
)

# Distinct little-endian test values. Each is chosen so that byte order is observable.
HDD_CAPACITY = 0x0102030405060708
SYSTEM_LOGS_OFFSET = 0x1112131415161718
SYSTEM_LOGS_SIZE = 0x2122232425262728
VIDEO_DATA_OFFSET = 0x3132333435363738
DATA_BLOCK_SIZE = 0x4142434445464748
TOTAL_DATA_BLOCKS = 0x5152535455565758
HIKBTREE1_OFFSET = 0x6162636465666768
HIKBTREE1_SIZE = 0x7172737475767778
HIKBTREE2_OFFSET = 0x8182838485868788
HIKBTREE2_SIZE = 0x9192939495969798
INITIALIZATION_TIME = 0xA1A2A3A4


def _build_record(**overrides: int) -> bytes:
    record = bytearray(MASTER_SECTOR_RECORD_SIZE)
    record[: len(MASTER_SECTOR_SIGNATURE)] = MASTER_SECTOR_SIGNATURE
    fields: dict[str, tuple[int, str, int]] = {
        "hdd_capacity": (0x38, "<Q", HDD_CAPACITY),
        "system_logs_offset": (0x50, "<Q", SYSTEM_LOGS_OFFSET),
        "system_logs_size": (0x58, "<Q", SYSTEM_LOGS_SIZE),
        "video_data_offset": (0x68, "<Q", VIDEO_DATA_OFFSET),
        "data_block_size": (0x78, "<Q", DATA_BLOCK_SIZE),
        "total_data_blocks": (0x80, "<Q", TOTAL_DATA_BLOCKS),
        "hikbtree1_offset": (0x88, "<Q", HIKBTREE1_OFFSET),
        "hikbtree1_size": (0x90, "<Q", HIKBTREE1_SIZE),
        "hikbtree2_offset": (0x98, "<Q", HIKBTREE2_OFFSET),
        "hikbtree2_size": (0xA0, "<Q", HIKBTREE2_SIZE),
        "initialization_time": (0xE0, "<I", INITIALIZATION_TIME),
    }
    for name, (offset, fmt, default) in fields.items():
        value = overrides.get(name, default)
        struct.pack_into(fmt, record, offset, value)
    return bytes(record)


def _write_image(tmp_path: Path, body: bytes, name: str = "image.dd") -> Path:
    target = tmp_path / name
    target.write_bytes(body)
    return target


def test_valid_record_at_offset_zero(tmp_path: Path) -> None:
    target = _write_image(tmp_path, _build_record())
    result = detect_master_sector(target)
    assert result is not None
    assert result.signature_offset == 0
    assert result.signature == MASTER_SECTOR_SIGNATURE
    assert result.hdd_capacity == HDD_CAPACITY
    assert result.initialization_time == INITIALIZATION_TIME


def test_record_at_nonzero_offset(tmp_path: Path) -> None:
    prefix = 0x2000
    target = _write_image(tmp_path, b"\x00" * prefix + _build_record())
    result = detect_master_sector(target)
    assert result is not None
    assert result.signature_offset == prefix
    assert result.hikbtree2_size == HIKBTREE2_SIZE


def test_signature_crossing_chunk_boundary(tmp_path: Path) -> None:
    # chunk_size=64 gives slices [0,64), [47,111), ... A record placed at offset 50
    # starts its 18-byte signature at 50 and ends at 68, straddling the 64-byte slice
    # boundary. The 17-byte overlap must still recover the exact offset.
    prefix = 50
    target = _write_image(tmp_path, b"\x00" * prefix + _build_record())
    result = detect_master_sector(target, chunk_size=64)
    assert result is not None
    assert result.signature_offset == prefix
    assert result.hdd_capacity == HDD_CAPACITY


def test_signature_crossing_chunk_boundary_small_chunk(tmp_path: Path) -> None:
    # A chunk_size smaller than the signature must be clamped internally, not error.
    prefix = 100
    target = _write_image(tmp_path, b"\x00" * prefix + _build_record())
    result = detect_master_sector(target, chunk_size=4)
    assert result is not None
    assert result.signature_offset == prefix


def test_signature_found_but_record_truncated(tmp_path: Path) -> None:
    truncated = MASTER_SECTOR_SIGNATURE + b"\x00\x01\x02\x03"
    target = _write_image(tmp_path, truncated)
    with pytest.raises(MasterSectorTruncatedError):
        detect_master_sector(target)


def test_signature_found_but_record_truncated_mid_record(tmp_path: Path) -> None:
    record = _build_record()
    target = _write_image(tmp_path, record[: MASTER_SECTOR_RECORD_SIZE - 1])
    with pytest.raises(MasterSectorTruncatedError):
        detect_master_sector(target)


def test_no_signature_returns_none(tmp_path: Path) -> None:
    target = _write_image(tmp_path, b"\x00" * 4096)
    assert detect_master_sector(target) is None


def test_no_signature_within_search_window(tmp_path: Path) -> None:
    # The signature is present at offset 100 but the window stops at 50 bytes.
    target = _write_image(tmp_path, b"\x00" * 100 + _build_record())
    assert detect_master_sector(target, max_search_bytes=50) is None
    # Widening the window finds it, proving the earlier None was the window bound.
    result = detect_master_sector(target, max_search_bytes=400)
    assert result is not None
    assert result.signature_offset == 100


def test_little_endian_field_decoding(tmp_path: Path) -> None:
    target = _write_image(tmp_path, _build_record())
    result = detect_master_sector(target)
    assert result is not None
    assert result.hdd_capacity == HDD_CAPACITY
    assert result.system_logs_offset == SYSTEM_LOGS_OFFSET
    assert result.system_logs_size == SYSTEM_LOGS_SIZE
    assert result.video_data_offset == VIDEO_DATA_OFFSET
    assert result.data_block_size == DATA_BLOCK_SIZE
    assert result.total_data_blocks == TOTAL_DATA_BLOCKS
    assert result.hikbtree1_offset == HIKBTREE1_OFFSET
    assert result.hikbtree1_size == HIKBTREE1_SIZE
    assert result.hikbtree2_offset == HIKBTREE2_OFFSET
    assert result.hikbtree2_size == HIKBTREE2_SIZE
    assert result.initialization_time == INITIALIZATION_TIME


def test_zero_fields_are_not_treated_as_invalid(tmp_path: Path) -> None:
    record = _build_record(
        hdd_capacity=0,
        system_logs_offset=0,
        video_data_offset=0,
        initialization_time=0,
    )
    target = _write_image(tmp_path, record)
    result = detect_master_sector(target)
    assert result is not None
    assert result.hdd_capacity == 0
    assert result.system_logs_offset == 0
    assert result.video_data_offset == 0
    assert result.initialization_time == 0


@pytest.mark.parametrize("bad", [True, False, 0, -1, 3.5, "10", None])
def test_invalid_max_search_bytes_rejected(tmp_path: Path, bad: object) -> None:
    target = _write_image(tmp_path, _build_record())
    with pytest.raises(MasterSectorError):
        detect_master_sector(target, max_search_bytes=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [True, False, 0, -8, 2.5, "chunk", None])
def test_invalid_chunk_size_rejected(tmp_path: Path, bad: object) -> None:
    target = _write_image(tmp_path, _build_record())
    with pytest.raises(MasterSectorError):
        detect_master_sector(target, chunk_size=bad)  # type: ignore[arg-type]


def test_parameters_are_validated_before_file_access(tmp_path: Path) -> None:
    # Even for a missing path, invalid parameters raise MasterSectorError first.
    with pytest.raises(MasterSectorError):
        detect_master_sector(tmp_path / "missing.dd", chunk_size=0)


def test_missing_file_raises_inspection_error(tmp_path: Path) -> None:
    with pytest.raises(InspectionError):
        detect_master_sector(tmp_path / "does-not-exist.dd")


def test_directory_raises_inspection_error(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory"
    directory.mkdir()
    with pytest.raises(InspectionError):
        detect_master_sector(directory)


def test_deterministic_repeated_results(tmp_path: Path) -> None:
    target = _write_image(tmp_path, b"\x00" * 0x100 + _build_record())
    first = detect_master_sector(target)
    second = detect_master_sector(target)
    third = detect_master_sector(target, max_search_bytes=10 * 1024 * 1024, chunk_size=512)
    assert first is not None and second is not None and third is not None
    assert first == second == third
    assert first.to_dict() == second.to_dict() == third.to_dict()
    assert first.to_json() == third.to_json()
    assert first.to_json(indent=2, sort_keys=True) == third.to_json(indent=2, sort_keys=True)


def test_default_limits(tmp_path: Path) -> None:
    assert DEFAULT_MAX_SEARCH_BYTES == 50 * 1024 * 1024
    assert DEFAULT_CHUNK_SIZE == 1024 * 1024
    assert MASTER_SECTOR_RECORD_SIZE == 256
    assert MASTER_SECTOR_SIGNATURE == b"HIKVISION@HANGZHOU"


def test_source_file_is_not_mutated(tmp_path: Path) -> None:
    target = _write_image(tmp_path, b"\x00" * 0x80 + _build_record())
    before = target.read_bytes()
    detect_master_sector(target)
    after = target.read_bytes()
    assert before == after
    inspection = inspect_forensic_image(target)
    assert inspection.byte_size == len(before)
    assert inspection.sha256 == hashlib.sha256(before).hexdigest()


# ---------------------------------------------------------------------------
# Feature 004: location, multiplicity, verbatim passthrough, and the
# detection-vs-validation boundary.
#
# None of the tests below authenticate a record. They confirm what the detector
# DOES (find an exact byte signature at a reported offset and decode the bytes
# that follow it) and, just as importantly, what it does NOT establish
# (that the candidate is a genuine, untampered, firmware-consistent Master
# Sector). See the README provenance notes.
# ---------------------------------------------------------------------------


def test_signature_at_documented_0x200_location(tmp_path: Path) -> None:
    # Primary research (Han et al. 2015) states the master-sector AREA begins at
    # offset 0x200. GhostTrace does NOT assume a fixed location -- it scans from
    # offset zero -- so this test only confirms the reported offset is exact when
    # a record happens to sit at the documented 0x200 location.
    prefix = 0x200
    target = _write_image(tmp_path, b"\x00" * prefix + _build_record(), name="at-200.dd")
    result = detect_master_sector(target)
    assert result is not None
    assert result.signature_offset == prefix
    assert result.signature == MASTER_SECTOR_SIGNATURE
    assert result.hdd_capacity == HDD_CAPACITY


def test_signature_at_0x200_crossing_a_small_chunk_boundary(tmp_path: Path) -> None:
    # Same documented location, but with a small chunk so the scan must stitch
    # slices together. The reported offset must still be exactly 0x200.
    prefix = 0x200
    target = _write_image(tmp_path, b"\x00" * prefix + _build_record(), name="at-200-small.dd")
    result = detect_master_sector(target, chunk_size=64)
    assert result is not None
    assert result.signature_offset == prefix


def test_multiple_signature_occurrences_returns_first(tmp_path: Path) -> None:
    # Two complete records at different offsets with distinguishable payloads.
    # Documented behaviour: the FIRST (lowest-offset) occurrence in the window wins.
    first_offset = 0x100
    second_offset = 0x800
    first_record = _build_record(hdd_capacity=0x1111111111111111)
    second_record = _build_record(hdd_capacity=0x2222222222222222)
    body = b"\x00" * first_offset + first_record
    body += b"\x00" * (second_offset - len(body)) + second_record
    target = _write_image(tmp_path, body, name="two-records.dd")

    result = detect_master_sector(target)
    assert result is not None
    assert result.signature_offset == first_offset
    assert result.hdd_capacity == 0x1111111111111111

    # Same answer regardless of scan parameters (determinism of first-wins).
    for chunk in (32, 256, 4096):
        again = detect_master_sector(target, chunk_size=chunk)
        assert again is not None
        assert again.signature_offset == first_offset
        assert again.hdd_capacity == 0x1111111111111111


def test_multiple_occurrences_within_one_chunk(tmp_path: Path) -> None:
    # Two records inside a single 1 KiB slice: first-wins must not be affected by
    # how many occurrences a single slice contains.
    body = _build_record(hdd_capacity=0xAAAA) + (b"\x00" * 64) + _build_record(hdd_capacity=0xBBBB)
    target = _write_image(tmp_path, body, name="adjacent-records.dd")
    result = detect_master_sector(target, chunk_size=1024)
    assert result is not None
    assert result.signature_offset == 0
    assert result.hdd_capacity == 0xAAAA


def test_unusual_field_values_are_returned_verbatim(tmp_path: Path) -> None:
    # Sentinel-like and implausible values must pass through unchanged. GhostTrace
    # deliberately applies NO plausibility heuristics (no capacity alignment checks,
    # no timestamp-range checks, no offset-monotonicity checks). These values echo
    # patterns the reference parser uses elsewhere (0x7FFFFFFF = "not yet full",
    # 0xFFFFFFFFFFFFFFFF = -1 / invalid offset); none of them may cause rejection.
    extreme = {
        "hdd_capacity": 0xFFFFFFFFFFFFFFFF,
        "system_logs_offset": 0xFFFFFFFFFFFFFFFF,
        "system_logs_size": 0,
        "video_data_offset": 0x7FFFFFFFFFFFFFFF,
        "data_block_size": 0,
        "total_data_blocks": 0,
        "hikbtree1_offset": 0xFFFFFFFFFFFFFFFF,
        "hikbtree1_size": 0,
        "hikbtree2_offset": 0,
        "hikbtree2_size": 0xFFFFFFFFFFFFFFFF,
        "initialization_time": 0xFFFFFFFF,
    }
    target = _write_image(tmp_path, _build_record(**extreme), name="extreme.dd")
    result = detect_master_sector(target)
    assert result is not None
    for field, expected in extreme.items():
        assert getattr(result, field) == expected, field


def test_unaligned_capacity_and_zero_block_geometry_pass_through(tmp_path: Path) -> None:
    # A capacity that is not a 512-multiple and a zero data-block size would be
    # "invalid" under many vendor parsers. GhostTrace has no such rule and returns
    # them verbatim.
    record = _build_record(hdd_capacity=12345, data_block_size=0, total_data_blocks=0)
    target = _write_image(tmp_path, record, name="unaligned.dd")
    result = detect_master_sector(target)
    assert result is not None
    assert result.hdd_capacity == 12345
    assert result.data_block_size == 0
    assert result.total_data_blocks == 0


def test_nonstructured_random_file_with_signature_returns_candidate(tmp_path: Path) -> None:
    # A random, non-structured blob that merely CONTAINS the signature plus enough
    # trailing bytes for a full 256-byte record. The detector returns a candidate
    # because detection is a byte-pattern match, not an authenticity check. This test
    # pins that behaviour and demonstrates the false-positive surface: a candidate here
    # is NOT authenticated and NOT structurally validated.
    rng = random.Random(20261011)
    prefix_offset = 0x180
    filler = bytearray(rng.randbytes(prefix_offset))
    # Ensure the random prefix does not itself contain the signature, so the reported
    # offset is unambiguous.
    assert MASTER_SECTOR_SIGNATURE not in bytes(filler)

    body = bytes(filler) + _build_record()
    target = _write_image(tmp_path, body, name="random.dd")
    result = detect_master_sector(target)
    assert result is not None
    assert result.signature_offset == prefix_offset
    assert result.signature == MASTER_SECTOR_SIGNATURE
    # The decoded values are simply the bytes that happened to follow the signature.
    # They carry no evidentiary weight.
    assert result.hdd_capacity == HDD_CAPACITY


def test_candidate_detection_does_not_imply_authenticity(tmp_path: Path) -> None:
    # Explicitly asserts the detection/validation boundary at the API level: a
    # returned candidate proves only that the exact 18-byte signature occurs and that
    # 256 readable bytes follow it. It does not prove the record is genuine.
    target = _write_image(tmp_path, _build_record(hdd_capacity=0), name="unverified.dd")
    result = detect_master_sector(target)
    assert result is not None  # detected...
    # ...yet nothing here establishes authenticity; the API exposes no such claim.
    assert not hasattr(result, "is_valid")
    assert not hasattr(result, "authenticated")
    assert not hasattr(result, "structurally_valid")
    assert result.to_dict().keys() == {
        "signature_offset",
        "signature",
        "hdd_capacity",
        "system_logs_offset",
        "system_logs_size",
        "video_data_offset",
        "data_block_size",
        "total_data_blocks",
        "hikbtree1_offset",
        "hikbtree1_size",
        "hikbtree2_offset",
        "hikbtree2_size",
        "initialization_time",
    }

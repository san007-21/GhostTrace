from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from ghosttrace import InspectionError, InspectionResult, inspect_forensic_image

EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _full_hashes(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    return md5, sha256


def test_inspects_known_content(tmp_path: Path) -> None:
    content = b"GhostTrace forensic fixture v1\n"
    target = tmp_path / "known.bin"
    target.write_bytes(content)

    result = inspect_forensic_image(target)

    expected_md5, expected_sha256 = _full_hashes(target)
    assert result.filename == "known.bin"
    assert result.byte_size == len(content)
    assert result.md5 == expected_md5
    assert result.sha256 == expected_sha256


def test_inspects_empty_file(tmp_path: Path) -> None:
    target = tmp_path / "empty.bin"
    target.write_bytes(b"")

    result = inspect_forensic_image(target)

    assert result.filename == "empty.bin"
    assert result.byte_size == 0
    assert result.md5 == EMPTY_MD5
    assert result.sha256 == EMPTY_SHA256


def test_chunked_read_matches_full_read(tmp_path: Path) -> None:
    content = b"The quick brown fox jumps over the lazy dog.\n" * 4096
    target = tmp_path / "chunked.bin"
    target.write_bytes(content)

    full_result = inspect_forensic_image(target, chunk_size=1024 * 1024)
    tiny_result = inspect_forensic_image(target, chunk_size=17)

    assert tiny_result.byte_size == len(content)
    assert tiny_result.md5 == full_result.md5
    assert tiny_result.sha256 == full_result.sha256
    assert tiny_result.md5 == _full_hashes(target)[0]


def test_missing_file_raises(tmp_path: Path) -> None:
    with pytest.raises(InspectionError):
        inspect_forensic_image(tmp_path / "missing.bin")


def test_invalid_chunk_size_raises() -> None:
    with pytest.raises(InspectionError):
        inspect_forensic_image(__file__, chunk_size=0)
    with pytest.raises(InspectionError):
        inspect_forensic_image(__file__, chunk_size=-1)


def test_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(InspectionError):
        inspect_forensic_image(tmp_path)


def test_source_file_not_mutated(tmp_path: Path) -> None:
    content = b"immutable forensic evidence fixture"
    target = tmp_path / "immutable.bin"
    target.write_bytes(content)
    before = target.read_bytes()

    inspect_forensic_image(target, chunk_size=7)

    after = target.read_bytes()
    assert before == after
    assert after == content
    assert target.stat().st_size == len(content)

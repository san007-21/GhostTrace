from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghosttrace import EvidenceError, EvidenceRecord, create_evidence_record, verify_against_record
from ghosttrace.forensic_image import InspectionError, inspect_forensic_image


def _valid_record(
    *,
    case_id: str = "CASE-1",
    evidence_id: str = "EV-1",
    byte_size: int = 100,
    md5: str = "a" * 32,
    sha256: str = "b" * 64,
    inspection_timestamp: str = "2026-01-01T00:00:00Z",
    verification_status: str = "pending",
    **kwargs: str | None,
) -> EvidenceRecord:
    return EvidenceRecord(
        case_id=case_id,
        evidence_id=evidence_id,
        original_filename="evidence.bin",
        byte_size=byte_size,
        md5=md5,
        sha256=sha256,
        inspection_timestamp=inspection_timestamp,
        verification_status=verification_status,
        **kwargs,
    )


def test_valid_record_has_intended_fields() -> None:
    record = _valid_record()
    assert record.case_id == "CASE-1"
    assert record.evidence_id == "EV-1"
    assert record.original_filename == "evidence.bin"
    assert record.byte_size == 100
    assert record.md5 == "a" * 32
    assert record.sha256 == "b" * 64
    assert record.inspection_timestamp == "2026-01-01T00:00:00Z"
    assert record.verification_status == "pending"


def test_json_round_trip_preserves_all_fields() -> None:
    record = _valid_record(
        acquisition_timestamp="2026-02-02T02:02:02Z",
        acquisition_device="DVR-01",
        acquisition_method="local_export",
        acquired_by="analyst@example.local",
        acquisition_location="lab-bench-3",
        notes="derived from DVR export",
        verification_status="not_verified",
        verification_timestamp="2026-03-03T03:03:03Z",
    )
    text = record.to_json()
    parsed = json.loads(text)
    for optional_null_field in (
        "acquisition_timestamp",
        "acquisition_device",
        "acquisition_method",
        "acquired_by",
        "acquisition_location",
        "notes",
        "verification_timestamp",
    ):
        assert optional_null_field in parsed
    restored = EvidenceRecord.from_json(text)
    assert restored == record


def test_optional_fields_serialized_explicitly_as_null() -> None:
    record = _valid_record(
        verification_status="pending",
        verification_timestamp=None,
        acquisition_timestamp=None,
        acquisition_device=None,
        acquisition_method=None,
        acquired_by=None,
        acquisition_location=None,
        notes=None,
    )
    parsed = json.loads(record.to_json())
    assert parsed["acquisition_timestamp"] is None
    assert parsed["acquisition_device"] is None
    assert parsed["acquisition_method"] is None
    assert parsed["acquired_by"] is None
    assert parsed["acquisition_location"] is None
    assert parsed["notes"] is None
    assert parsed["verification_timestamp"] is None
    assert parsed["verification_status"] == "pending"


def test_timestamps_normalized_and_distinct() -> None:
    record = _valid_record(
        inspection_timestamp="2026-04-04T04:04:04Z",
        acquisition_timestamp="2026-05-05T05:05:05Z",
        verification_timestamp="2026-06-06T06:06:06Z",
        verification_status="not_verified",
    )
    assert record.inspection_timestamp == "2026-04-04T04:04:04Z"
    assert record.acquisition_timestamp == "2026-05-05T05:05:05Z"
    assert record.verification_timestamp == "2026-06-06T06:06:06Z"
    assert record.inspection_timestamp != record.acquisition_timestamp


def test_acquisition_time_not_inferred_from_inspection_time() -> None:
    record = _valid_record(
        inspection_timestamp="2026-07-07T07:07:07Z",
        acquisition_timestamp=None,
        verification_status="pending",
    )
    assert record.acquisition_timestamp is None
    assert record.acquisition_timestamp != record.inspection_timestamp


def test_invalid_md5_rejected() -> None:
    with pytest.raises(EvidenceError):
        _valid_record(md5="short")
    with pytest.raises(EvidenceError):
        _valid_record(md5="G" * 32)
    with pytest.raises(EvidenceError):
        _valid_record(md5="a" * 31)


def test_invalid_sha256_rejected() -> None:
    with pytest.raises(EvidenceError):
        _valid_record(sha256="short")
    with pytest.raises(EvidenceError):
        _valid_record(sha256="G" * 64)
    with pytest.raises(EvidenceError):
        _valid_record(sha256="b" * 63)


def test_invalid_byte_size_rejected() -> None:
    with pytest.raises(EvidenceError):
        _valid_record(byte_size=-1)
    with pytest.raises(EvidenceError):
        _valid_record(byte_size=True)  # type: ignore[arg-type]


def test_missing_required_fields_rejected() -> None:
    for missing_field in (
        "case_id",
        "evidence_id",
        "original_filename",
        "byte_size",
        "md5",
        "sha256",
        "inspection_timestamp",
        "verification_status",
    ):
        base = _valid_record().to_dict()
        del base[missing_field]
        with pytest.raises(EvidenceError, match="Missing required fields"):
            EvidenceRecord.from_dict(base)


def test_invalid_status_rejected() -> None:
    with pytest.raises(EvidenceError, match="not supported"):
        _valid_record(verification_status="approved")


def test_from_dict_rejects_malformed_input() -> None:
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_dict("not a mapping")
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_json("not json")


def test_from_json_rejects_invalid_hashes() -> None:
    payload = _valid_record().to_dict()
    payload["md5"] = "nothex"
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_dict(payload)


def test_from_json_rejects_invalid_timestamps() -> None:
    payload = _valid_record().to_dict()
    payload["inspection_timestamp"] = "not-a-timestamp"
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_dict(payload)

    payload = _valid_record().to_dict()
    payload["verification_timestamp"] = "not-a-timestamp"
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_dict(payload)


def test_from_json_rejects_malformed_optional_timestamps() -> None:
    payload = _valid_record().to_dict()
    payload["acquisition_timestamp"] = "not-a-timestamp"
    with pytest.raises(EvidenceError):
        EvidenceRecord.from_dict(payload)


def test_from_json_rejects_unexpected_fields() -> None:
    payload = _valid_record().to_dict()
    payload["surprise"] = 1
    with pytest.raises(EvidenceError, match="Unexpected fields"):
        EvidenceRecord.from_dict(payload)


def test_frozen_record_cannot_be_reassigned() -> None:
    record = _valid_record()
    with pytest.raises(AttributeError):
        record.case_id = "OTHER"


def test_default_status_is_not_verified_success() -> None:
    record = _valid_record()
    assert record.verification_status in {"pending", "not_verified"}


def test_create_record_uses_default_original_filename() -> None:
    from ghosttrace.forensic_image import InspectionResult

    inspection = InspectionResult(
        filename="camera-export.mp4",
        byte_size=42,
        md5="a" * 32,
        sha256="b" * 64,
    )
    record = create_evidence_record(
        inspection,
        case_id="CASE-1",
        evidence_id="EV-1",
    )
    assert record.original_filename == "camera-export.mp4"
    assert record.byte_size == 42


def test_create_record_uses_explicit_original_filename() -> None:
    from ghosttrace.forensic_image import InspectionResult

    inspection = InspectionResult(
        filename="internal-name.bin",
        byte_size=7,
        md5="a" * 32,
        sha256="b" * 64,
    )
    record = create_evidence_record(
        inspection,
        case_id="CASE-1",
        evidence_id="EV-1",
        original_filename="evidence-referred-by-case.bin",
    )
    assert record.original_filename == "evidence-referred-by-case.bin"


def test_verify_matching_records_shows_verified_file_match(tmp_path: Path) -> None:
    content = b"matching verification fixture"
    target = tmp_path / "match.bin"
    target.write_bytes(content)

    inspection = inspect_forensic_image(target)
    record = create_evidence_record(
        inspection,
        case_id="CASE-1",
        evidence_id="EV-1",
        original_filename="match.bin",
        verification_status="not_verified",
    )
    verified = verify_against_record(record, inspection)
    assert verified.verification_status == "verified_file_match"
    assert verified.verification_timestamp is not None


def test_verify_mismatched_records_shows_verification_failed() -> None:
    record = _valid_record(
        byte_size=99,
        md5="a" * 32,
        sha256="b" * 64,
        verification_status="not_verified",
    )
    from ghosttrace.forensic_image import InspectionResult

    inspection = InspectionResult(
        filename="other.bin",
        byte_size=100,
        md5="c" * 32,
        sha256="d" * 64,
    )
    verified = verify_against_record(record, inspection)
    assert verified.verification_status == "verification_failed"


def test_inspection_error_propagates_not_swallowed(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(InspectionError):
        inspect_forensic_image(missing)


def test_manifest_does_not_fake_record_after_inspection_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(InspectionError):
        inspect_forensic_image(missing)

    with pytest.raises(InspectionError):
        create_evidence_record(
            inspect_forensic_image(missing),  # type: ignore[misc]
            case_id="CASE-1",
            evidence_id="EV-1",
        )

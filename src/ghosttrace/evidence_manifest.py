from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .forensic_image import InspectionError, InspectionResult


class EvidenceError(Exception):
    """Raised for invalid or malformed evidence-manifest data."""

VERIFICATION_STATUSES = frozenset(
    {
        "pending",
        "not_verified",
        "verified_file_match",
        "verification_failed",
    }
)

_KNOWN_FIELDS = frozenset(
    {
        "case_id",
        "evidence_id",
        "original_filename",
        "byte_size",
        "md5",
        "sha256",
        "inspection_timestamp",
        "acquisition_timestamp",
        "acquisition_device",
        "acquisition_method",
        "acquired_by",
        "acquisition_location",
        "notes",
        "verification_status",
        "verification_timestamp",
    }
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _assert_iso8601_utc(value: str, field: str) -> str:
    """Accept only YYYY-MM-DDTHH:MM:SSZ or a timezone-aware ISO 8601 timestamp and
    normalize it to YYYY-MM-DDTHH:MM:SSZ. Unknown or malformed timestamps are
    stored as None, never as the inspection time.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string or null, got {type(value).__name__}")
    normalized = _normalize_iso8601_utc_candidate(value)
    if normalized is None:
        raise ValueError(f"{field} is not a recognized ISO 8601 timestamp: {value!r}")
    return normalized


def _assert_optional_iso8601_utc(value: str | None, field: str) -> str | None:
    """For optional timestamp fields: None stays None, a valid timestamp is
    normalized, and a supplied but malformed timestamp is rejected with
    EvidenceError so malformed metadata is not silently converted to unknown.
    """
    if value is None:
        return None
    try:
        return _assert_iso8601_utc(value, field)
    except ValueError as exc:
        raise EvidenceError(str(exc)) from exc


def _normalize_iso8601_utc_candidate(value: str) -> str | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None
    if parsed.tzinfo is None:
        return None
    utc = parsed.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def _assert_hex(value: str, field: str, expected_length: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if len(value) != expected_length or not all(c in "0123456789abcdef" for c in value):
        raise EvidenceError(f"{field} must be {expected_length} lowercase hexadecimal characters")
    return value


@dataclass(frozen=True)
class EvidenceRecord:
    case_id: str
    evidence_id: str
    original_filename: str
    byte_size: int
    md5: str
    sha256: str
    inspection_timestamp: str
    acquisition_timestamp: str | None = None
    acquisition_device: str | None = None
    acquisition_method: str | None = None
    acquired_by: str | None = None
    acquisition_location: str | None = None
    notes: str | None = None
    verification_status: str = "pending"
    verification_timestamp: str | None = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.case_id, str) or not self.case_id:
            raise EvidenceError("case_id must be a non-empty string")
        if not isinstance(self.evidence_id, str) or not self.evidence_id:
            raise EvidenceError("evidence_id must be a non-empty string")
        if not isinstance(self.original_filename, str) or not self.original_filename:
            raise EvidenceError("original_filename must be a non-empty string")

        if isinstance(self.byte_size, bool) or not isinstance(self.byte_size, int):
            raise EvidenceError("byte_size must be an integer")
        if self.byte_size < 0:
            raise EvidenceError("byte_size must be non-negative")

        _assert_hex(self.md5, "md5", 32)
        _assert_hex(self.sha256, "sha256", 64)

        if not isinstance(self.inspection_timestamp, str):
            raise EvidenceError("inspection_timestamp must be a string")
        inspection_normalized = _normalize_iso8601_utc_candidate(self.inspection_timestamp)
        if inspection_normalized is None:
            raise EvidenceError("inspection_timestamp must be a valid ISO 8601 UTC timestamp")

        if not isinstance(self.verification_status, str):
            raise EvidenceError("verification_status must be a string")
        if self.verification_status not in VERIFICATION_STATUSES:
            raise EvidenceError(f"verification_status is not supported: {self.verification_status!r}")

        if self.verification_timestamp is not None:
            if not isinstance(self.verification_timestamp, str):
                raise EvidenceError("verification_timestamp must be a string or null")
            normalized = _normalize_iso8601_utc_candidate(self.verification_timestamp)
            if normalized is None:
                raise EvidenceError("verification_timestamp must be a valid ISO 8601 UTC timestamp")

        for optional_str_field in (
            "acquisition_timestamp",
            "acquisition_device",
            "acquisition_method",
            "acquired_by",
            "acquisition_location",
            "notes",
        ):
            value = getattr(self, optional_str_field)
            if value is not None and not isinstance(value, str):
                raise EvidenceError(f"{optional_str_field} must be a string or null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "original_filename": self.original_filename,
            "byte_size": self.byte_size,
            "md5": self.md5,
            "sha256": self.sha256,
            "inspection_timestamp": self.inspection_timestamp,
            "acquisition_timestamp": self.acquisition_timestamp,
            "acquisition_device": self.acquisition_device,
            "acquisition_method": self.acquisition_method,
            "acquired_by": self.acquired_by,
            "acquisition_location": self.acquisition_location,
            "notes": self.notes,
            "verification_status": self.verification_status,
            "verification_timestamp": self.verification_timestamp,
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Any) -> EvidenceRecord:
        if not isinstance(data, dict):
            raise EvidenceError("EvidenceRecord data must be a mapping")

        required: list[str] = [
            "case_id",
            "evidence_id",
            "original_filename",
            "byte_size",
            "md5",
            "sha256",
            "inspection_timestamp",
            "verification_status",
        ]
        missing = [key for key in required if key not in data]
        if missing:
            raise EvidenceError(f"Missing required fields: {missing}")

        for key, value in data.items():
            if not isinstance(key, str):
                raise EvidenceError("EvidenceRecord keys must be strings")

        try:
            inspection_timestamp = _assert_iso8601_utc(data["inspection_timestamp"], "inspection_timestamp")
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc
        if inspection_timestamp is None:
            raise EvidenceError("inspection_timestamp is required")

        try:
            verification_timestamp = _assert_iso8601_utc(
                data.get("verification_timestamp"), "verification_timestamp"
            )
        except ValueError as exc:
            raise EvidenceError(str(exc)) from exc

        byte_size = data["byte_size"]
        if isinstance(byte_size, bool) or not isinstance(byte_size, int):
            raise EvidenceError("byte_size must be an integer")
        if byte_size < 0:
            raise EvidenceError("byte_size must be non-negative")

        unexpected = sorted(key for key in data if key not in _KNOWN_FIELDS)
        if unexpected:
            raise EvidenceError(f"Unexpected fields: {unexpected}")

        return cls(
            case_id=data["case_id"],
            evidence_id=data["evidence_id"],
            original_filename=data["original_filename"],
            byte_size=byte_size,
            md5=_assert_hex(data["md5"], "md5", 32),
            sha256=_assert_hex(data["sha256"], "sha256", 64),
            inspection_timestamp=inspection_timestamp,
            acquisition_timestamp=_assert_optional_iso8601_utc(
                data.get("acquisition_timestamp"), "acquisition_timestamp"
            ),
            acquisition_device=data.get("acquisition_device"),
            acquisition_method=data.get("acquisition_method"),
            acquired_by=data.get("acquired_by"),
            acquisition_location=data.get("acquisition_location"),
            notes=data.get("notes"),
            verification_status=data["verification_status"],
            verification_timestamp=verification_timestamp,
        )

    @classmethod
    def from_json(cls, json_text: str) -> EvidenceRecord:
        try:
            data = json.loads(json_text)
        except json.JSONDecodeError as exc:
            raise EvidenceError("EvidenceRecord JSON is malformed") from exc
        return cls.from_dict(data)


def create_evidence_record(
    inspection_result: InspectionResult,
    *,
    case_id: str,
    evidence_id: str,
    original_filename: str | None = None,
    inspection_timestamp: str | None = None,
    acquisition_timestamp: str | None = None,
    acquisition_device: str | None = None,
    acquisition_method: str | None = None,
    acquired_by: str | None = None,
    acquisition_location: str | None = None,
    notes: str | None = None,
    verification_status: str = "pending",
    verification_timestamp: str | None = None,
) -> EvidenceRecord:
    if original_filename is None:
        original_filename = inspection_result.filename
    if inspection_timestamp is None:
        inspection_timestamp = _utc_now_iso()

    return EvidenceRecord(
        case_id=case_id,
        evidence_id=evidence_id,
        original_filename=original_filename,
        byte_size=inspection_result.byte_size,
        md5=inspection_result.md5,
        sha256=inspection_result.sha256,
        inspection_timestamp=inspection_timestamp,
        acquisition_timestamp=acquisition_timestamp,
        acquisition_device=acquisition_device,
        acquisition_method=acquisition_method,
        acquired_by=acquired_by,
        acquisition_location=acquisition_location,
        notes=notes,
        verification_status=verification_status,
        verification_timestamp=verification_timestamp,
    )


def verify_against_record(record: EvidenceRecord, inspection_result: InspectionResult) -> EvidenceRecord:
    if (
        inspection_result.byte_size == record.byte_size
        and inspection_result.md5 == record.md5
        and inspection_result.sha256 == record.sha256
    ):
        status = "verified_file_match"
    else:
        status = "verification_failed"

    return EvidenceRecord(
        case_id=record.case_id,
        evidence_id=record.evidence_id,
        original_filename=record.original_filename,
        byte_size=inspection_result.byte_size,
        md5=inspection_result.md5,
        sha256=inspection_result.sha256,
        inspection_timestamp=_utc_now_iso(),
        acquisition_timestamp=record.acquisition_timestamp,
        acquisition_device=record.acquisition_device,
        acquisition_method=record.acquisition_method,
        acquired_by=record.acquired_by,
        acquisition_location=record.acquisition_location,
        notes=record.notes,
        verification_status=status,
        verification_timestamp=_utc_now_iso(),
    )

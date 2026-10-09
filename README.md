# GhostTrace

Multi-vendor DVR/NVR forensic analysis for evidence acquisition, video recovery, integrity verification, and reporting.

## Forensic image inspector

The inspector reads an image file without modifying it and reports:

* Filename
* Byte size
* MD5 hash
* SHA-256 hash

MD5 is provided for legacy compatibility; SHA-256 is the stronger integrity check.
Hashes do **not** establish evidence authenticity or chain of custody.

### Setup

```bash
python3 -m pip install -e ".[dev]"
```

### Run tests

```bash
python3 -m pytest -q
```

### Usage

```python
from ghosttrace import inspect_forensic_image

result = inspect_forensic_image("evidence.bin")
print(result.filename)
print(result.byte_size)
print(result.md5)
print(result.sha256)
```

### Independent verification with Linux utilities

For any file used with the inspector, the same values can be verified with standard
Linux hashing tools:

```bash
md5sum evidence.bin
sha256sum evidence.bin
stat -c '%s' evidence.bin
```
The reported byte size, MD5, and SHA-256 should match the inspector output for the
same file.

## Evidence manifest

The manifest records a read-only inspection in a structured evidence record:

* Case ID and evidence ID
* Original filename
* Byte size, MD5, and SHA-256 from the inspector
* Inspection timestamp in UTC ISO 8601
* Optional acquisition metadata when known
* Verification status

```python
from ghosttrace import (
    create_evidence_record,
    inspect_forensic_image,
    verify_against_record,
)

inspection = inspect_forensic_image("evidence.bin")
record = create_evidence_record(
    inspection,
    case_id="CASE-1",
    evidence_id="EV-1",
    acquired_by="analyst@example.local",
)
print(record.to_json(indent=2))

re_inspection = inspect_forensic_image("evidence.bin")
verified = verify_against_record(record, re_inspection)
print(verified.verification_status)
```

Important limitations:

* The inspection timestamp is when GhostTrace inspected the file, not when it was
  acquired. If acquisition time is unknown, it remains unknown.
* Unknown optional fields are stored as JSON `null`, not guessed or inferred.
* A hash match means the current file bytes match the recorded bytes. It does not
  prove authenticity, authorship, acquisition time, or chain of custody.
* MD5 is included for legacy compatibility only.
* JSON manifests are not tamper-evident.
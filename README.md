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

## Hikvision Master Sector detection

This feature performs one narrow job: it scans a regular file, read-only and in bounded
chunks, for the exact reference signature `HIKVISION@HANGZHOU`, reports the absolute byte
offset of its first occurrence within the search window (default 50 MiB), and — when the
full 256-byte record is present — decodes a small set of documented little-endian fields.

```python
from ghosttrace import detect_master_sector

result = detect_master_sector("evidence.dd")
if result is not None:
    print(result.signature_offset)
    print(result.hdd_capacity)
    print(result.initialization_time)
```

What it does **not** do:

* It does not parse HIKBTREE structures, extract video, recover deleted files, detect
  anti-forensics, read E01 images, or support any other vendor format.
* It applies no validity rules beyond two checks: the exact signature is present, and the
  full 256-byte record is readable. A field value of zero is reported as zero and is never
  interpreted as "missing", "disabled", or "invalid".
* If the signature occurs but fewer than 256 record bytes remain, GhostTrace raises
  `MasterSectorTruncatedError` rather than decode a partial record.
* If no signature occurs within the search window, it returns `None`; it does not guess at
  alternate on-disk formats.

The tests for this feature use synthetic fixtures constructed in the test suite. Passing
synthetic tests **does not** establish compatibility with any real DVR or NVR firmware,
disk layout, or evidence image. Field offsets were transcribed from a reference parser and
have not been validated against real device output.
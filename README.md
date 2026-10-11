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

### Detection is not validation or authentication

`detect_master_sector` answers exactly one question: *does the exact 18-byte signature
`HIKVISION@HANGZHOU` occur within the search window, and are the 256 bytes that follow it
readable?* A returned candidate proves only that. It does **not** prove the record is
authentic, untampered, or consistent with any device's configuration.

Concretely:

* **A candidate can be a false positive.** Any file that happens to contain the signature
  plus 256 readable bytes — a random blob, an unrelated image, planted bytes — yields a
  candidate. The test suite includes such a case deliberately to document this surface.
* **First occurrence wins.** If the signature appears more than once in the window, the
  lowest-offset occurrence is reported. GhostTrace does not arbitrate between duplicates
  and does not check the documented backup copy.
* **No plausibility heuristics.** Field values are returned verbatim. Values that many
  vendor parsers would reject — a capacity that is not a sector multiple, a zero block
  size, sentinel timestamps such as `0x7FFFFFFF`, or `0xFFFFFFFFFFFFFFFF` in an offset —
  are reported unchanged. GhostTrace infers no undocumented validity rules from field
  values, including zeros.
* **Real-image compatibility is unverified.** No authentic Hikvision image with
  independently known expected values has been run against this detector. Treat every
  result as a candidate for manual confirmation, not as an authenticated finding.

### Provenance of the format constants

Not every constant in this feature rests on the same quality of evidence:

* **Primary-source supported** — reported by the 2015 research paper *Analysis of the
  HIKVISION DVR File System* (Han, Jeong & Lee, Springer LNCS 157): the ASCII signature
  `HIKVISION@HANGZHOU`, the 256-byte master-sector size, the documented master-sector
  area start at offset `0x200`, and little-endian field encoding. (These were verified via
  indexed excerpts of the paper; the full text was not retrieved during development.)
* **Reference implementation only** — the eleven per-field offsets and widths
  (`0x38`, `0x50`, `0x58`, `0x68`, `0x78`, `0x80`, `0x88`, `0x90`, `0x98`, `0xA0`, `0xE0`)
  come solely from the community reference parser, whose own comments describe them as
  "based on empirical analysis." They have **not** been independently confirmed against
  the paper or against real device output.

GhostTrace scans from offset `0` rather than seeking to `0x200`. That is a deliberate
choice: whether the documented `0x200` is measured from the start of the disk image or
from the start of a partition has **not** been established (see the offset-semantics
section below), so a fixed `0x200` read could miss the record on some layouts, while a
whole-window scan finds it wherever it lands. The trade-off is a wider false-positive
surface, described above.

### Offset fields are raw values, not absolute file offsets

Several decoded fields *look* like file offsets — `system_logs_offset`, `video_data_offset`,
`hikbtree1_offset`, and `hikbtree2_offset` — and a reader could reasonably assume they can
be used directly with `seek()` on the image. They cannot, and GhostTrace does not treat
them that way.

What GhostTrace actually does (confirmed against the source, not just intended):

* Each field is decoded verbatim from its fixed position in the 256-byte record with
  `struct.unpack_from`. The bytes at, say, record offset `0x50` become the integer
  `system_logs_offset`, unchanged.
* GhostTrace performs **no rebasing**. It does not add a partition base, a partition
  offset, or any other value to these numbers, and it does not otherwise reinterpret
  them. Whatever integer the record stores is what you get.
* Consequently these values are **not** known to be absolute offsets into the image file.
  Their coordinate system — partition-relative, disk-relative, or something else — has
  **not** been independently verified against authentic device evidence.

Only one offset in the result is a true absolute file offset: `signature_offset`, which is
where GhostTrace actually found the signature while scanning the file.

The community reference parser rebases these same pointers before using them: it detects a
partition offset from the MBR and adds it to the stored values before reading from them.
That is evidence about how one implementation interprets the format; it is **not**
independent proof of the format's semantics. A second implementation agreeing with the
first does not constitute device-verified ground truth, and GhostTrace has not confirmed
the reference parser's interpretation against a real image.

Practical guidance: treat these four fields as opaque metadata reported for completeness.
Do not use them to locate data in the image until their coordinate system has been
verified against an authentic disk with independently known expected values. When you do
need an absolute location you can rely on today, use `signature_offset`.
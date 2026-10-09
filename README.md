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
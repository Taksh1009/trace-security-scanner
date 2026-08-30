# TRACE — Dependency Manifest

TRACE's core scanning engine uses **only the Python standard library**.
No third-party scanning framework, HTTP client, or crypto library is
required to run a scan.

## Standard library modules used

| Module | Used for |
|---|---|
| `socket` | DNS resolution, TCP connect checks, raw TLS socket setup |
| `ssl` | TLS handshake and certificate inspection |
| `http.client` | HTTP/HTTPS GET requests |
| `urllib.parse` | Parsing target input and redirect URLs |
| `datetime` | Certificate expiry calculations |
| `time` | Stage timing |
| `dataclasses` | Structured parsed-target representation |
| `contextlib` | Timing context manager |

## Development-only dependency

| Package | Used for |
|---|---|
| `pytest` | Running the automated test suite (`tests/`) |

Install it with:

```bash
pip install pytest
```

`pytest` is **not** required to run TRACE itself — only to run the test
suite during development.

## Why this matters

Being able to say *"TRACE's core analysis uses Python's standard
library rather than relying on a large third-party scanning
framework"* is a meaningful technical point: it means the tool has a
minimal attack surface, no supply-chain dependencies to audit, and
will keep working as long as a plain Python 3 interpreter is available.

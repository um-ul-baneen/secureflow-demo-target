# secureflow-demo-target

> ⚠️ **THIS REPOSITORY IS INTENTIONALLY VULNERABLE — FOR DEMO PURPOSES ONLY** ⚠️
>
> Do **not** deploy any code from this repository in a production environment.
> Every vulnerability present here is deliberate and serves as a target for
> automated AI-driven remediation tooling.

## Purpose

This repository acts as a synthetic "customer" codebase used to demonstrate an
AI security-remediation pipeline. The files mirror **8 records** of a synthetic
vulnerability scan dataset, one vulnerability per module:

| # | File | Vulnerability |
|---|------|---------------|
| 1 | `notification-svc/src/main/service/File2.py` | SQL Injection (f-string query) |
| 2 | `data-pipeline/src/main/service/File4.py` | Insecure Deserialization (pickle) |
| 3 | `analytics-engine/src/main/controller/File16.py` | Insecure TLS (`verify=False`) |
| 4 | `search-indexer/src/main/service/File43.py` | Hardcoded Secret (API token) |
| 5 | `admin-dashboard/src/main/controller/File47.py` | Cross-Site Scripting (XSS) |
| 6 | `data-pipeline/src/main/config/File20.py` | Open Redirect |
| 7 | `admin-dashboard/src/main/util/File36.py` | Path Traversal |
| 8 | `payment-api/src/main/service/File34.py` | SQL Injection (LIKE clause) |

## Running Tests

```bash
pip install -r requirements.txt

# Functional tests only (all should pass on vulnerable code)
pytest -q -m "not exploit"

# Exploit tests (all should FAIL on vulnerable code, pass after a fix)
pytest -q -m exploit
```

## Disclaimer

All secrets, tokens, credentials, and data in this repository are **synthetic
and non-functional**. They exist solely to demonstrate vulnerability patterns.

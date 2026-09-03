# F-005: FastAPI `app.version` hardcoded to "3.2.0" while pyproject is "3.2.1"

| Field | Value |
|---|---|
| Severity | Low |
| CWE | CWE-1104 (Use of Unmaintained Third Party Components) — operational drift |
| CVSS-like | 2.7 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| Location | `server/src/zaqorincore_server/main.py:130` |
| Status | Open |

## Description

`create_app()` declares `FastAPI(title="ZaqorinCore Server", version="3.2.0", ...)` while
`pyproject.toml` declares `version = "3.2.1"`. The docstring of `version.py` claims:

> ``version`` is read from ``app.version`` so it stays in sync with the FastAPI constructor in ``main.create_app`` — bump it there and this endpoint follows.

That contract is broken. `/api/v1/version` and `/api/v1/healthcheck` will return `"3.2.0"`
even though `pyproject.toml` is `"3.2.1"`.

## Impact

* **Reconnaissance** — a fingerprinting attacker compares the public version against known
  CVE databases and gets a stale (older) version number. For v3.2.1 this means the attacker
  thinks they are dealing with v3.2.0, which has the 4 critical/high vulns from Phase 1
  (F1-F4) still unpatched. Wrong-version mismatch can also feed false positives into a
  defender's own vulnerability dashboard.
* **Operationally misleading** — operators relying on `git describe` to reconcile a deployed
  build with the source tag will silently mis-tag their deployments.

## POC sketch

```
$ curl -s http://target/api/v1/version | jq
{
  "version": "3.2.0",   # pyproject says 3.2.1
  "git_sha": "57e3af4",
  "git_sha_full": "57e3af4..."
}
```

## Remediation sketch

Replace the literal in `main.py`:

```python
app = FastAPI(
    title="ZaqorinCore Server",
    version="3.2.1",
    ...
)
```

Or read from `pyproject.toml` / `importlib.metadata` so the value cannot drift again.
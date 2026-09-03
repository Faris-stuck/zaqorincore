# F-014: `requests` and other HTTP clients — verify minimum versions are pinned against known-bad

| Field | Value |
|---|---|
| Severity | Low |
| CWE | CWE-1104 (Use of Unmaintained Third Party Components) |
| CVSS-like | 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| Location | `server/pyproject.toml:32-58`, `agent/go.mod` |
| Status | Verified — no known-bad pins in v3.2.1 |

## Description

Reviewed the dependency list for known-bad minimum versions:

* `requests<2.20` — N/A. Not a direct dep; `httpx>=0.27` is used instead. httpx 0.27+
  has no known critical CVEs at the time of writing.
* `pyyaml<5.1` — N/A. Not a direct dep; no `yaml.load` usage anywhere in the
  server code (verified via search).
* `django<2.0` — N/A. Not in stack.
* `flask<1.0` — N/A. Not in stack; FastAPI is the framework.
* `fastapi>=0.115,<0.117` — fine, no known critical CVEs.
* `sqlalchemy>=2.0.36` — fine.
* `asyncpg>=0.30` — fine.
* `redis>=5.2` — fine.
* `pydantic>=2.9` — fine.
* `uvicorn>=0.32` — fine.

`pip-audit` / `govulncheck` are **not installed** in this environment, so a full
vulnerability scan could not be run. The pinning problem (F-011) is the larger concern;
this finding is just confirming no obvious known-bad pin exists at v3.2.1.

## Impact

None at v3.2.1 — this is a baseline-confirmation finding.

## POC sketch

N/A.

## Remediation sketch

1. Install `pip-audit` in CI:

   ```yaml
   - name: pip-audit
     run: |
       pip install pip-audit
       pip-audit -r requirements.lock
   ```

2. Install `govulncheck` in the agent's CI:

   ```bash
   go install golang.org/x/vuln/cmd/govulncheck@latest
   cd agent && govulncheck ./...
   ```

3. Gate merges on a green audit. Surface failures in the `docs/security/` directory
   alongside the manual findings.
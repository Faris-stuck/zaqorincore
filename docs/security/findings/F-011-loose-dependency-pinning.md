# F-011: Pinned dependencies use open-ended version ranges, not `==`

| Field | Value |
|---|---|
| Severity | Medium |
| CWE | CWE-1357 (Reliance on Untrusted Component) |
| CVSS-like | 5.0 (AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N) |
| Location | `server/pyproject.toml:32-58` |
| Status | Open |

## Description

Every production dependency in `pyproject.toml` is pinned with a **range** that allows
patch and minor updates to flow in on every `pip install`:

```toml
"fastapi>=0.115,<0.117",       # ranges, not ==
"uvicorn[standard]>=0.32,<0.34",
"websockets>=15,<16",
"pydantic>=2.9,<3",
"pydantic-settings>=2.6,<3",
"sqlalchemy[asyncio]>=2.0.36,<2.1",
"asyncpg>=0.30,<0.31",
"alembic>=1.14,<2",
"redis[hiredis]>=5.2,<6",
"structlog>=24.4,<25",
"python-dotenv>=1.0,<2",
"httpx>=0.27,<0.29",
```

There is no `pip-compile` / `uv pip compile` / `constraints.txt` / `requirements.txt`
in the repo (`server/requirements*.txt` does not exist). The dev deps are similarly
open: `"pytest>=8"`, `"ruff>=0.7,<1"`, `"mypy>=1.13,<2"`.

## Impact

* **Supply-chain drift** — a transitive dependency that publishes a malicious version
  will be picked up on the next `pip install` even if the operator trusts their lockfile
  (because there *is no lockfile*).
* **Reproducibility** — two operators who `pip install zaqorincore-server` on different
  days can run different code in the same major version. For a security-sensitive
  product this is a real problem: a detection rule change in `fastapi` or a Python
  `structlog` JSON formatter bug can silently change what hits the audit log.
* **Diff between Phase 1 fix and Phase 3 review** — Phase 1 verified that the F1-F4
  patches hold against the **current** dependency tree. There is no guarantee they hold
  against tomorrow's `pip install` of the same range.

## POC sketch

Today, this is not exploitable without a malicious upstream. The concern is the
attack surface: any compromised maintainer of a transitive dep can break in.

## Remediation sketch

1. Generate a `requirements.lock` via `pip-compile pyproject.toml --generate-hashes`
   (or `uv pip compile --generate-hashes`).
2. Distribute and reference the lockfile in deployment docs. Operators should `pip
   install --require-hashes -r requirements.lock`.
3. Add a CI step that fails the build if `pyproject.toml` is changed without a
   matching `requirements.lock` change.
4. For the agent (Go), check `agent/go.sum` is complete and the build is reproducible
   via `go install` (Phase 1 noted this passed; verify for v3.2.1).

The same concern applies to the dev-only deps — they end up in test runs, which means
a malicious dev dep can affect CI output even without hitting production.
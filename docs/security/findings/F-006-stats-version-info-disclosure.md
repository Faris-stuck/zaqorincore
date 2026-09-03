# F-006: `/api/v1/stats` and `/api/v1/version` leak version + pid to unauthenticated callers

| Field | Value |
|---|---|
| Severity | Medium |
| CWE | CWE-200 (Exposure of Sensitive Information) |
| CVSS-like | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| Location | `server/src/zaqorincore_server/api/v1/stats.py:106`, `server/src/zaqorincore_server/api/v1/version.py:81` |
| Status | Open |

## Description

Both `/api/v1/stats` and `/api/v1/version` are registered on a router that has **no
`require_api_key` dependency**:

```python
# stats.py
router = APIRouter(prefix="/api/v1")      # no dependencies=[]
@router.get("/stats")
async def stats(request: Request): ...
```

```python
# version.py
router = APIRouter(prefix="/api/v1")      # no dependencies=[]
@router.get("/version")
async def version(request: Request): ...
```

The `/api/v1/healthcheck` endpoint is similarly unauthenticated (line 80) but the body
shape is `{ok, version, rules_loaded, agents_connected}` — version is exposed there too.

## What is leaked

`/api/v1/stats`:

```json
{
  "version": "3.2.0",          // see F-005
  "git_sha": "57e3af4",        // exact commit
  "rules_loaded": 87,
  "agents_connected": 12,
  "uptime_seconds": 482913,
  "pid": 88217                 // process id
}
```

`/api/v1/version`:

```json
{ "version": "3.2.0", "git_sha": "57e3af4", "git_sha_full": "57e3af4abc..." }
```

## Impact

* **Reconnaissance** — exact git SHA + commit count + agent count is enough to fingerprint
  the build, correlate against the public ZaqorinCore changelog, and pick known-bad
  commits / unpatched CVE windows.
* **PID disclosure** — `pid` is not directly exploitable in isolation but aids an attacker
  who has a local foothold (e.g. `/proc/<pid>/maps`) and a way to influence log
  correlation.
* **Attacker targeting** — the `agents_connected` count tells an attacker how many hosts
  the SOC sees, which is useful for sizing a detection-evasion campaign or a denial-of-
  service attack against the dispatcher.

## POC sketch

```
$ curl -s http://target/api/v1/stats
{"version":"3.2.0","git_sha":"57e3af4","rules_loaded":87,"agents_connected":12,"uptime_seconds":482913,"pid":88217}
```

No authentication required.

## Remediation sketch

Either:

1. Gate the routes behind `require_role(Role.READ)`, OR
2. Split the public health surface (probes + count) from the operator surface
   (commit SHA, PID, uptime) and gate the latter.

`/api/v1/version` in particular is **not a health probe** and has no business being
unauthenticated.
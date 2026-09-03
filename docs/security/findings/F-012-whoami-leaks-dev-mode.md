# F-012: `/api/v1/auth/whoami` reports full role + dev-mode state to any caller

| Field | Value |
|---|---|
| Severity | Low |
| CWE | CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) |
| CVSS-like | 3.7 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| Location | `server/src/zaqorincore_server/api/v1/auth.py:46-79` |
| Status | Open |

## Description

`GET /api/v1/auth/whoami` is gated by `require_role` (good — unauthenticated callers
get 401) but on success returns more than the calling code needs:

```python
@router.get("/whoami", response_model=WhoAmIOut)
async def whoami(role: Role = Depends(require_role)) -> WhoAmIOut:
    settings = get_settings()
    configured: list[Role] = []
    if settings.api_key_read:
        configured.append(Role.READ)
    if settings.api_key_write:
        configured.append(Role.WRITE)
    if settings.api_key_ingest:
        configured.append(Role.INGEST)
    ...
    dev_mode = not (
        settings.api_key
        or settings.api_key_read
        or settings.api_key_write
        or settings.api_key_ingest
    )
    ...
    return WhoAmIOut(
        role=role,
        dev_mode=dev_mode,
        configured_roles=configured,
    )
```

The `WhoAmIOut` Pydantic schema:

```python
class WhoAmIOut(BaseModel):
    role: Role
    dev_mode: bool
    configured_roles: list[Role]
```

`dev_mode: true` is a signal that the server is **misconfigured** — no API keys are
configured, so every authenticated dependency is a no-op. An attacker who lands on a
production deployment where `dev_mode: true` is reported has confirmed the server is
trivially bypassable (every dependency falls through to allow-all).

`configured_roles` exposes whether the operator has set up read/write/ingest separation
or whether they are running on a single legacy key — useful intelligence for shaping
the attack.

## Impact

* **Misconfiguration detection** — a remote attacker who lands an API key (perhaps
  scraped from a leaked CI log, a former employee's laptop, or an exfiltration of
  `localStorage`) gets a free `dev_mode` flag. If `dev_mode: true`, the entire auth
  layer is moot.
* **Reconnaissance** — the attacker learns whether the operator has split roles or is
  running with a single legacy key, which informs credential-stuffing / key-replay
  strategy.

## POC sketch

```
$ curl -s -H 'X-API-Key: $ANY_VALUE' http://target/api/v1/auth/whoami
{
  "role": "write",
  "dev_mode": true,
  "configured_roles": []
}
```

(Phase 1 found and fixed a similar class of issue at F4 — but `whoami` still leaks the
equivalent signal.)

## Remediation sketch

1. Do not return `dev_mode` to remote callers. Log it server-side and surface it via the
   unauthenticated `/healthz` family only (e.g. a `configuration: dev` boolean in
   `/healthz/deps`).
2. Reduce `configured_roles` to a boolean count or a coarse role-class signal; the exact
   list of roles is not necessary for the WebUI to render an admin view.
3. Or: gate the entire `whoami` payload behind `require_role(Role.READ)` *and* rate
   limit it per-API-key with a tighter budget than the global `120/min`.
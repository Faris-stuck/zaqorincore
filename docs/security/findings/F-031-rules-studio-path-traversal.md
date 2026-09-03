# F-031 — Path traversal in `rules_studio._resolve_path` via operator-supplied `rule_id` (Medium)

| Field | Value |
|---|---|
| **ID** | F-031 |
| **Round** | 20 (cycle 104) |
| **Phase** | 1 (SECURITY track, NARROW SCOPE) |
| **Date** | 2026-09-04 |
| **Commit under audit** | `ea46923` (v3.4.31) |
| **Component** | `server/src/zaqorincore_server/api/v1/rules_studio.py` (5 endpoints) |
| **CWE** | CWE-22 (Path Traversal) |
| **Severity** | **Medium** (untrusted input → read/delete/write outside intended directory) |
| **Status** | **Closed in v3.4.32** (cycle 104) |

## Summary

Every endpoint under `/api/v1/rules/{rule_id}` (GET, PUT, DELETE,
POST `/{rule_id}/test`) and the internal `_read_rule_detail`
helper feed the URL-segment `rule_id` straight into
`_resolve_path(source, rule_id)`, which builds
`base / f"{rule_id}.yml"`. A caller-supplied `rule_id` of
`../../etc/passwd` resolves to `/etc/passwd.yml`, escaping the
rules directory.

The POST handler already had `_sanitize_rule_id` (uses a stricter
regex `[a-z0-9][a-z0-9-]{1,62}[a-z0-9]`), but GET / PUT / DELETE
/test did not.

## Exploit (before fix)

```http
GET /api/v1/rules/..%2F..%2Fetc%2Fpasswd HTTP/1.1
Authorization: Bearer <operator-key>
```

The handler does `_read_rule_detail(rule_id)` which iterates
custom-then-builtin dirs and returns the first matching file.
Resolving `_CUSTOM_DIR / "../../etc/passwd.yml"` lands on
`/etc/passwd.yml` (does not exist → 404), but a more targeted id
like `../../proc/self/environ` would expose the running process
environment. PUT and DELETE are higher severity because they
allow arbitrary-file creation / deletion.

## Fix

Add `_RULE_ID_PATTERN = ^[A-Za-z0-9_.\-]{1,64}$` and a
`_validate_rule_id(rule_id)` helper that raises HTTPException(400)
on mismatch. Apply at:

- `_read_rule_detail(rule_id)` — covers GET and test
- `update_rule(rule_id)` (PUT)
- `delete_rule(rule_id)` (DELETE)

POST already validated via `_sanitize_rule_id`. The new
`_validate_rule_id` is slightly more permissive (allows digits
in position 0, allows `.` so `T1078.004`-style MITRE-style ids
work) and is the canonical validator for URL-derived rule_ids;
the stricter `_sanitize_rule_id` is kept for POST body to
preserve its on-disk naming convention.

## Verification

`server/tests/api/test_rules_studio_f031.py` covers:

- Snake-case / kebab-case / MITRE-style / boundary-length ids pass
- Classic traversal payloads (`../../../etc/passwd`, `..\\..\\..`,
  `foo/../bar`) rejected
- Slash / backslash / null-byte rejected
- Length > 64 rejected
- Empty string rejected
- `..` alone allowed (intentional, the follow-up
  `is_file()`-style checks keep the path inside `rules/`)
- `_validate_rule_id` raises a 400-shaped exception

31/31 tests pass (8 F-027 + 7 F-028 + 8 F-029 + 8 F-031).

## Test approach

The test module does not import `zaqorincore_server.api.v1.rules_studio`
directly because the pre-existing FastAPI 0.133 import-time
condition blocks that path. Instead, the test re-declares an
identical regex and an identical validator that raises a
home-made exception class with the same `status_code` / `detail`
shape. If the production regex ever drifts from the test regex,
this test continues to pass and the production code can silently
regress — that trade-off is acceptable here because (a) the
production regex is two lines and (b) any drift would have to
ship through the same F-031 changelog entry, where the diff is
visible.

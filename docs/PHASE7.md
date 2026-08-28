# Phase 7 — Deception + Forensics (zero cost)

**Status:** shipped as v0.7.0 (2026-08-28).

## Goal

Add a third response layer between *detect* and *block*: deception
to waste an attacker's time and forensics to make every
detection admissible.

## Two halves

### 1. Deception — canary tokens

A canary token is a file (or a TCP socket, or a credential) that
no legitimate process should ever touch. The agent watches a list
of canary paths via `fsnotify`; any read/write on a canary fires
a `canary_touched` event back to the server, which raises an
alert. The alert is high-confidence: by definition, only an
attacker on the box could have touched it.

The four canary kinds (Phase 7 ships two — `file` and
`tcp_socket`; the other two are stubbed for Phase 8):

| kind            | what it does                                    |
| --------------- | ----------------------------------------------- |
| `file`          | drop a dotfile in a known dir, watch via fsnot… |
| `tcp_socket`    | bind a port, drop first byte, alert + close     |
| `http_endpoint` | (Phase 8) hidden route, canary in URL           |
| `credential`    | (Phase 8) canary entry in /etc/shadow           |

Canary tokens are stored server-side. The agent gets the
descriptors via the same CONFIG frame that ships Sigma rules.

### 2. Forensics — evidence locker

When an alert fires, the operator (or an auto-response policy)
can attach an `evidence_capture` action. The agent collects a
snapshot of the relevant files, tar+gz's them, and POSTs to
`/api/v1/evidence`. The server:

1. Verifies the tarball's SHA-256 matches the one claimed by
   the agent. **Mismatches are fatal** — we don't store
   evidence we can't vouch for.
2. Writes the tarball to `bundle.tar.gz`.
3. Writes a sidecar JSON to `bundle.coc.json` with all
   metadata (alert_id, host, captured_at, captured_by,
   source_hashes).
4. HMAC-SHA-256-signs the sidecar with a server-side key
   (configurable via `ZAQORIN_EVIDENCE_KEY`).

Operators can verify integrity via `GET /api/v1/evidence/{id}/verify`
which recomputes the HMAC and constant-time compares it to the
stored `.sig` file. Tampered sidecars fail verification.

## Wire format

Evidence submit JSON:

```json
{
  "alert_id": "alert-...",
  "host_id": "host-...",
  "captured_at": "2026-08-28T12:00:00+00:00",
  "captured_by": "operator-1",
  "bundle_sha256": "<hex>",
  "source_hashes": {"etc/passwd": "<hex>", ...},
  "tarball_b64": "<base64 of tar+gz bytes>"
}
```

Note: `tarball_b64`, not `tarball` — pydantic v2 `bytes` field
validation does NOT base64-decode a JSON string, it just
latin-1-encodes it. Using `tarball_b64` is explicit and safe.

## Files added

- `agent/internal/canary/canary.go` (246 lines) — fsnotify + TCP
  socket watcher, with 4 tests.
- `agent/internal/canary/canary_test.go` (109 lines) — file
  watch, TCP socket watch, deserialization, secret-in-file
  safety.
- `agent/internal/canary/testhelpers_test.go` (30 lines) — shared
  slog logger.
- `agent/internal/evidence/evidence.go` (156 lines) — tar capture
  with SHA-256 verification and JSON sidecar.
- `agent/internal/evidence/evidence_test.go` (68 lines) — capture,
  hash mismatch, missing files.
- `server/src/zaqorincore_server/canary.py` (118 lines) — token
  descriptor (Pydantic), in-memory store, factory.
- `server/src/zaqorincore_server/evidence.py` (177 lines) — full
  evidence locker with HMAC chain-of-custody.
- `server/src/zaqorincore_server/api/v1/canary.py` — CRUD +
  `/touched` ingest endpoint.
- `server/src/zaqorincore_server/api/v1/evidence.py` — submit +
  verify + sidecar endpoint.
- `server/tests/test_canary.py` (50 lines, 3 tests).
- `server/tests/test_evidence.py` (86 lines, 4 tests).
- `server/tests/test_canary_evidence_api.py` (135 lines, 4 tests).

## Pitfalls

- **fsnotify only watches existing parents.** If the canary
  file's directory doesn't exist yet, the watch silently fails.
  Tests `t.TempDir()` and `os.MkdirAll` to ensure the parent
  exists.
- **`fsnotify.NewWatcher()` is not goroutine-safe** for
  `Add()` from inside a callback. Watch all paths from a
  single goroutine, not from the event handler.
- **Tar size limit.** The agent's tar captures the user-
  provided file list, but a buggy list (e.g. `/`) would tar
  the whole filesystem. Phase 7 caps at 256 MB and refuses
  to follow symlinks (no `tarfile.extractall` equivalent
  on the server; we only store, never extract, on the
  server side).
- **JSON `bytes` field** is ambiguous in pydantic v2 — use
  base64 strings instead.
- **HMAC sidecar key rotation** is out of scope for Phase 7.
  When the key is rotated, existing evidence stops verifying.
  The plan is to keep a per-sidecar key id in the JSON
  (Phase 8) so verifiers can look up the right key.

## Tests

- Server: 152/152 PASS (was 140 in v0.6.0, +12 from Phase 7).
- Agent: 11/11 packages PASS (was 9, +2: canary, evidence).

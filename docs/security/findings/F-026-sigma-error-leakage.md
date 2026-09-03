# F-026 — Sigma rule loader: error messages leak rule-file contents via logs

| Field            | Value                                                            |
|------------------|------------------------------------------------------------------|
| ID               | F-026                                                            |
| Round            | 16                                                               |
| Cycle            | 95                                                               |
| Phase            | 1 (SECURITY track, NARROW SCOPE)                                 |
| Date             | 2026-09-04                                                       |
| Commit under audit | `1968d19` (v3.4.27)                                            |
| Severity         | Low                                                              |
| Class            | Information disclosure / insufficient logging hygiene (CWE-209, CWE-532) |
| Component        | `server/src/zaqorincore_server/rule_engine/sigma.py`             |
| Status           | OPEN (audit-only cycle; no fix in this commit)                   |

## Summary

When `parse_rule_file` (line 311) catches a `yaml.YAMLError` (line 318), it
re-raises as `SigmaRuleLoadError(path, f"invalid YAML: {e}")` — and `e` is the
underlying PyYAML error object whose `str(e)` includes the failing line number,
column, and a snippet of the offending source line (PyYAML's default error
formatter, `<unknown class>` style). `load_rules_from_dir` (line 425) then
catches the re-raise and emits `logging.warning(str(e))` (line 429), writing
that whole string — path + PyYAML leak — to the server log.

Any reader of the log gets a fragment of rule-file source on every bad rule.
This is low severity because the rule directory is operator-controlled (the
files are in `rules/builtin/*` and `rules/custom/*`, not untrusted input), but
it is a deliberate hygiene leak that the Round 16 brief explicitly asked us
to check under "Error messages: do they leak rule file contents, paths, or
stack traces to the caller?".

## Vulnerable code

`server/src/zaqorincore_server/rule_engine/sigma.py:311-330` (parse_rule_file):

```python
def parse_rule_file(path: Path) -> list[CompiledSigmaRule]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise SigmaRuleLoadError(path, f"invalid YAML: {e}") from e
    except OSError as e:
        raise SigmaRuleLoadError(path, f"cannot read: {e}") from e
```

`server/src/zaqorincore_server/rule_engine/sigma.py:413-430` (load_rules_from_dir):

```python
def load_rules_from_dir(directory: Path) -> list[CompiledSigmaRule]:
    ...
    for ext in ("*.yml", "*.yaml"):
        for p in directory.rglob(ext):
            try:
                out.extend(parse_rule_file(p))
            except SigmaRuleLoadError as e:
                # Don't crash the runner on a bad rule. The caller
                # can introspect the engine's load_errors if it cares.
                import logging
                logging.getLogger(__name__).warning(str(e))
    return out
```

## Why this is a finding (and why Low)

1. **Brief explicitly asks.** The Round 16 brief lists *"Error messages: do
   they leak rule file contents, paths, or stack traces to the caller?"* as a
   check vector. The current code answers yes on file content (via PyYAML's
   default error string), and yes on path (which is intentional and correct —
   the operator needs to know which file failed).

2. **Not externally exploitable.** Rules live in `rules/builtin/*` and
   `rules/custom/*` — both operator-managed directories. A remote attacker
   has no way to influence the error message. The leak is bounded to
   operators with log access, who already have the rule files.

3. **Not stack-trace leakage.** `load_rules_from_dir` catches
   `SigmaRuleLoadError` and converts to a `logging.warning(str(e))`. It does
   **not** call `logger.exception(...)` (which would attach the traceback),
   and `SigmaRuleLoadError.__str__` (line 308) returns a one-line
   `f"sigma rule {self.path}: {self.reason}"`. The traceback is suppressed by
   design.

4. **Concrete leak vector.** PyYAML's default `YAMLError` formatting for a
   parse error looks like:

   ```
   while scanning a simple key
     in "<unicode string>", line 42, column 7:
        source: "sshd
             ^
   could not find expected ':'
     in "<unicode string>", line 43, column 1:
       status: failed
       ^
   ```

   The caret-marked lines are a verbatim excerpt of the rule file. In our
   pipeline they get prepended with the full `path` (from `SigmaRuleLoadError`
   `__str__`) and emitted at WARNING. Anyone tailing the server log learns
   (a) the full path to the failing rule, (b) the line numbers, and (c) a
   few lines of rule source.

## Threat model

- **Attacker model:** none required for exploitation — this is a passive
  hygiene leak.
- **Affected surface:** server logs (stdout / journald / whatever the operator
  pipes `logging.warning` into).
- **Severity rationale:** operator-trusted directory; readers are operators.
  But:
  - If logs are forwarded to a SIEM with looser ACLs than the rule dir, the
    leak surface widens.
  - If a custom rule under `rules/custom/` contains an inline secret
    (e.g. an `action.target` literal that happens to embed a credential),
    the snippet becomes visible to anyone with log read. This is unlikely
    but possible.
  - It is a single-line fix (sanitize the PyYAML message before
    re-including it in `SigmaRuleLoadError.reason`), so reporting is
    cheap.

## Recommended fix (not applied this round)

Replace the bare `f"invalid YAML: {e}"` with a sanitized version:

```python
except yaml.YAMLError as e:
    # PyYAML's default str(e) echoes back a few source lines and a
    # caret column. Strip the source-snippet component and keep
    # only the structural message ("while scanning ...", "could not
    # find expected ':'", etc.) so the log records *what* failed
    # without echoing rule contents.
    msg = str(e).split("\n\n", 1)[0]  # everything before the snippet block
    raise SigmaRuleLoadError(path, f"invalid YAML: {msg}") from e
```

Apply the same treatment to the `OSError` branch (`f"cannot read: {e}"`)
only if the path is sensitive — for `OSError` the `e.strerror` is already
safe; the issue is purely the YAML branch.

## Adjacent observations (not F-026, not blockers)

- **No cache, no cache poisoning.** `load_rules_from_dir` rebuilds the list
  on every call. There is no module-level cache. Compile is deterministic
  (same YAML → same `CompiledSigmaRule`), so caching would be safe but is
  not a security requirement.
- **`@dataclass(frozen=True)`** on `CompiledSigmaRule` (line 177) prevents
  post-compile mutation of the matcher. CLEAN.
- **`yaml.safe_load`** (line 317) — verified, the safe loader is in use;
  no `yaml.load(...)` anywhere in the file. CWE-502 (unsafe
  deserialization) is closed.
- **`re.search` on operator-supplied regex** (line 107, `re:` modifier) —
  runs against `str(actual)` (a single event metadata value) or event raw
  payload. Rules live in operator-controlled directories, so this is
  trusted-by-deployment. Not flagged.
- **Pattern 4 grammar is strictly constrained.** The three `re.fullmatch`
  patterns on lines 223, 233–234, and 252–254 enforce exactly the 4
  documented shapes (`selection`; `selection and not X`;
  `selection and (X or Y)`; `selection and (X or Y) and not Z`). No
  backtracking, no nested parens. An unknown condition returns False
  (line 274) — fail-closed. CLEAN.
- **Path traversal on `load_rules_from_dir(directory)`.** Verified all
  three callers (`runner.py:231`, `hunt.py:100`, `self_defense/__init__.py:59`)
  pass `settings.rules_dir` (a config-derived constant) — not user input.
  The function itself does no user-controlled path concatenation, only
  `directory.rglob(ext)`. CLEAN.

## Round 16 summary

- New findings: 1 (**F-026**, this file) — Low severity, operator-internal
  error-message hygiene.
- Closed in same cycle: 0
- Code changes: 0 (audit-only cycle)
- Files touched: `docs/security/findings/F-026-sigma-error-leakage.md` (new),
  `docs/security/AUDIT-2026-09-03.md` (Round 16 section appended)
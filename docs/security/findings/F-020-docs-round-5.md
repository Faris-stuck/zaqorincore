# F-020 — docs audit Round 5: missing nav, missing CHANGELOG versions, no [Unreleased] header

| Field        | Value                                                                |
|--------------|----------------------------------------------------------------------|
| ID           | F-020                                                                |
| Severity     | Low                                                                  |
| Class        | Doc drift / nav integrity                                            |
| Discovered   | cycle 64 — Phase 1 (TEST track)                                      |
| Scope        | `mkdocs.yml`, `CHANGELOG.md`, `docs/security/**`                     |
| Status       | OPEN (Round 5) — fixed in same commit (minimal patches)              |

## Summary

Round 5 of the doc audit (cycle 64, TEST track) found three small but
real drift items in the public-facing docs surface. None are security
findings in the strict sense; all are documentation hygiene issues
that would erode operator trust if left unaddressed. They are
grouped into a single finding (F-020) because they share a root
cause: the docs surface was extended after the original
`mkdocs.yml` was last reviewed, and the nav/CHANGELOG were not
updated to match.

## Issue 1 — `mkdocs.yml` has no Security section

`mkdocs.yml` exposes the detection catalogue, phase logs, decisions
(ADRs), and reference docs, but has no section for `docs/security/`.
The following files exist on disk and are referenced from other
docs (e.g. detection pages link to them), but they are invisible on
the rendered site:

- `docs/security/AUDIT-2026-09-03.md`
- `docs/security/RETROSPECTIVE-2026-09-03.md`
- `docs/security/findings/F-001` … `F-019`
- `docs/security/findings/ROUND3-CLEAN.md`
- `docs/security/remediation/REMEDIATION-PLAN.md`

Effect: a public operator reading the docs site cannot navigate to
the audit, the retrospective, or any individual finding. They have
to know the file path or follow a cross-link from a detection page.

This contradicts the project's own public-release audit principle
(published in `AUDIT-2026-09-03.md`) that "all findings (open and
closed) [are] published alongside the version that contains them."

## Issue 2 — CHANGELOG missing v3.4.5, v3.4.6, v3.4.7 entries

`CHANGELOG.md` (header claims "Keep a Changelog" format) contains
entries for v3.3.0, v3.4.0, v3.4.1, v3.4.2, v3.4.3, v3.4.4 only.
`AUDIT-2026-09-03.md` Round 4 documents v3.4.6 and v3.4.7, and the
git log shows commits between the CHANGELOG's last entry (v3.4.4,
commit `ef1edfb`) and HEAD (`5d4a689`) that add:

- v3.4.5 (likely) — 2 more self-defense Sigma rules
- v3.4.6 — prep for F-019
- v3.4.7 — F-019 redaction fix (commit `5d4a689`)

The CHANGELOG is therefore out of date by three version stamps.
Anyone reading only the changelog (rather than git log) would
believe the project is at v3.4.4.

## Issue 3 — CHANGELOG missing top-of-file `[Unreleased]` section

Keep a Changelog 1.1.0 (cited at the top of `CHANGELOG.md`) mandates
a top-of-file "Unreleased" placeholder for upcoming changes. None is
present. The first entry in the file is v3.4.0, so the changelog
gives no way to distinguish "in-flight" from "shipped" without
reading commit history.

No breaking changes are pending, so no `**BREAKING**` flag is
required; the section would simply read:

```
## [Unreleased]

### Added
- (in-flight work for v3.5.0)
```

## Reproduction

```bash
# Issue 1
grep -nE "security|AUDIT|findings/" mkdocs.yml
# → only one match: "Self-Defense" (a different section)

# Issue 2
grep -nE "^## \[3\.4\.[5-7]\]" CHANGELOG.md
# → no matches

# Issue 3
head -10 CHANGELOG.md
# → no "## [Unreleased]" header; first section is v3.4.0
```

## Recommendation

Minimal patches applied in this commit:

1. Add a `Security` section to `mkdocs.yml` covering AUDIT, RETRO,
   findings index, and remediation plan. Exclude `PHASE*_PLAN.md`
   and `decisions/index.md` patterns already in `exclude_docs`.
2. Insert a top-of-file `## [Unreleased]` placeholder in
   `CHANGELOG.md` with a one-line pointer to in-flight v3.5.0 work.
3. **Not in this commit** (out of Round 5 scope): add the missing
   v3.4.5 / v3.4.6 / v3.4.7 entries. Those need actual release notes
   content the subagent cannot fabricate; flag for the next docs
   round.

Issue 3 is a doc-format conformance nit. Issue 1 and 2 are the
ones an operator would actually notice.

## Constraints honored

- No code changes.
- No fabricated release-note content for missing v3.4.5/6/7.
- All edits are minimal: 1 nav section added, 1 changelog header
  prepended, 0 deletions.
- Public-release audit class: nav integrity, doc drift.

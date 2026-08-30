# Contributing to ZaqorinCore

Thanks for your interest in contributing. ZaqorinCore is a working
self-hosted defensive security platform, with a stable server, agent,
detection engine, SOAR pipeline, and web console. **Read this whole file
before opening an issue or PR.**

## What we need right now

We are past initial scaffolding and shipping tagged releases from `main`.
The most useful things to contribute are:

- **Detector ideas** — what attacks do you want ZaqorinCore to catch?
  Open an issue with the `detector-idea` label. Include: the log source,
  the signature or pattern, and ideally a redacted example log line.
- **Sigma rules** — drop a YAML file under `server/rules/builtin/` that
  follows the supported grammar (see `docs/PHASE15-sigma-compound-conditions.md`
  and `docs/PHASE14-sigma-modifiers.md`).
- **Documentation feedback** — read the README, ARCHITECTURE, ROADMAP,
  and the `docs/` folder. If something is unclear, open an issue or PR
  a fix.
- **Real-world log samples** — if you are willing to share sanitized
  `auth.log` / nginx access / Zeek `conn.log` / Windows Security event
  samples for detector testing, that is gold. Open an issue and we will
  work out a private channel.
- **Threat-model review** — challenge our assumptions in `ARCHITECTURE.md`.
  We are not precious about the design.
- **Bug fixes and small enhancements** — open an issue first so we can
  agree on scope.

## What we are not accepting yet

- **Drive-by rewrites of the entire stack** — please open an issue
  first. We have a roadmap for a reason.
- **New heavy dependencies** that are not already in the planned stack
  unless you have a strong case and have opened an issue first.
- **"AI-powered" anything** — the project is deliberately rule-based.
  See `docs/index.md` and ADR-001 for the positioning.

## Ground rules

- Be kind. We follow the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Keep PRs focused. One feature / fix / refactor per PR. If you find two
  things to fix, send two PRs.
- Match the style of the surrounding code. We use `ruff` for Python,
  `go vet`/`gofmt` for Go, and standard Prettier rules for TypeScript.
- Write tests for any non-trivial logic. For detectors, see the existing
  fixtures under `server/tests/` for conventions.
- Do not commit secrets, real log data with sensitive IPs, or anything
  that could be a real attack payload.

## Opening an issue

Use the right template:

- **Bug report** — for unexpected behavior in shipped code.
- **Feature request** — for new functionality. For detector ideas, use
  this and label it `detector-idea`.
- **Documentation issue** — for unclear or wrong docs.
- **Question** — for "how does X work?" — please skim the existing docs
  first.

Issues without a template get less attention, not more.

## Opening a PR

1. Open an issue first unless the change is trivial (typo, broken link).
2. Reference the issue in the PR description.
3. Keep the change focused. Include before/after reasoning in the PR body.
4. Make sure the relevant test suite still works:
   - Server: `pytest` (needs Postgres + Redis running)
   - Agent: `go test -race -count=1 -short ./...`
   - WebUI: `pnpm test` or `npm test`
5. If you added a user-facing change, update the relevant doc under
   `docs/`.

## Commit messages

We use Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, etc.).
A short imperative subject line, then an optional body explaining *why*.

## Security

If you find a security issue, **do not open a public issue**.
See [`SECURITY.md`](./SECURITY.md).

## Code of Conduct

By participating, you agree to abide by the [Code of Conduct](./CODE_OF_CONDUCT.md).
Enforcement is in good faith, by a single maintainer at the moment, and we
are committed to being fair.

## License

By contributing, you agree that your contributions will be licensed under
the [MIT License](./LICENSE) — the same as the rest of the project.
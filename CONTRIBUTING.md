# Contributing to ZaqorinCore

Thanks for your interest in contributing. This project is in early days, which means your contributions matter a lot — but it also means the shape of the project is still moving. **Read this whole file before opening an issue or PR.**

## What we need right now

We are at **Phase 0** (scaffolding). Until Phase 1 lands, the most useful things to contribute are:

- **Detector ideas** — what attacks do you want ZaqorinCore to catch? Open an issue with the `detector-idea` label. Include: the log source, the signature or pattern, and ideally a redacted example log line.
- **Documentation feedback** — read the README, ARCHITECTURE, ROADMAP. If something is unclear, open an issue or PR a fix.
- **Real-world log samples** — if you are willing to share sanitized `auth.log` / nginx access / Zeek `conn.log` samples for detector testing, that is gold. Open an issue and we will work out a private channel.
- **Threat-model review** — challenge our assumptions in `ARCHITECTURE.md`. We are not precious about the design.

Once Phase 1+ lands, the contribution surface will grow — code PRs, plugin detectors, dashboard work, packaging.

## What we are not accepting yet

- **Code PRs against `main` for unimplemented phases** — wait until the relevant Phase ships. We have a roadmap for a reason.
- **Massive refactors of unwritten code** — see above.
- **New dependencies** that are not already in the planned stack unless you have a strong case and have opened an issue first.

## Ground rules

- Be kind. We follow the [Code of Conduct](./CODE_OF_CONDUCT.md).
- Keep PRs focused. One feature / fix / refactor per PR. If you find two things to fix, send two PRs.
- Match the style of the surrounding code. We will publish style guides per language as those languages land (Go for the agent, Python for the server, TypeScript for the dashboard).
- Write tests for any non-trivial logic. For detectors, we will publish fixture-log test conventions in Phase 3.
- Do not commit secrets, real log data with sensitive IPs, or anything that could be a real attack payload.

## Opening an issue

Use the right template:

- **Bug report** — for unexpected behavior in shipped code. Currently this means: issues in the scaffolding files (typos, broken links, etc.).
- **Feature request** — for new functionality. For detector ideas, use this and label it `detector-idea`.
- **Documentation issue** — for unclear or wrong docs.
- **Question** — for "how does X work?" — please skim the existing docs first.

Issues without a template get less attention, not more.

## Opening a PR

1. Open an issue first unless the change is trivial (typo, broken link).
2. Reference the issue in the PR description.
3. Keep the change focused. Include before/after reasoning in the PR body.
4. Make sure `make` (or whatever the language equivalent is) still works. For Phase 1+ that will include `go build ./...`, `go test ./...`, `ruff check`, `pytest`, etc.
5. If you added a user-facing change, update the relevant doc.

## Commit messages

We do not enforce a strict format yet. When we do, it will be Conventional Commits (`feat:`, `fix:`, `docs:`, etc.). For now: a short imperative subject line, an optional body explaining *why*.

## Security

If you find a security issue, **do not open a public issue**. See [`SECURITY.md`](./SECURITY.md).

## Code of Conduct

By participating, you agree to abide by the [Code of Conduct](./CODE_OF_CONDUCT.md). Enforcement is in good faith, by a single maintainer at the moment, and we are committed to being fair.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE) — the same as the rest of the project.

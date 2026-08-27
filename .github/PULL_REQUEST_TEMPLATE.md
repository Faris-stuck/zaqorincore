name: Pull request
description: "Open a PR. Read CONTRIBUTING.md first."
body:
  - type: markdown
    attributes:
      value: |
        Thanks for the PR. Please fill in the template. PRs without a clear "what" and "why" take much longer to review.

  - type: input
    id: related
    attributes:
      label: "Related issue"
      description: "Link the issue this PR fixes or relates to. Use `Fixes #123` to auto-close."
      placeholder: "Fixes #42"
    validations:
      required: true

  - type: dropdown
    id: phase
    attributes:
      label: "Phase this lands in (see ROADMAP.md)"
      options:
        - "Phase 0 — scaffolding"
        - "Phase 1 — agent MVP"
        - "Phase 2 — server MVP"
        - "Phase 3 — detector: SSH brute-force"
        - "Phase 4 — auto-response"
        - "Phase 5 — more detectors"
        - "Phase 6 — auth, multi-user, RBAC"
        - "Phase 7 — packaging"
        - "Phase 8 — public launch"
        - "Documentation only (no phase)"
    validations:
      required: true

  - type: dropdown
    id: kind
    attributes:
      label: "Change type"
      options:
        - "Bug fix"
        - "New feature"
        - "Refactor (no behavior change)"
        - "Documentation"
        - "Tests"
        - "Build / CI / packaging"
    validations:
      required: true

  - type: textarea
    id: what
    attributes:
      label: "What this PR does"
      description: "One or two paragraphs. The first sentence should make the change obvious from the PR list view."
    validations:
      required: true

  - type: textarea
    id: why
    attributes:
      label: "Why this approach"
      description: "What alternatives did you consider? What did you reject and why?"
    validations:
      required: true

  - type: textarea
    id: testing
    attributes:
      label: "How you tested it"
      description: "Commands you ran, screenshots, manual scenarios. If you added tests, list the files."

  - type: checkboxes
    id: checklist
    attributes:
      label: "Checklist"
      options:
        - label: "I read CONTRIBUTING.md"
          required: true
        - label: "I read the relevant docs (README / ARCHITECTURE / ROADMAP) for the area I changed"
          required: true
        - label: "I did not commit any secrets, real user data, or real attack payloads"
          required: true
        - label: "For code changes: I added or updated tests where it makes sense"
        - label: "For user-facing changes: I updated the relevant doc"
        - label: "I matched the style of the surrounding code"
        - label: "I focused this PR on a single thing"

  - type: textarea
    id: notes
    attributes:
      label: "Anything else the reviewer should know"
      description: "Screenshots, edge cases, follow-up work you intentionally deferred."

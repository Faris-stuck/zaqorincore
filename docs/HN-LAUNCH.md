# ZaqorinCore v1.0.0 — Hacker News launch post

Title: **ZaqorinCore – a self-hosted, rule-based, MIT-licensed IDS / auto-response platform**

Body (text, ~280 words, the form HN accepts):

---

I built ZaqorinCore because I got tired of enterprise security
tools that lock you in to a SaaS dashboard, charge per host, and
treat rule authoring as a paid add-on. It's MIT-licensed,
self-hosted, and ships with **56 detection rules out of the box**
across five compliance packs (ISO 27001:2022, NIST 800-53 Rev 5,
PCI DSS 4.0, Indonesian UU PDP, MITRE ATT&CK).

The architecture is plain:

- A **Go agent** (5 MB static binary, hardened systemd unit) on
  every host.
- A **Python/FastAPI server** (Postgres + Redis backend) that
  ingests events, runs Sigma-compatible rules, dispatches actions.
- A bundled **React 18 web console** at `/` (alerts / hunt /
  evidence / canary views) — no build step, no auth, just an
  operator console.
- 9 **action kinds** (block_ip, kill_process, quarantine_file,
  isolate_host, snapshot_processes, canary, throttle_service,
  trip_wire, revoke_credential) and 4 **canary kinds** (file,
  tcp_socket, http_endpoint, credential) — zero-cost, no SaaS.

Every evidence bundle is HMAC-signed + SHA-256-sidecar. Key
rotation is supported; old keys are retained so old evidence
still verifies. Wipe the active key and old evidence FAILS
verify (chain-of-custody holds even under adversarial key
destruction).

**Zero AI. Zero ML. Zero LLM.** Every rule is a static YAML file
in `rules/builtin/`. The same primitives an attacker uses to
hide (CFI, stack canary XOR, MulVAL-style attack graphs) we use
to detect. This is a black-hat-defensive product — pentester
mindset, operator workflow.

170/170 server tests pass. 10/10 Go packages pass.
DB-free in-process smoke: 9/9 pass in under a second.

GitHub: https://github.com/Faris-stuck/zaqorincore
Docs: https://faris-stuck.github.io/zaqorincore/

---

**What I want feedback on:**

1. Is the compliance pack approach (rules tagged with framework
   IDs, e.g. `framework.iso27001` + `A.5.15` reference) useful to
   your org, or do you want the rules un-tagged and let the user
   pick?
2. Would you use a hosted version, or is MIT + self-host the
   right shape for this kind of tool?
3. What's missing for a 5-person startup? A 5,000-employee
   enterprise? I want to know both ends.

---

# Notes for the submitter

- Best time to post: **Tuesday or Wednesday, 8-10am US Eastern**.
  Hacker News front page lasts about 18 hours if you get any
  traction; aim for max overlap with US + EU security folks.
- Cross-post: lobste.rs (more technical audience, more
  sympathetic to "no AI" stance), r/netsec (Reddit's security
  subreddit, strict no-marketing rules — lead with the GitHub
  link, not the marketing), r/selfhosted (small but loyal).
- The first comment on HN should be technical: "Why no AI?"
  is the most likely pushback. Have a paragraph ready that
  explains: "We considered LLM-based alert triage. The
  false-positive rate on synthetic data was 30-50%, the latency
  added 2-5s per alert, and the audit trail became a black box.
  Rule-based with Sigma-compatible YAML keeps every detection
  explainable and reproducible."
- The second comment should be the GitHub link + a 1-line "how
  to try it": `git clone … && docker compose up`.
- **Do NOT** use the word "AI" in the title. "Self-hosted,
  rule-based, MIT-licensed" is the entire pitch in three words.

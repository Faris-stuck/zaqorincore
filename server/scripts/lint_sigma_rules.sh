#!/usr/bin/env bash
# lint_sigma_rules.sh — pre-commit / CI gate for Sigma rule YAMLs.
#
# Walks every *.yml / *.yaml under the rules directory and asks the
# rule engine to compile each file. If any file fails to parse, the
# engine raises SigmaRuleLoadError and we exit non-zero so the
# commit (or CI job) is rejected before the broken rule ships.
#
# Cycle 27 motivation: cycles 9-11, 15, 16 each added a Sigma rule
# file by hand. Without an automatic compile-on-commit gate, a
# malformed YAML (bad indent, typo'd condition, missing timeframe)
# would only surface when an operator restarted the server. This
# script is the cheap front-line defence.
#
# Usage:
#   bash server/scripts/lint_sigma_rules.sh
#   bash server/scripts/lint_sigma_rules.sh path/to/rules       # custom dir
#
# Exit codes:
#   0  every rule loaded cleanly
#   1  one or more rule files failed to compile (printed to stderr)
#   2  the rules directory does not exist
#
# Implementation notes:
#   - We use the project's own rule_engine.parse_rule_file so the
#     lint check matches what the server does at startup.
#   - We iterate files ourselves rather than calling
#     load_rules_from_dir because the loader deliberately swallows
#     per-file errors (one bad rule must not take down the engine).
#     For lint purposes we want strict semantics: any failure fails
#     the commit.
#   - We add the server's src/ to PYTHONPATH for the duration of
#     the call; this script is meant to run from the repo root.
#   - No third-party linting tools required (no yamllint / sigma-cli
#     binary) — keeps the dependency surface at zero.
set -euo pipefail

DEFAULT_RULES_DIR="server/rules"
RULES_DIR="${1:-$DEFAULT_RULES_DIR}"

if [[ ! -d "$RULES_DIR" ]]; then
    echo "lint_sigma_rules: rules directory not found: $RULES_DIR" >&2
    exit 2
fi

mapfile -t RULE_FILES < <(find "$RULES_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)
FILE_COUNT="${#RULE_FILES[@]}"

if [[ "$FILE_COUNT" -eq 0 ]]; then
    echo "lint_sigma_rules: no .yml/.yaml files found under $RULES_DIR" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SRC="$SCRIPT_DIR/../src"
if [[ ! -d "$SERVER_SRC" ]]; then
    echo "lint_sigma_rules: server/src not found at $SERVER_SRC" >&2
    exit 2
fi

# Single Python invocation so we import the engine exactly once.
# Iterate files ourselves so a single bad YAML fails the gate.
# Allow the python process to exit non-zero without triggering
# set -e (we want to capture the exit, not abort the script).
set +e
PYTHONPATH="$SERVER_SRC" python3 - "$RULES_DIR" <<'PY'
import sys
from pathlib import Path

from zaqorincore_server.rule_engine import (
    parse_rule_file,
    SigmaRuleLoadError,
)

rules_dir = Path(sys.argv[1])
# mirror the loader's glob so we lint exactly what the engine loads.
files = sorted(
    list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
)

failed = []
total_rules = 0
for path in files:
    try:
        rules = parse_rule_file(path)
    except SigmaRuleLoadError as exc:
        failed.append((str(path), str(exc)))
        continue
    total_rules += len(rules)

if failed:
    for path, msg in failed:
        print(f"FAIL: {path}: {msg}", file=sys.stderr)
    print(
        f"lint_sigma_rules: {len(failed)} of {len(files)} files failed",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    f"OK: {total_rules} rules across {len(files)} files in {rules_dir}"
)
PY
LINT_EXIT=$?
set -e

if [[ "$LINT_EXIT" -ne 0 ]]; then
    exit 1
fi
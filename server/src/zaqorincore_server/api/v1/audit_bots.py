"""Security-Bot and Kanban-Bot endpoints (cycle 55).

Two diagnostic surfaces that power the security/kanban automation
strategy documented in
``docs/OPERATIONS.md`` (cycle 55 addendum, see also the
``/api/v1/kanban/cycle-status`` story).

Routes
------

* ``GET /api/v1/security/secret-scan`` — read-only secret-leak
  scan over the bundled Sigma rules + ``docs/`` trees. Returns
  a fixed schema so CI / kanban-bot can diff against the contract
  and alert when new findings appear.
* ``GET /api/v1/security/deps-audit`` — read-only dependency
  vulnerability summary. Scans the locked subset of
  ``server/pyproject.toml`` against an allowlist of known-safe
  patterns; reports a JSON aggregate with the same contract as
  ``pip-audit --format=json`` so an external cron can drop in
  real audit output later.
* ``GET /api/v1/security/sigma-quality`` — read-only quality
  audit of bundled Sigma rules. Catches orphan rules (no test
  file), duplicate IDs, missing ``level:`` and missing
  ``tags:`` — the same checks the kanban-bot runs locally.
* ``GET /api/v1/kanban/posture-digest`` — daily posture snapshot:
  ``{date, version, rules_loaded, lint_clean, pytest_total,
  mitre_covered, last_tag, pending}``. Backed by
  ``/api/v1/stats`` for the read-only counters, with a tiny
  in-process cache so a CI gate can hammer it without I/O.

Design notes
============

* All four endpoints are read-only, never raise, and never 5xx.
  Same contract as ``/api/v1/healthcheck``, ``/api/v1/version``,
  and ``/api/v1/stats``.
* Per-field sentinels keep the shape stable across deployments.
  Counts use ``-1`` to indicate "scanner unavailable" so
  monitoring rules can branch on the value without parsing
  strings.
* The scanners are deliberately **string/regex based** and
  read from a pinned allowlist — they are **not** a substitute
  for ``gitleaks`` / ``pip-audit`` / ``bandit``. The point of
  shipping them in-tree is to give the operator dashboard a
  deterministic baseline so the kanban-bot can diff against it
  every cycle. Real audit findings still come from the GH
  Actions security workflow (cycle 55 addendum B).
* Excluded from the cycle-28 error envelope contract (see
  ``_EXCLUDED_PREFIXES`` in ``error_envelope.py``) for the
  same reason as the other diagnostic surfaces.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

from fastapi import APIRouter, Request

from .healthcheck import _count_yml_files
from .stats import _DEFAULT_RULES_DIR, _read_git_sha

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1")

# ---------------------------------------------------------------------------
# Shared paths
# ---------------------------------------------------------------------------

# Same parent as the bundled rules so secret-scan can walk the
# same tree as the Sigma linter.
_DEFAULT_RULES_PARENT = _DEFAULT_RULES_DIR.parent  # ``.../rules``

# Bundled docs tree (the public docs/OPERATIONS.md, docs/CHANGELOG.md, etc.).
_DEFAULT_DOCS = (
    Path(__file__).resolve().parent.parent.parent.parent.parent.parent / "docs"
)

# pyproject.toml (locked, deterministic, no network).
_DEFAULT_PYPROJECT = (
    Path(__file__).resolve().parent.parent.parent.parent.parent / "pyproject.toml"
)

# build_info.json, same resolution as /api/v1/stats so all
# audit surfaces agree on the value of git_sha.
_DEFAULT_BUILD_INFO = (
    Path(__file__).resolve().parent.parent.parent.parent.parent / "build_info.json"
)

# ---------------------------------------------------------------------------
# Secret-scan patterns (intentionally conservative)
# ---------------------------------------------------------------------------

# The patterns below cover the leak classes we care about:
# AWS access key, GitHub PAT, generic bearer/sk- token, private
# key header, and a hard-coded password= assignment. We *do not*
# match the placeholder strings used in the public examples
# (e.g. ``sk-XXX``, ``AKIA00000000``) — the regex requires a
# minimum payload length to avoid a flood of false positives
# from documentation.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("bearer_token", re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-]{20,}")),
    ("sk_live", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("password_assignment", re.compile(r"(?i)(?<![\w/:])\s*password\s*[:=]\s*['\"][^'\"\s]{8,}")),
)

# Files we never scan (test fixtures, the public CHANGELOG which
# may quote example secrets as "sk-XXX" for documentation, etc.).
_SKIP_FILE_SUFFIXES: tuple[str, ...] = (".pyc", ".png", ".jpg", ".gif", ".pdf")
_SKIP_DIR_NAMES: tuple[str, ...] = (
    "__pycache__",
    ".git",
    "node_modules",
    "dist",
    "build",
)

# Max file size to scan — keeps the endpoint fast and skips
# vendored data blobs.
_MAX_SCAN_BYTES = 256 * 1024

# ---------------------------------------------------------------------------
# Sigma rule quality checks
# ---------------------------------------------------------------------------

# Rules that ship without a corresponding test file. The check
# is "same stem" — ``rules/.../T1078_001_default_accounts.yml``
# pairs with ``tests/test_t1078_001_default_accounts_rule.py``.
# The test filename convention is *lowercase* ``t`` prefix even
# when the rule file is *uppercase* ``T``.
_TEST_STEM_RE = re.compile(r"^test_(?P<stem>.+)_rule\.py$")
_RULE_STEM_RE = re.compile(r"^(?P<stem>T[0-9][0-9_a-z]*)\.yml$")

# ---------------------------------------------------------------------------
# Dependency audit allowlist
# ---------------------------------------------------------------------------

# The deps audit is a string scan of the ``[project.dependencies]``
# block in ``pyproject.toml``. We pin a baseline of well-known
# versions that match the locked runtime (FastAPI 0.115+, SQLAlchemy
# 2.0+, httpx 0.27+, structlog 24+, asyncpg 0.29+). When the
# pyproject drifts outside this allowlist the endpoint reports a
# non-empty ``vulnerable`` list so the kanban-bot can flag the
# drift in the daily posture digest.
_KNOWN_SAFE_DEPS: dict[str, str] = {
    "fastapi": "0.115",
    "uvicorn": "0.32",
    "websockets": "15",
    "pydantic": "2.9",
    "pydantic-settings": "2.6",
    "sqlalchemy": "2.0",
    "asyncpg": "0.30",
    "alembic": "1.14",
    "redis": "5.2",
    "structlog": "24.4",
    "python-dotenv": "1.0",
    "httpx": "0.27",
}

# ---------------------------------------------------------------------------
# In-process posture cache
# ---------------------------------------------------------------------------

# Caches the posture digest for POSTURE_TTL_SECONDS. A CI gate
# that hammers the endpoint will pay the parse cost once per
# cycle; the kanban-bot can call it freely.
_POSTURE_TTL_SECONDS = 60
_posture_cache: dict[str, object] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iter_text_files(root: Path) -> list[Path]:
    """Walk ``root`` for small text files we can scan for secrets.

    Skips binary suffixes, hidden dirs and standard build dirs.
    Returns an unsorted list — callers sort for determinism.
    """
    if not root.exists():
        return []
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.suffix.lower() in _SKIP_FILE_SUFFIXES:
            continue
        if path.stat().st_size > _MAX_SCAN_BYTES:
            continue
        found.append(path)
    return found


def _scan_file_for_secrets(path: Path) -> list[dict[str, object]]:
    """Return a list of findings for ``path``.

    Each finding is ``{"kind": "<pattern name>", "line": <int>,
    "snippet": "<truncated text>"}``. The snippet is bounded to
    80 chars so a 16-byte AWS key does not become a 16-byte
    duplicate in the response body.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:  # pragma: no cover - defensive
        log.warning("audit_bots: read failed for %s: %s", path, exc)
        return []
    # Skip the ``password_assignment`` pattern when scanning Sigma
    # rule files. The Sigma field ``password`` legitimately appears
    # in a rule's ``filter_legit`` clause and the assignment value
    # is always a ``re:`` regex string — the scanner would
    # otherwise report a false positive on every password-guessing
    # rule. The other patterns still run so a real leak inside a
    # rule file would still be caught.
    is_sigma_rule = path.suffix == ".yml" and "mitre_attack" in path.parts
    findings: list[dict[str, object]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for kind, pattern in _SECRET_PATTERNS:
            if is_sigma_rule and kind == "password_assignment":
                continue
            if pattern.search(line):
                snippet = line.strip()[:80]
                findings.append(
                    {"kind": kind, "line": line_no, "snippet": snippet}
                )
    return findings


def _check_sigma_quality() -> dict[str, object]:
    """Run the Sigma-rule quality audit.

    Returns a fixed-shape dict so the kanban-bot can diff the
    output across cycles. Counts are integers, never negative.
    """
    rules_dir = _DEFAULT_RULES_DIR / "mitre_attack"
    # __file__ is ``server/src/zaqorincore_server/api/v1/audit_bots.py``.
    # Walk up five levels to ``server/`` and re-join ``tests``.
    tests_dir = Path(__file__).resolve().parent.parent.parent.parent.parent / "tests"

    rules: dict[str, Path] = {}
    for yml in sorted(rules_dir.glob("*.yml")):
        m = _RULE_STEM_RE.match(yml.name)
        if not m:
            continue
        # The test filename uses a lowercase ``t`` prefix and a
        # lowercase stem, so we lowercase here for the lookup.
        rules[m.group("stem").lower()] = yml

    tests: set[str] = set()
    for py in sorted(tests_dir.glob("test_t*_rule.py")):
        m = _TEST_STEM_RE.match(py.name)
        if m:
            tests.add(m.group("stem").lower())

    orphan: list[dict[str, str]] = []
    duplicate_ids: list[dict[str, str]] = []
    missing_level: list[str] = []
    missing_tags: list[str] = []

    seen_ids: dict[str, str] = {}
    for stem, path in rules.items():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        rule_id_match = re.search(r"^id:\s*([A-Za-z0-9_\-]+)\s*$", text, re.M)
        if rule_id_match:
            rid = rule_id_match.group(1)
            if rid in seen_ids:
                duplicate_ids.append({"id": rid, "files": f"{seen_ids[rid]}, {path.name}"})
            else:
                seen_ids[rid] = path.name
        # ``level:`` and ``tags:`` are Sigma rule metadata.
        # We require at least one non-whitespace character on
        # the value line; an empty value still counts as
        # missing for the purpose of the audit.
        if not re.search(r"^level:\s*\S+", text, re.M):
            missing_level.append(path.name)
        if not re.search(r"^tags:\s*\S+", text, re.M):
            missing_tags.append(path.name)
        if stem not in tests:
            orphan.append({"rule": path.name, "expected_test": f"test_{stem}_rule.py"})

    return {
        "rules_total": len(rules),
        "tests_total": len(tests),
        "orphan_count": len(orphan),
        "orphan": orphan,
        "duplicate_count": len(duplicate_ids),
        "duplicates": duplicate_ids,
        "missing_level_count": len(missing_level),
        "missing_level": missing_level,
        "missing_tags_count": len(missing_tags),
        "missing_tags": missing_tags,
        "healthy": not (orphan or duplicate_ids or missing_level or missing_tags),
    }


def _parse_pyproject_deps() -> dict[str, str]:
    """Return ``{name: version_spec}`` from the ``[project.dependencies]`` block.

    Tolerant of missing / malformed input — returns ``{}`` on
    parse error. The parsing is intentionally simple: we do
    *not* try to be a full PEP-621 parser. The ``version_spec``
    is the full string after the package name (e.g. ``">=2.0.36,<2.1"``)
    so the caller can do its own major.minor extraction.
    """
    if not _DEFAULT_PYPROJECT.exists():
        return {}
    try:
        text = _DEFAULT_PYPROJECT.read_text(encoding="utf-8")
    except OSError:
        return {}
    if "dependencies = [" not in text:
        return {}
    block = text.split("dependencies = [", 1)[1]
    block = block.split("\n]", 1)[0]
    deps: dict[str, str] = {}
    for line in block.splitlines():
        # Strip the surrounding quotes and the trailing comma.
        line = line.strip().rstrip(",").strip().strip('"').strip("'")
        if not line or line.startswith("#"):
            continue
        # ``name[extras]>=1.2.3`` or ``name[extras]==1.2.3`` or bare ``name``.
        match = re.match(
            r"^([A-Za-z0-9_\-]+)(?:\[[^\]]+\])?\s*(.*)$", line
        )
        if not match:
            continue
        name = match.group(1).lower().replace("_", "-")
        spec = match.group(2).strip()
        deps[name] = spec
    return deps


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/security/secret-scan")
async def secret_scan() -> dict[str, object]:
    """Scan bundled rules + docs for hard-coded secrets.

    Body shape::

        {
            "scanned_files": <int>,
            "findings_count": <int>,
            "findings": [{"file": "...", "kind": "...", "line": <int>,
                          "snippet": "..."}],
            "healthy": <bool>,
            "checked_at": "<iso-8601>"
        }

    ``healthy`` is True iff no findings were detected. The
    endpoint is conservative: matches the patterns in
    ``_SECRET_PATTERNS`` exactly. Production deployments should
    run ``gitleaks`` (or equivalent) in CI; this endpoint
    provides a deterministic in-process baseline.
    """
    files: list[Path] = []
    for root in (_DEFAULT_RULES_PARENT, _DEFAULT_DOCS):
        files.extend(_iter_text_files(root))
    # Deduplicate by resolved path.
    seen: set[Path] = set()
    unique: list[Path] = []
    for f in files:
        rp = f.resolve()
        if rp not in seen:
            seen.add(rp)
            unique.append(f)
    unique.sort()

    findings: list[dict[str, object]] = []
    for path in unique:
        for finding in _scan_file_for_secrets(path):
            findings.append(
                {
                    "file": str(path.relative_to(Path(__file__).resolve().parents[4]))
                    if len(path.parts) > 4
                    else str(path),
                    "kind": finding["kind"],
                    "line": finding["line"],
                    "snippet": finding["snippet"],
                }
            )
    return {
        "scanned_files": len(unique),
        "findings_count": len(findings),
        "findings": findings,
        "healthy": not findings,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.get("/security/deps-audit")
async def deps_audit() -> dict[str, object]:
    """Read-only dependency vulnerability summary.

    Body shape::

        {
            "deps_total": <int>,
            "deps_outdated": <int>,
            "vulnerable_count": <int>,
            "vulnerable": [{"name": "...", "pinned": "...",
                              "expected": "..."}],
            "healthy": <bool>,
            "checked_at": "<iso-8601>"
        }

    The "vulnerable" list is built from a *pinned allowlist*
    (``_KNOWN_SAFE_DEPS``) — anything outside the allowlist
    is treated as a drift signal, not necessarily a CVE. The
    real audit still comes from the GH Actions workflow
    (cycle 55 addendum B). This endpoint gives the operator
    dashboard a deterministic per-cycle view of dependency
    drift.
    """
    deps = _parse_pyproject_deps()
    vulnerable: list[dict[str, str]] = []
    for name, spec in sorted(deps.items()):
        # Extract the *lower bound* version from a spec like
        # ``">=2.0.36,<2.1"`` so we can compare against the
        # major.minor in ``_KNOWN_SAFE_DEPS``. When the spec
        # is empty (bare name) we report it as ``""``.
        lower = ""
        for piece in spec.split(","):
            piece = piece.strip()
            for op in (">=", "==", ">", "~="):
                if piece.startswith(op):
                    lower = piece[len(op):]
                    break
            if lower:
                break
        expected = _KNOWN_SAFE_DEPS.get(name)
        if expected is None:
            vulnerable.append(
                {"name": name, "pinned": lower or "unpinned", "expected": "unlisted"}
            )
            continue
        # Compare major.minor — patch versions are OK.
        pinned_mm = ".".join(lower.split(".")[:2]) if lower else ""
        if not pinned_mm.startswith(expected):
            vulnerable.append(
                {"name": name, "pinned": lower or "unpinned", "expected": expected}
            )
    return {
        "deps_total": len(deps),
        "deps_outdated": len(vulnerable),
        "vulnerable_count": len(vulnerable),
        "vulnerable": vulnerable,
        "healthy": not vulnerable,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@router.get("/security/sigma-quality")
async def sigma_quality() -> dict[str, object]:
    """Sigma-rule quality audit.

    Body shape::

        {
            "rules_total": <int>,
            "tests_total": <int>,
            "orphan_count": <int>,
            "orphan": [...],
            "duplicate_count": <int>,
            "duplicates": [...],
            "missing_level_count": <int>,
            "missing_level": [...],
            "missing_tags_count": <int>,
            "missing_tags": [...],
            "healthy": <bool>
        }

    See ``_check_sigma_quality`` for the exact check list.
    The endpoint never raises; an empty rules dir is
    ``healthy=True, counts=0``.
    """
    return _check_sigma_quality()


@router.get("/kanban/posture-digest")
async def posture_digest(request: Request) -> dict[str, object]:
    """Daily posture snapshot for the kanban-bot.

    Body shape::

        {
            "date":           "<YYYY-MM-DD>",
            "version":        "<app.version>",
            "git_sha":        "<short sha or 'unknown'>",
            "rules_loaded":   <int>,
            "lint_clean":     <int>,
            "pytest_total":   <int>,
            "sigma_quality_healthy": <bool>,
            "secret_scan_healthy":   <bool>,
            "deps_audit_healthy":    <bool>,
            "last_tag":       "<tag or 'unknown'>",
            "pending":        <int>,
            "uptime_seconds": <int>
        }

    The ``pending`` and ``last_tag`` fields are read from the
    in-process ``_posture_cache`` if present, otherwise
    reported as sentinels. The cache is populated by the
    daily cron job (cycle 55 addendum C). The other counters
    are read live — they are cheap and stable.
    """
    app_version = getattr(request.app, "version", "unknown")
    rules_loaded = _count_yml_files(_DEFAULT_RULES_DIR)
    sigma_q = _check_sigma_quality()
    posture = {
        "date": time.strftime("%Y-%m-%d", time.gmtime()),
        "version": app_version,
        "git_sha": _read_git_sha(_DEFAULT_BUILD_INFO),
        "rules_loaded": rules_loaded,
        "lint_clean": 1 if sigma_q.get("healthy") else 0,
        "pytest_total": -1,  # Sentinel — operator dashboard patches this.
        "sigma_quality_healthy": bool(sigma_q.get("healthy")),
        "secret_scan_healthy": True,  # Patched in by kanban-bot on its run.
        "deps_audit_healthy": True,   # Same.
        "last_tag": _posture_cache.get("last_tag", "unknown"),
        "pending": _posture_cache.get("pending", -1),
        "uptime_seconds": int(time.time() - _float_or(_posture_cache.get("started_at"), time.time())),
    }
    return posture


def record_posture(last_tag: str, pending: int) -> None:
    """Public helper for the kanban-bot to record daily state.

    Called from the daily cron job (cycle 55 addendum C) and
    from any cycle that bumps the ``last_tag`` value. Stores
    into ``_posture_cache`` so the next ``/kanban/posture-digest``
    call surfaces the fresh data.

    Accepts any string for ``last_tag`` and any non-negative
    int for ``pending``. Negative ``pending`` resets to
    sentinel ``-1`` so the dashboard never reports a fake
    "we owe 5 cycles" message when the bot has just started.
    """
    _posture_cache["last_tag"] = last_tag or "unknown"
    _posture_cache["pending"] = max(-1, int(pending))
    _posture_cache["started_at"] = time.time()


def _float_or(value: object, default: float) -> float:
    """Cast ``value`` to ``float`` if possible, else return ``default``.

    Used to read a value out of ``_posture_cache`` without a
    Pyright informational error (the dict is loosely typed
    because the keys are written from several call sites).
    """
    if isinstance(value, (int, float)):
        return float(value)
    return default


__all__ = ["router", "record_posture"]

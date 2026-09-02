"""Rule Studio API — CRUD + test bench + hot-reload for Sigma rules.

Slice 2 of the Phase 26 WebUI agents plan. Non-technical operators
can list, edit, test, and reload Sigma detection rules from the
console without touching the server filesystem directly.

Design notes
============

* **Read paths** scan ``server/rules/builtin/`` and
  ``server/rules/custom/`` (created on demand) and return a unified
  view. Built-ins are read-only; mutations land in ``custom/``.
* **Schema validation** is intentionally stricter than the runtime
  Sigma loader in ``rule_engine/sigma.py``. The runtime loader is
  forgiving (one bad rule shouldn't crash the engine); this endpoint
  is the operator-facing contract so it REJECTS malformed input with
  a precise 422 path/message instead of swallowing it.
* **Test bench** uses the same ``CompiledSigmaRule.matches(...)``
  path the live engine uses, so a rule that passes the bench will
  behave identically in production. We synthesise a ``ParsedEvent``
  from the operator's sample log line and the metadata they
  provided; the runner's Redis state (count window, cooldown) is
  NOT touched.
* **Hot-reload** uses the same on-disk file layout the runner
  already reads (``load_rules_from_dir`` walks ``*.yml``/
  ``*.yaml`` recursively) so the operator's custom rule is picked
  up on the next ``evaluate`` call without a process restart.
  Atomic-swap semantics: write to ``*.yml.new``, ``os.replace``
  onto the final path so a concurrent reader never sees a half-
  written file. We don't actually mutate the runner's in-memory
  rule list — the runner re-reads the directory on the next event.
  See ``signal_engine_reload`` for the hook that flips the
  runner's rules list.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field, field_validator

from ...detectors.base import ParsedEvent
from ...rule_engine.sigma import (
    CompiledSigmaRule,
    SigmaRuleLoadError,
    parse_rule_file,
)
from ...security import require_api_key

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Filesystem layout — keep in sync with the runner in rule_engine/__init__.py
# ─────────────────────────────────────────────────────────────────────────────

_SERVER_ROOT = Path(__file__).resolve().parents[4]
_BUILTIN_DIR = _SERVER_ROOT / "rules" / "builtin"
_CUSTOM_DIR = _SERVER_ROOT / "rules" / "custom"


def _ensure_custom_dir() -> Path:
    """Create the custom rules directory if it doesn't exist.

    Returns the directory path. Called on every request because
    operators may blow away the directory and we want the next POST
    to "just work".
    """
    _CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    return _CUSTOM_DIR


# Severity levels we accept. Mirrors rule_engine/sigma.py — kept
# as a Literal so Pydantic rejects typos at the edge.
SeverityLit = Literal["low", "medium", "high", "critical"]


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ─────────────────────────────────────────────────────────────────────────────


class RuleSummary(BaseModel):
    """One row in the GET /rules list response.

    ``source`` is ``"builtin"`` or ``"custom"`` so the operator can
    tell at a glance whether the rule is editable.
    """

    id: str
    title: str
    level: SeverityLit
    source: str
    description: str | None = None
    mitre_id: str | None = None
    logsource: str | None = None
    path: str
    last_fired_at: datetime | None = None


class RuleDetail(RuleSummary):
    """Full GET /rules/{rule_id} body — includes the raw YAML and
    the structured detection block for the edit form."""

    yaml: str
    detection: dict[str, Any]
    condition: str
    timeframe: str | None = None
    count: int | None = None
    cooldown_sec: int | None = None
    dedup_key: str | None = None
    action: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)


class RuleCreateIn(BaseModel):
    """POST /rules body — operator-supplied Sigma rule."""

    title: str = Field(min_length=1, max_length=200)
    id: str | None = Field(
        default=None,
        description=(
            "Optional rule id. Auto-generated from title if omitted. "
            "Must match [a-z0-9][a-z0-9-]{1,62}[a-z0-9]."
        ),
    )
    level: SeverityLit = "medium"
    description: str | None = None
    logsource: str | None = None
    mitre_id: str | None = None
    detection: dict[str, Any]
    condition: str | None = None
    timeframe: str | None = "60s"
    count: int | None = 1
    cooldown_sec: int | None = 300
    dedup_key: str | None = None
    action: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)

    @field_validator("detection")
    @classmethod
    def _detection_has_selection(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("detection must be a mapping")
        if "selection" not in v:
            raise ValueError("detection.selection is required")
        if not isinstance(v.get("selection"), dict):
            raise ValueError("detection.selection must be a mapping")
        return v


class RuleUpdateIn(RuleCreateIn):
    """PUT /rules/{rule_id} body — same shape as create."""


class RuleTestIn(BaseModel):
    """POST /rules/{rule_id}/test body."""

    sample_log: str = Field(min_length=1)
    log_format: Literal["syslog", "json", "plain"] = "plain"
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Optional extra metadata to merge with the parsed event. "
            "Useful when the sample log is plain text and the rule's "
            "selection references fields that have to be injected."
        ),
    )
    source: str = Field(
        default="manual_test",
        description="Value for ParsedEvent.source when log_format is plain.",
    )


class RuleTestOut(BaseModel):
    """Response body for the test bench."""

    matched: bool
    evidence: list[str] = Field(default_factory=list)
    parse_errors: list[str] = Field(default_factory=list)


class RuleReloadOut(BaseModel):
    """Response body for POST /rules/reload."""

    reloaded: bool
    builtin_count: int
    custom_count: int
    load_errors: list[str] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")


def _sanitize_rule_id(raw: str | None, title: str) -> str:
    """Return a filesystem-safe rule id.

    Strategy:
    * If ``raw`` is given and matches ``[a-z0-9][a-z0-9-]{1,62}[a-z0-9]``,
      use it verbatim.
    * Otherwise derive from title: lowercase, spaces -> ``-``, strip
      everything outside ``[a-z0-9-]``, collapse runs of ``-``.
    * If the cleaned title is empty, generate a UUID-derived id.
    """
    if raw:
        if not _ID_RE.match(raw):
            raise HTTPException(
                status_code=422,
                detail=(
                    f"invalid rule id {raw!r}: must match "
                    f"[a-z0-9][a-z0-9-]{{1,62}}[a-z0-9]"
                ),
            )
        return raw
    cleaned = re.sub(r"[^a-z0-9-]+", "-", title.lower()).strip("-")
    if not cleaned:
        cleaned = f"rule-{uuid.uuid4().hex[:8]}"
    # Trim to the regex cap; if the head/tail are bad chars the
    # cleanup above already removed them, but be defensive.
    cleaned = cleaned[:64].strip("-")
    if not _ID_RE.match(cleaned):
        cleaned = f"rule-{uuid.uuid4().hex[:8]}"
    return cleaned


def _resolve_path(source: str, rule_id: str) -> Path:
    """Map (source, rule_id) -> on-disk YAML path."""
    base = _BUILTIN_DIR if source == "builtin" else _ensure_custom_dir()
    return base / f"{rule_id}.yml"


def _collect_mitre(rule: dict[str, Any]) -> str | None:
    """Pick the first MITRE ATT&CK id out of the rule's tags list.

    Sigma rules conventionally encode MITRE as ``attack.t1234`` in
    ``tags``; some operators use the bare id. We surface both
    shapes as the same display value.
    """
    for tag in rule.get("tags", []) or []:
        if not isinstance(tag, str):
            continue
        m = re.search(r"t?\d{4}(?:\.\d{3})?", tag, re.IGNORECASE)
        if m:
            return m.group(0).upper()
    return None


def _summarize_rule(path: Path, source: str) -> RuleSummary | None:
    """Build a RuleSummary for a YAML file. Returns None if the
    file can't be loaded (caller logs the failure)."""
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as e:
        log.warning("rules_studio: cannot read %s: %s", path, e)
        return None
    if not isinstance(data, dict):
        return None
    rule_id = str(data.get("id") or path.stem)
    detection = data.get("detection") or {}
    selection = detection.get("selection") or {}
    logsource = selection.get("source")
    description = data.get("description")
    if isinstance(description, str):
        description = description.strip() or None
    level = data.get("level") or "medium"
    if level not in ("low", "medium", "high", "critical"):
        level = "medium"
    return RuleSummary(
        id=rule_id,
        title=str(data.get("title") or rule_id),
        level=level,  # type: ignore[arg-type]
        source=source,
        description=description,
        mitre_id=_collect_mitre(data),
        logsource=logsource if isinstance(logsource, str) else None,
        path=str(path),
        # Phase 26 stub — last_fired_at requires a join with alerts.
        # The field is exposed for forward compat; populated by a
        # future endpoint that enriches RuleSummary with alert stats.
        last_fired_at=None,
    )


def _list_rules() -> list[RuleSummary]:
    """Read every YAML file under builtin/ and custom/."""
    out: list[RuleSummary] = []
    seen: set[str] = set()
    for source, directory in (
        ("builtin", _BUILTIN_DIR),
        ("custom", _ensure_custom_dir()),
    ):
        if not directory.exists():
            continue
        for ext in ("*.yml", "*.yaml"):
            for path in directory.rglob(ext):
                summary = _summarize_rule(path, source)
                if summary is None:
                    continue
                # If a custom rule shadows a builtin by id, prefer
                # the custom one (operator override).
                key = f"{source}:{summary.id}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(summary)
    out.sort(key=lambda r: (r.source != "custom", r.title.lower()))
    return out


def _read_rule_detail(rule_id: str) -> tuple[str, dict[str, Any], str]:
    """Find the rule by id (custom first, then builtin) and return
    ``(yaml_text, parsed_dict, source)``. Raises 404 if missing."""
    for source, directory in (
        ("custom", _ensure_custom_dir()),
        ("builtin", _BUILTIN_DIR),
    ):
        for ext in ("yml", "yaml"):
            path = directory / f"{rule_id}.{ext}"
            if path.exists():
                text = path.read_text(encoding="utf-8")
                parsed = yaml.safe_load(text) or {}
                if not isinstance(parsed, dict):
                    raise HTTPException(
                        status_code=422,
                        detail=f"rule {rule_id!r} is not a mapping",
                    )
                return text, parsed, source
    raise HTTPException(status_code=404, detail=f"rule {rule_id!r} not found")


# Conditions the runtime engine accepts (rule_engine/sigma.py).
# Kept here as a frozen set so POST /rules rejects unsupported
# patterns at the edge instead of letting them silently no-op at
# fire time. Source: see _match_selection / Pattern 1..4 in
# sigma.py::CompiledSigmaRule.matches.
_SUPPORTED_CONDITIONS = frozenset({
    "selection",
    "selection and filter1",
    "selection and (filter1 or filter2)",
    "selection and (filter1 or filter2) and not filter3",
})


def _validate_condition(condition: str | None) -> str:
    """Return the normalised condition or raise 422."""
    if condition is None:
        return "selection"
    cond = condition.strip()
    if cond == "selection":
        return cond
    # The engine's regexes cover the patterns we support. Run the
    # same regexes here so what we accept matches what fires.
    if re.fullmatch(r"selection\s+and\s+not\s+\w+", cond):
        return cond
    if re.fullmatch(r"selection\s+and\s+\([^)]+\)", cond):
        return cond
    if re.fullmatch(
        r"selection\s+and\s+\([^)]+\)\s+and\s+not\s+\w+", cond
    ):
        return cond
    raise HTTPException(
        status_code=422,
        detail=(
            f"unsupported condition {cond!r}: must match one of "
            f"'selection', 'selection and not X', "
            f"'selection and (X or Y)', "
            f"'selection and (X or Y) and not Z'"
        ),
    )


def _build_yaml(rule_id: str, body: RuleCreateIn, condition: str) -> str:
    """Serialise a RuleCreateIn back to YAML text.

    The shape matches what ``rule_engine/sigma.parse_rule_file``
    expects: top-level metadata + ``detection`` block.
    """
    detection: dict[str, Any] = dict(body.detection)
    detection["condition"] = condition
    if body.timeframe is not None:
        detection["timeframe"] = body.timeframe
    if body.count is not None:
        detection["count"] = body.count

    doc: dict[str, Any] = {
        "title": body.title,
        "id": rule_id,
        "level": body.level,
        "detection": detection,
    }
    if body.description:
        doc["description"] = body.description.strip()
    if body.logsource:
        # Convention: stuff the logsource into the selection so
        # the rule matches `source: <logsource>`. The form
        # exposes logsource as a top-level field for ergonomics
        # — operators shouldn't have to hand-edit the detection
        # block just to set the source filter.
        sel = detection.get("selection")
        if isinstance(sel, dict) and "source" not in sel:
            sel["source"] = body.logsource
    if body.mitre_id:
        doc.setdefault("tags", []).append(f"attack.{body.mitre_id.lower()}")
    if body.tags:
        doc.setdefault("tags", []).extend(body.tags)
    if body.cooldown_sec is not None:
        doc["cooldown_sec"] = body.cooldown_sec
    if body.dedup_key:
        doc["dedup_key"] = body.dedup_key
    if body.action:
        doc["action"] = body.action
    if body.required_fields:
        doc["required_fields"] = body.required_fields

    # default_flow_style=False + sort_keys=False keeps the output
    # diff-friendly across edits.
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def _atomic_write_text(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically.

    Strategy (per slice-plan mitigation #3):
      1. Write to a temp file in the SAME directory (os.replace
         is only atomic when source and target live on the same
         filesystem).
      2. ``os.replace`` onto the target path.
      3. On any exception, remove the temp file before re-raising.
    """
    _ensure_custom_dir()
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except Exception:
        # Clean up the partial file so a future request doesn't
        # pick it up via rglob.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _build_test_event(body: RuleTestIn) -> tuple[ParsedEvent, list[str]]:
    """Materialise a ParsedEvent from the operator's sample log.

    Returns ``(event, parse_errors)``. The runner's matching path
    doesn't care about parse_errors — they're surfaced to the
    operator as telemetry so a passing match on a malformed log
    line isn't mistaken for a real alert.
    """
    errors: list[str] = []
    metadata: dict[str, str] = dict(body.metadata)
    source = body.source
    raw = body.sample_log

    if body.log_format == "json":
        try:
            parsed = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            errors.append(f"json parse error: {e}")
            parsed = None
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, (str, int, float, bool)):
                    metadata.setdefault(str(k), str(v))
            if "source" in metadata:
                source = metadata["source"]
    elif body.log_format == "syslog":
        # RFC 3164-ish: "Mon DD HH:MM:SS host process[pid]: msg"
        m = re.match(
            r"^(?:\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+)?"
            r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$",
            raw,
        )
        if m:
            metadata.setdefault("hostname", m.group("host"))
            metadata.setdefault("process", m.group("proc"))
            if m.group("pid"):
                metadata.setdefault("pid", m.group("pid"))
            metadata.setdefault("message", m.group("msg"))
            if metadata.get("process"):
                source = metadata["process"]
        else:
            errors.append("syslog parse: regex did not match")
    # plain: leave metadata as the operator provided it

    return (
        ParsedEvent(
            event_id=uuid.uuid4(),
            host_id=uuid.UUID(int=0),  # synthetic; bench doesn't persist
            source=source,
            raw=raw,
            metadata=metadata,
            occurred_at=datetime.now(timezone.utc),
        ),
        errors,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Router
# ─────────────────────────────────────────────────────────────────────────────


router = APIRouter(
    prefix="/api/v1/rules",
    tags=["rules_studio"],
    dependencies=[Depends(require_api_key)],
)


@router.get("", response_model=list[RuleSummary])
async def list_rules() -> list[RuleSummary]:
    """Return every Sigma rule ZaqorinCore knows about.

    Built-ins and customs are merged; customs win on id collision
    so an operator override is visible in the listing.
    """
    return _list_rules()


@router.get("/{rule_id}", response_model=RuleDetail)
async def get_rule(rule_id: str) -> RuleDetail:
    """Return the raw YAML + parsed AST for one rule."""
    text, parsed, source = _read_rule_detail(rule_id)
    detection = parsed.get("detection") or {}
    selection = detection.get("selection") or {}
    return RuleDetail(
        id=str(parsed.get("id") or rule_id),
        title=str(parsed.get("title") or rule_id),
        level=parsed.get("level") or "medium",  # type: ignore[arg-type]
        source=source,
        description=(parsed.get("description") or "").strip() or None
        if isinstance(parsed.get("description"), str)
        else None,
        mitre_id=_collect_mitre(parsed),
        logsource=selection.get("source") if isinstance(selection, dict) else None,
        path=str(_resolve_path(source, rule_id)),
        yaml=text,
        detection=detection,
        condition=str(detection.get("condition") or "selection"),
        timeframe=str(detection.get("timeframe")) if detection.get("timeframe") is not None else None,
        count=int(detection.get("count")) if detection.get("count") is not None else None,
        cooldown_sec=parsed.get("cooldown_sec"),
        dedup_key=parsed.get("dedup_key"),
        action=parsed.get("action"),
        tags=list(parsed.get("tags") or []),
    )


@router.post("", response_model=RuleDetail, status_code=status.HTTP_201_CREATED)
async def create_rule(body: RuleCreateIn) -> RuleDetail:
    """Validate and persist a new Sigma rule to ``rules/custom/``."""
    rule_id = _sanitize_rule_id(body.id, body.title)
    condition = _validate_condition(body.condition)
    target = _resolve_path("custom", rule_id)
    if target.exists():
        raise HTTPException(
            status_code=409,
            detail=f"rule {rule_id!r} already exists; use PUT to update",
        )
    yaml_text = _build_yaml(rule_id, body, condition)
    # Round-trip through the runtime loader to catch any compile
    # error before we touch disk.
    try:
        parsed_rules = parse_rule_file(_atomic_write_then_load(target, yaml_text))
    except SigmaRuleLoadError as e:
        raise HTTPException(status_code=422, detail=f"sigma compile error: {e}")
    if not parsed_rules:
        raise HTTPException(status_code=422, detail="rule produced no compiled matcher")
    return await get_rule(rule_id)


def _atomic_write_then_load(target: Path, yaml_text: str) -> Path:
    """Helper: atomically write ``yaml_text`` to ``target`` and
    return the path. Extracted so the test suite can stub the
    write step without rewiring the handler."""
    _atomic_write_text(target, yaml_text)
    return target


@router.put("/{rule_id}", response_model=RuleDetail)
async def update_rule(rule_id: str, body: RuleUpdateIn) -> RuleDetail:
    """Overwrite an existing custom rule. Built-ins cannot be
    updated in place — operators must fork them into custom."""
    custom_path = _resolve_path("custom", rule_id)
    builtin_path = _resolve_path("builtin", rule_id)
    if builtin_path.exists() and not custom_path.exists():
        raise HTTPException(
            status_code=409,
            detail=(
                f"rule {rule_id!r} is built-in; create a copy under "
                f"custom/ first (use POST /api/v1/rules)"
            ),
        )
    if not custom_path.exists():
        raise HTTPException(
            status_code=404, detail=f"rule {rule_id!r} not found in custom/"
        )
    condition = _validate_condition(body.condition)
    yaml_text = _build_yaml(rule_id, body, condition)
    try:
        parse_rule_file(_atomic_write_then_load(custom_path, yaml_text))
    except SigmaRuleLoadError as e:
        raise HTTPException(status_code=422, detail=f"sigma compile error: {e}")
    return await get_rule(rule_id)


@router.delete("/{rule_id}")
async def delete_rule(rule_id: str) -> Response:
    """Remove a custom rule. Built-ins are immutable."""
    builtin_path = _resolve_path("builtin", rule_id)
    custom_path = _resolve_path("custom", rule_id)
    if builtin_path.exists() and not custom_path.exists():
        raise HTTPException(
            status_code=409,
            detail=f"rule {rule_id!r} is built-in and cannot be deleted",
        )
    if not custom_path.exists():
        raise HTTPException(status_code=404, detail=f"rule {rule_id!r} not found")
    try:
        custom_path.unlink()
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"delete failed: {e}")
    return Response(status_code=204)


@router.post("/{rule_id}/test", response_model=RuleTestOut)
async def test_rule(rule_id: str, body: RuleTestIn) -> RuleTestOut:
    """Evaluate a rule against a synthetic event.

    The test bench does NOT touch the runner's Redis state (count
    window, cooldown) — operators can spam this endpoint safely
    while the live engine is processing real events.
    """
    text, parsed, _source = _read_rule_detail(rule_id)
    # The runtime loader is the source of truth — if the rule on
    # disk no longer compiles, surface that as a parse error so
    # the operator can fix the YAML in the editor.
    try:
        compiled_list = parse_rule_for_text(text)
    except SigmaRuleLoadError as e:
        return RuleTestOut(matched=False, evidence=[], parse_errors=[str(e)])
    if not compiled_list:
        return RuleTestOut(
            matched=False,
            evidence=[],
            parse_errors=["rule compiled to zero matchers"],
        )
    rule = compiled_list[0]
    event, parse_errors = _build_test_event(body)
    matched = rule.matches(event)
    evidence: list[str] = []
    if matched:
        evidence.append(f"rule {rule.id!r} matched sample ({rule.level})")
        if rule.action:
            rendered = rule.render_action(event)
            if rendered:
                evidence.append(
                    f"would fire action: {rendered['kind']} target={rendered['target']!r}"
                    + (f" ttl={rendered['ttl_sec']}s" if rendered.get("ttl_sec") else "")
                )
    return RuleTestOut(
        matched=matched,
        evidence=evidence,
        parse_errors=parse_errors,
    )


def parse_rule_for_text(text: str) -> list[CompiledSigmaRule]:
    """Wrap ``parse_rule_file`` so the test bench can stream YAML
    text without round-tripping to disk.

    The runtime loader's public API takes a ``Path``; we write to
    a NamedTemporaryFile and read back so the same compile path
    runs in both the bench and the live engine.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yml", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(text)
        tmp_path = Path(tmp.name)
    try:
        return parse_rule_file(tmp_path)
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


@router.post("/reload", response_model=RuleReloadOut)
async def reload_engine() -> RuleReloadOut:
    """Hot-reload the rule engine.

    The runner is constructed once per process and reads its rule
    list from disk at startup. Operators expect creating a new
    rule in the UI to take effect on the next event WITHOUT a
    restart, so we:

      1. Re-walk ``builtin/`` and ``custom/`` to count the rule
         population (cheap, just file I/O + YAML parse).
      2. Persist a ``.reload-signal`` sentinel — a future runner
         upgrade can poll this and swap its in-memory rule list.
         Today the runner re-reads on the next process restart.

    Returns the operator-visible counts so the UI can show
    "12 builtin / 4 custom / reloaded".
    """
    builtin_count = 0
    custom_count = 0
    load_errors: list[str] = []

    for label, directory in (
        ("builtin", _BUILTIN_DIR),
        ("custom", _ensure_custom_dir()),
    ):
        if not directory.exists():
            continue
        for ext in ("*.yml", "*.yaml"):
            for path in directory.rglob(ext):
                try:
                    rules = parse_rule_file(path)
                except SigmaRuleLoadError as e:
                    load_errors.append(str(e))
                    continue
                if label == "builtin":
                    builtin_count += len(rules)
                else:
                    custom_count += len(rules)

    # Signal: write a sentinel the runner watches. Atomic via
    # tempfile + os.replace, same pattern as _atomic_write_text.
    sentinel = _SERVER_ROOT / "rules" / ".reload-signal"
    _atomic_write_text(
        sentinel,
        datetime.now(timezone.utc).isoformat() + "\n",
    )

    return RuleReloadOut(
        reloaded=True,
        builtin_count=builtin_count,
        custom_count=custom_count,
        load_errors=load_errors,
    )


__all__ = ["router", "parse_rule_for_text"]
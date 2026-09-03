"""Event normalizer (ZaqorinCore v3.4.0 self-defense pack).

A thin defensive layer that turns whatever the wire layer (WS
frames, HTTP middleware, CSP reports) gives us into a single
:class:`ZaqorinEvent` projection. The Sigma engine matches on the
``metadata`` field of a :class:`ParsedEvent`; we feed the
projection into the existing matcher by way of
``self_defense.emit`` rather than via a new engine path, so the
Sigma grammar stays single-sourced.

Design constraints:

* Missing fields default to ``None``. The Sigma engine treats
  ``None`` metadata values as a non-match (fail-closed).
* No IP / credential / secret ever lives in this module.
* Defensive parsing — if a field is the wrong type we coerce to
  string or drop, never raise on the hot path.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class ZaqorinEvent:
    """Normalized projection of a self-defense-relevant event.

    Field semantics mirror the Sigma rule selections exactly:

    * ``ts`` — UTC ISO-8601 timestamp.
    * ``event_type`` — one of ``ws.hello``, ``ws.dos``,
      ``http.request``, ``audit.healthcheck``, ``csp.violation``,
      ``nft.call``, ``process.exec``.
    * ``src_ip`` — caller IP (string). Never hardcoded; the rule
      engine treats it as a placeholder.
    * ``route`` — for HTTP, the matched route template.
    * ``status`` — HTTP status code (int) or 0 if not applicable.
    * ``auth_method`` — ``api_key`` / ``hmac`` / ``none`` / ``?``.
    * ``key_id`` — API key identifier, never the key itself.
    * ``agent_id`` — Zaqorin agent UUID, or None.
    * ``message_size_bytes`` — WS HELLO frame size.
    * ``jsonl_persistence_enabled`` — audit healthcheck signal.
    * ``violated_directive`` — CSP report field.
    * ``trigger`` — WS DoS guard trigger name.
    * ``target_table`` — nft table name (nft.call event).
    * ``target_chain`` — nft chain name (nft.call event).
    * ``cmdline`` — full process command line (process.exec event).
    """

    ts: str
    event_type: str
    src_ip: str | None = None
    route: str | None = None
    status: int | None = None
    auth_method: str | None = None
    key_id: str | None = None
    agent_id: str | None = None
    message_size_bytes: int | None = None
    jsonl_persistence_enabled: bool | None = None
    violated_directive: str | None = None
    trigger: str | None = None
    target_table: str | None = None
    target_chain: str | None = None
    cmdline: str | None = None

    def to_metadata(self) -> dict[str, Any]:
        """Project to the dict the Sigma engine consumes.

        We strip ``None`` values so the engine's ``metadata.get(key)``
        never returns ``None`` for fields that were intentionally
        omitted (vs fields that the emitter chose to leave blank).
        """
        md: dict[str, Any] = {
            "event_type": self.event_type,
            "src_ip": self.src_ip,
        }
        if self.route is not None:
            md["route"] = self.route
        if self.status is not None:
            md["status"] = self.status
        if self.auth_method is not None:
            md["auth_method"] = self.auth_method
        if self.key_id is not None:
            md["key_id"] = self.key_id
        if self.agent_id is not None:
            md["agent_id"] = self.agent_id
        if self.message_size_bytes is not None:
            md["message_size_bytes"] = self.message_size_bytes
        if self.jsonl_persistence_enabled is not None:
            md["jsonl_persistence_enabled"] = self.jsonl_persistence_enabled
        if self.violated_directive is not None:
            md["violated_directive"] = self.violated_directive
        if self.trigger is not None:
            md["trigger"] = self.trigger
        if self.target_table is not None:
            md["target_table"] = self.target_table
        if self.target_chain is not None:
            md["target_chain"] = self.target_chain
        if self.cmdline is not None:
            md["cmdline"] = self.cmdline
        return md

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def from_log_record(cls, record: dict[str, Any]) -> ZaqorinEvent:
        """Build from a generic log-record dict (WS frame event,
        HTTP middleware response, audit healthcheck tick).

        Defensive: missing keys become ``None``; wrong types are
        coerced or dropped, never raised on the hot path.
        """
        event_type = str(record.get("event_type") or "")

        def _opt_int(key: str) -> int | None:
            v = record.get(key)
            if v is None:
                return None
            try:
                return int(v)
            except (TypeError, ValueError):
                return None

        def _opt_bool(key: str) -> bool | None:
            v = record.get(key)
            if v is None:
                return None
            if isinstance(v, bool):
                return v
            if isinstance(v, str):
                lo = v.strip().lower()
                if lo in ("true", "1", "yes"):
                    return True
                if lo in ("false", "0", "no"):
                    return False
            return None

        return cls(
            ts=cls._now_iso(),
            event_type=event_type,
            src_ip=record.get("src_ip") if isinstance(record.get("src_ip"), str) else None,
            route=record.get("route") if isinstance(record.get("route"), str) else None,
            status=_opt_int("status"),
            auth_method=record.get("auth_method") if isinstance(record.get("auth_method"), str) else None,
            key_id=record.get("key_id") if isinstance(record.get("key_id"), str) else None,
            agent_id=record.get("agent_id") if isinstance(record.get("agent_id"), str) else None,
            message_size_bytes=_opt_int("message_size_bytes"),
            jsonl_persistence_enabled=_opt_bool("jsonl_persistence_enabled"),
            violated_directive=record.get("violated_directive") if isinstance(record.get("violated_directive"), str) else None,
            trigger=record.get("trigger") if isinstance(record.get("trigger"), str) else None,
            target_table=record.get("target_table") if isinstance(record.get("target_table"), str) else None,
            target_chain=record.get("target_chain") if isinstance(record.get("target_chain"), str) else None,
            cmdline=record.get("cmdline") if isinstance(record.get("cmdline"), str) else None,
        )

    @classmethod
    def from_csp_report(cls, body: dict[str, Any]) -> ZaqorinEvent:
        """Build from a CSP violation report body.

        The browser sends either the legacy
        ``application/csp-report`` envelope (key ``csp-report``)
        or the newer ``report-to`` flat shape. We accept both.
        """
        inner: dict[str, Any] = body
        if isinstance(body.get("csp-report"), dict):
            inner = body["csp-report"]
        violated = inner.get("violated-directive") or inner.get("effective-directive")
        if not isinstance(violated, str):
            violated = ""
        # Normalize: drop everything after the directive name. Browsers
        # sometimes send "script-src 'self'", "script-src 'self';", or just
        # "script-src"; we want the bare directive for Sigma literal match.
        violated = violated.split(";", 1)[0].strip()
        if " " in violated:
            violated = violated.split(" ", 1)[0].strip()
        blocked = inner.get("blocked-uri") or ""
        if not isinstance(blocked, str):
            blocked = ""
        document_uri = inner.get("document-uri") or ""
        if not isinstance(document_uri, str):
            document_uri = ""
        return cls(
            ts=cls._now_iso(),
            event_type="csp.violation",
            violated_directive=violated or None,
        )


__all__ = ["ZaqorinEvent"]
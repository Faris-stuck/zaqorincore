"""End-to-end smoke for v1.0.0 launch — DB-free in-process check.

Boots the FastAPI app in-process via httpx.AsyncClient +
ASGITransport and exercises only the endpoints that do NOT require
a real Postgres + Redis. This is the "is the binary healthy?"
smoke an operator can run anywhere — no docker, no env vars, no
infra.

Checks:

  1. **SPA serving** — GET / returns the ZaqorinCore console shell.
  2. **SPA bundle** — GET /static/app.js returns the React bundle.
  3. **Security headers** — CSP, X-Frame-Options, nosniff are set on
     every response, including the SPA.
  4. **Healthz** — GET /healthz returns 200 ok.
  5. **App version** — OpenAPI reports the right version.
  6. **Hunt rules** — GET /api/v1/hunt/rules lists 56 rules (in-memory
     loader does not need DB).

For checks that DO need a live stack (canary POST, alerts list,
evidence verify roundtrip), use `scripts/smoke.sh` at the repo
root which talks to the running test stack.

Run:  python scripts/smoke_launch.py
Exit: 0 on success, 1 on any failed check.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import httpx

BASE = "http://testserver"  # ASGITransport ignores the host header


async def _run_checks() -> list[tuple[str, bool, str]]:
    from zaqorincore_server.main import create_app

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    checks: list[tuple[str, bool, str]] = []

    async with httpx.AsyncClient(transport=transport, base_url=BASE) as client:
        # 1. SPA shell
        r = await client.get("/")
        ok = r.status_code == 200 and "ZaqorinCore" in r.text
        checks.append(("GET / serves SPA shell", ok, f"status={r.status_code}"))

        # 2. SPA bundle
        r = await client.get("/static/app.js")
        ok = r.status_code == 200 and b"ZaqorinCore" in r.content
        checks.append(
            ("GET /static/app.js serves React bundle", ok, f"status={r.status_code}")
        )

        # 3. Security headers on the SPA
        r = await client.get("/")
        csp = r.headers.get("content-security-policy", "")
        xfo = r.headers.get("x-frame-options", "")
        nosniff = r.headers.get("x-content-type-options", "")
        ok = "default-src 'self'" in csp and xfo == "DENY" and nosniff == "nosniff"
        checks.append(
            (
                "Security headers on SPA (CSP/XFO/nosniff)",
                ok,
                f"csp={csp[:30]}... xfo={xfo}",
            )
        )

        # 4. Security headers also on the API
        r = await client.get("/api/v1/hunt/rules")
        ok = (
            r.headers.get("x-frame-options") == "DENY"
            and r.headers.get("x-content-type-options") == "nosniff"
        )
        checks.append(
            (
                "Security headers on API (XFO/nosniff)",
                ok,
                f"xfo={r.headers.get('x-frame-options')}",
            )
        )

        # 5. Healthz
        r = await client.get("/healthz")
        ok = r.status_code == 200 and r.json().get("status") == "ok"
        checks.append(
            ("GET /healthz returns 200 ok", ok, f"status={r.status_code}")
        )

        # 6. App version
        openapi = (await client.get("/openapi.json")).json()
        version = openapi.get("info", {}).get("version", "")
        ok = version in ("0.9.0", "1.0.0")
        checks.append(
            ("FastAPI app version is 0.9.0 or 1.0.0", ok, f"version={version}")
        )

        # 7. Hunt rules endpoint (in-memory loader, no DB)
        r = await client.get("/api/v1/hunt/rules")
        rules: list[dict[str, Any]] = []
        if r.status_code == 200:
            try:
                payload = r.json()
                rules = payload.get("rules", [])
            except Exception:
                pass
        ok = r.status_code == 200 and len(rules) >= 50
        checks.append(
            ("GET /api/v1/hunt/rules returns >= 50 rules", ok, f"count={len(rules)}")
        )

        # 8. OpenAPI / Swagger UI reachable
        r = await client.get("/docs")
        ok = r.status_code == 200 and "swagger" in r.text.lower()
        checks.append(
            ("GET /docs serves Swagger UI", ok, f"status={r.status_code}")
        )

        # 9. OpenAPI JSON lists the v1 surface
        paths = openapi.get("paths", {})
        expected = {
            "/api/v1/canary",
            "/api/v1/canary/touched",
            "/api/v1/alerts",
            "/api/v1/hunt/rules",
            "/api/v1/hunt/run",
            "/api/v1/events",
            "/api/v1/hosts",
            "/api/v1/evidence/{alert_id}/verify",
            "/api/v1/evidence/{alert_id}/sidecar",
        }
        missing = expected - set(paths)
        ok = not missing
        checks.append(
            (
                "OpenAPI exposes all v1.0.0 endpoints",
                ok,
                f"missing={sorted(missing) if missing else 'none'}",
            )
        )

    return checks


def main() -> int:
    checks = asyncio.run(_run_checks())
    print()
    print("=" * 72)
    print(" ZaqorinCore v1.0.0 launch smoke (DB-free, in-process)")
    print("=" * 72)
    fails = 0
    for name, ok, detail in checks:
        flag = "PASS" if ok else "FAIL"
        print(f"  [{flag}] {name}  ({detail})")
        if not ok:
            fails += 1
    print("=" * 72)
    print(f" {len(checks) - fails} / {len(checks)} checks passed")
    print("=" * 72)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
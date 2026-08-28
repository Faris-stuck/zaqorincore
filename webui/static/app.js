// ZaqorinCore Console — minimal SPA. No build step. React 18 via ESM.
import React, { useState, useEffect, useCallback, useMemo } from "react";
import { createRoot } from "react-dom/client";

const API = "/api/v1";

async function apiFetch(path, opts = {}) {
  const r = await fetch(API + path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!r.ok) {
    const text = await r.text().catch(() => "");
    throw new Error(`${r.status} ${r.statusText} — ${text.slice(0, 200)}`);
  }
  if (r.status === 204) return null;
  return r.json();
}

function useHashRoute() {
  const [hash, setHash] = useState(() => window.location.hash.slice(1) || "/");
  useEffect(() => {
    const onChange = () => setHash(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const navigate = (to) => {
    window.location.hash = to;
  };
  return [hash, navigate];
}

function Header({ route }) {
  const nav = (path, label) => (
    <a href={`#${path}`} className={route === path ? "active" : ""}>
      {label}
    </a>
  );
  return (
    <header>
      <h1>ZaqorinCore</h1>
      <span className="ver">v0.9.0</span>
      <nav>
        {nav("/alerts", "Alerts")}
        {nav("/hunt", "Hunt")}
        {nav("/evidence", "Evidence")}
        {nav("/canary", "Canary")}
      </nav>
    </header>
  );
}

// ─── Alerts ───────────────────────────────────────────────────────────────
function AlertsView() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [severity, setSeverity] = useState("");
  const [hostId, setHostId] = useState("");
  const [limit, setLimit] = useState(50);
  const [before, setBefore] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const params = new URLSearchParams();
      if (severity) params.set("severity", severity);
      if (hostId) params.set("host_id", hostId);
      params.set("limit", String(limit));
      if (before) params.set("before", before);
      const qs = params.toString();
      const data = await apiFetch(`/alerts?${qs}`);
      setItems(data);
    } catch (e) {
      setError(e.message);
    }
  }, [severity, hostId, limit, before]);

  useEffect(() => {
    load();
  }, [load]);

  const reset = () => {
    setSeverity("");
    setHostId("");
    setLimit(50);
    setBefore(null);
  };

  return (
    <div>
      <div className="toolbar">
        <input
          placeholder="host_id (uuid)"
          value={hostId}
          onChange={(e) => setHostId(e.target.value)}
        />
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">all severities</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
          <option value="informational">informational</option>
        </select>
        <select
          value={limit}
          onChange={(e) => setLimit(Number(e.target.value))}
        >
          <option value={25}>25</option>
          <option value={50}>50</option>
          <option value={100}>100</option>
          <option value={250}>250</option>
        </select>
        <button onClick={load}>Refresh</button>
        <button onClick={reset}>Reset</button>
        <span className="count">
          {items ? `${items.items.length} of ${items.total ?? "?"} alerts` : ""}
        </span>
      </div>

      {error && <div className="error">{error}</div>}
      {items === null && !error && (
        <div className="loading">Loading alerts…</div>
      )}
      {items && items.items.length === 0 && (
        <div className="empty">No alerts match the current filter.</div>
      )}

      {items &&
        items.items.map((a) => {
          const sev = (a.severity || "medium").toLowerCase();
          const detail = a.detail
            ? JSON.stringify(a.detail, null, 2)
            : null;
          return (
            <div key={a.id} className={`alert sev-${sev}`}>
              <div className="row1">
                <span className={`severity sev-${sev}`}>{sev}</span>
                <span className="summary">{a.summary}</span>
              </div>
              <div className="row2">
                <span>
                  <span className="k">detector: </span>
                  <span className="v">{a.detector || "-"}</span>
                </span>
                <span>
                  <span className="k">host: </span>
                  <span className="v">{a.host_id}</span>
                </span>
                <span>
                  <span className="k">created: </span>
                  <span className="v">
                    {new Date(a.created_at).toLocaleString()}
                  </span>
                </span>
                <span>
                  <span className="k">id: </span>
                  <span className="v">{a.id.slice(0, 8)}</span>
                </span>
              </div>
              {detail && (
                <details>
                  <summary>detail</summary>
                  <pre>{detail}</pre>
                </details>
              )}
            </div>
          );
        })}

      {items && items.next_before && (
        <div className="pagination">
          <button
            onClick={() => setBefore(items.next_before)}
          >
            Older →
          </button>
        </div>
      )}
    </div>
  );
}

// ─── Hunt ─────────────────────────────────────────────────────────────────
function HuntView() {
  const [rules, setRules] = useState(null);
  const [error, setError] = useState(null);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [selectedRule, setSelectedRule] = useState("");
  const [days, setDays] = useState(7);

  const loadRules = useCallback(async () => {
    setError(null);
    try {
      const data = await apiFetch("/hunt/rules");
      setRules(data.rules || []);
      if (!selectedRule && data.rules && data.rules[0]) {
        setSelectedRule(data.rules[0].id);
      }
    } catch (e) {
      setError(e.message);
    }
  }, [selectedRule]);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const run = async () => {
    if (!selectedRule) return;
    setRunning(true);
    setError(null);
    try {
      const data = await apiFetch("/hunt/run", {
        method: "POST",
        body: JSON.stringify({ rule_id: selectedRule, days }),
      });
      setResults(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div>
      <div className="toolbar">
        <select
          value={selectedRule}
          onChange={(e) => setSelectedRule(e.target.value)}
        >
          {rules === null && <option value="">loading…</option>}
          {rules && rules.length === 0 && <option value="">no rules</option>}
          {rules &&
            rules.map((r) => (
              <option key={r.id} value={r.id}>
                {r.id} — {r.title}
              </option>
            ))}
        </select>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
        >
          <option value={1}>last 24h</option>
          <option value={7}>last 7d</option>
          <option value={30}>last 30d</option>
          <option value={90}>last 90d</option>
        </select>
        <button onClick={run} disabled={!selectedRule || running}>
          {running ? "Running…" : "Run hunt"}
        </button>
        <span className="count">
          {rules ? `${rules.length} rules loaded` : ""}
        </span>
      </div>

      {error && <div className="error">{error}</div>}

      {results && (
        <div>
          <div className="toolbar" style={{ marginTop: 16 }}>
            <strong style={{ color: "var(--accent)" }}>
              {results.matches?.length ?? 0} matches
            </strong>
            <span style={{ color: "var(--muted)", fontSize: 12 }}>
              rule: {results.rule_id} — {results.rule_title}
            </span>
          </div>
          {results.matches && results.matches.length > 0 ? (
            results.matches.map((m, i) => (
              <div key={i} className="alert sev-high">
                <div className="row1">
                  <span className="summary">
                    {m.summary || JSON.stringify(m)}
                  </span>
                </div>
                <div className="row2">
                  {Object.entries(m).map(([k, v]) => (
                    <span key={k}>
                      <span className="k">{k}: </span>
                      <span className="v">
                        {typeof v === "string" ? v.slice(0, 40) : JSON.stringify(v)}
                      </span>
                    </span>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <div className="empty">No historical matches found.</div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Evidence ─────────────────────────────────────────────────────────────
function EvidenceView() {
  const [items, setItems] = useState(null);
  const [error, setError] = useState(null);
  const [verifying, setVerifying] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await apiFetch("/evidence");
      setItems(data);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const verify = async (alertId) => {
    setVerifying(alertId);
    setVerifyResult(null);
    try {
      const data = await apiFetch(`/evidence/${alertId}/verify`, {
        method: "POST",
      });
      setVerifyResult({ alertId, ...data });
    } catch (e) {
      setVerifyResult({ alertId, error: e.message });
    } finally {
      setVerifying(null);
    }
  };

  return (
    <div>
      <div className="toolbar">
        <button onClick={load}>Refresh</button>
        <span className="count">
          {items ? `${items.items?.length ?? 0} evidence bundles` : ""}
        </span>
      </div>

      {error && <div className="error">{error}</div>}
      {items === null && !error && (
        <div className="loading">Loading evidence…</div>
      )}
      {items && items.items?.length === 0 && (
        <div className="empty">No evidence bundles submitted yet.</div>
      )}

      {items &&
        items.items?.map((e) => (
          <div key={e.alert_id} className="alert sev-low">
            <div className="row1">
              <span className="severity sev-low">chain</span>
              <span className="summary">
                alert {e.alert_id.slice(0, 8)} — key {e.key_id || "current"}
              </span>
            </div>
            <div className="row2">
              <span>
                <span className="k">host: </span>
                <span className="v">{e.host_id}</span>
              </span>
              <span>
                <span className="k">captured: </span>
                <span className="v">
                  {new Date(e.captured_at).toLocaleString()}
                </span>
              </span>
              <span>
                <span className="k">captured_by: </span>
                <span className="v">{e.captured_by}</span>
              </span>
              <span>
                <span className="k">sha256: </span>
                <span className="v">{e.bundle_sha256?.slice(0, 16)}…</span>
              </span>
            </div>
            <div className="toolbar" style={{ marginTop: 8 }}>
              <button
                onClick={() => verify(e.alert_id)}
                disabled={verifying === e.alert_id}
              >
                {verifying === e.alert_id ? "Verifying…" : "Verify signature"}
              </button>
            </div>
            {verifyResult && verifyResult.alertId === e.alert_id && (
              <div
                className={
                  verifyResult.valid
                    ? "alert sev-low"
                    : "alert sev-critical"
                }
                style={{ marginTop: 8, marginBottom: 0 }}
              >
                <div className="row1">
                  <span className="summary">
                    {verifyResult.error
                      ? `Error: ${verifyResult.error}`
                      : verifyResult.valid
                        ? "Signature valid — chain of custody intact."
                        : "Signature INVALID — evidence has been tampered with!"}
                  </span>
                </div>
              </div>
            )}
          </div>
        ))}
    </div>
  );
}

// ─── Canary ───────────────────────────────────────────────────────────────
function CanaryView() {
  const [canaries, setCanaries] = useState(null);
  const [touches, setTouches] = useState(null);
  const [error, setError] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({
    kind: "file",
    name: "",
    target: "",
  });

  const load = useCallback(async () => {
    setError(null);
    try {
      const [c, t] = await Promise.all([
        apiFetch("/canary"),
        apiFetch("/canary/touched"),
      ]);
      setCanaries(c.items || c.canaries || []);
      setTouches(t.items || t.touched || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const submit = async (e) => {
    e.preventDefault();
    try {
      const payload = { kind: form.kind, name: form.name };
      if (form.kind === "file") payload.path = form.target;
      else if (form.kind === "tcp_socket") payload.port = Number(form.target);
      else if (form.kind === "http_endpoint") payload.url = form.target;
      else if (form.kind === "credential") payload.secret = form.target;
      await apiFetch("/canary", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setShowForm(false);
      setForm({ kind: "file", name: "", target: "" });
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div>
      <div className="toolbar">
        <button onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "+ New canary"}
        </button>
        <button onClick={load}>Refresh</button>
        <span className="count">
          {canaries ? `${canaries.length} active canaries` : ""}
        </span>
      </div>

      {error && <div className="error">{error}</div>}

      {showForm && (
        <form onSubmit={submit} className="alert sev-medium" style={{ marginBottom: 16 }}>
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <select
              value={form.kind}
              onChange={(e) => setForm({ ...form, kind: e.target.value })}
            >
              <option value="file">file</option>
              <option value="tcp_socket">tcp_socket</option>
              <option value="http_endpoint">http_endpoint</option>
              <option value="credential">credential</option>
            </select>
            <input
              placeholder="name (e.g. 'fake_passwords.txt')"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <input
              placeholder={
                form.kind === "file"
                  ? "/path/to/file"
                  : form.kind === "tcp_socket"
                    ? "port (1024-65535)"
                    : form.kind === "http_endpoint"
                      ? "https://..."
                      : "secret string"
              }
              value={form.target}
              onChange={(e) => setForm({ ...form, target: e.target.value })}
              required
            />
            <button type="submit">Create</button>
          </div>
        </form>
      )}

      {canaries === null && !error && (
        <div className="loading">Loading canaries…</div>
      )}
      {canaries && canaries.length === 0 && (
        <div className="empty">
          No canaries deployed. Create one to start catching intruders.
        </div>
      )}

      {canaries && canaries.length > 0 && (
        <div>
          <h3 style={{ color: "var(--muted)", fontSize: 13, marginBottom: 8 }}>
            Active canaries
          </h3>
          {canaries.map((c) => (
            <div key={c.id} className="alert sev-low">
              <div className="row1">
                <span className="severity sev-low">{c.kind}</span>
                <span className="summary">{c.name}</span>
              </div>
              <div className="row2">
                <span>
                  <span className="k">id: </span>
                  <span className="v">{c.id?.slice(0, 8) || "—"}</span>
                </span>
                <span>
                  <span className="k">target: </span>
                  <span className="v">{c.target || c.path || c.url || c.port}</span>
                </span>
                <span>
                  <span className="k">created: </span>
                  <span className="v">
                    {new Date(c.created_at || c.deployed_at).toLocaleString()}
                  </span>
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      {touches && touches.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h3 style={{ color: "var(--critical)", fontSize: 13, marginBottom: 8 }}>
            Touches ({touches.length}) — someone tripped a canary!
          </h3>
          {touches.map((t, i) => (
            <div key={i} className="alert sev-critical">
              <div className="row1">
                <span className="severity sev-critical">touched</span>
                <span className="summary">
                  canary {t.canary_id?.slice(0, 8) || "?"} touched by {t.source || "?"}
                </span>
              </div>
              <div className="row2">
                <span>
                  <span className="k">at: </span>
                  <span className="v">
                    {new Date(t.at || t.touched_at).toLocaleString()}
                  </span>
                </span>
                <span>
                  <span className="k">host: </span>
                  <span className="v">{t.host_id}</span>
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Root ─────────────────────────────────────────────────────────────────
function App() {
  const [route] = useHashRoute();
  let view = null;
  if (route.startsWith("/hunt")) view = <HuntView />;
  else if (route.startsWith("/evidence")) view = <EvidenceView />;
  else if (route.startsWith("/canary")) view = <CanaryView />;
  else view = <AlertsView />;

  return (
    <React.Fragment>
      <Header route={route} />
      <main>{view}</main>
    </React.Fragment>
  );
}

createRoot(document.getElementById("root")).render(<App />);

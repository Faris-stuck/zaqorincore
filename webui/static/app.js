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
      <span className="ver">v3.1.0</span>
      <nav>
        {nav("/alerts", "Alerts")}
        {nav("/agents", "Agents")}
        {nav("/hunt", "Hunt")}
        {nav("/evidence", "Evidence")}
        {nav("/rules", "Rules")}
        {nav("/canary", "Canary")}
        {nav("/sources", "Sources")}
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

// ─── Agents ──────────────────────────────────────────────────────────────
const LOG_SOURCES = [
  { id: "auth_log", label: "auth.log (SSH logins, sudo)" },
  { id: "syslog", label: "syslog (general)" },
  { id: "auditd", label: "auditd (kernel/LSM)" },
  { id: "osquery", label: "osquery results" },
  { id: "journald", label: "systemd journald" },
  { id: "cron", label: "cron jobs" },
  { id: "process_exec", label: "process execution" },
  { id: "network_conn", label: "network connections" },
  { id: "dns_queries", label: "DNS queries" },
  { id: "file_events", label: "file integrity" },
];

const OS_OPTIONS = ["linux", "darwin", "windows"];
const RESPONSE_OPTIONS = [
  { id: "auto_isolate", label: "Auto-isolate on critical alert" },
  { id: "auto_quarantine", label: "Auto-quarantine file evidence" },
  { id: "auto_collect", label: "Auto-collect evidence bundle" },
  { id: "notify_soc", label: "Notify SOC channel" },
];

function AgentsView() {
  const [tab, setTab] = useState("list"); // list | provision
  const [agents, setAgents] = useState(null);
  const [error, setError] = useState(null);
  const [provisioning, setProvisioning] = useState(false);
  const [installCmd, setInstallCmd] = useState("");
  const [tomlPreview, setTomlPreview] = useState("");
  const [form, setForm] = useState({
    host_id: "",
    display: "",
    os: "linux",
    tags: "",
    log_sources: ["auth_log", "syslog", "auditd"],
    auto_response: ["auto_collect"],
  });

  const loadAgents = useCallback(async () => {
    setError(null);
    try {
      const data = await apiFetch("/agents");
      setAgents(data.items || data.agents || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    if (tab === "list") loadAgents();
  }, [tab, loadAgents]);

  const toggleLog = (id) => {
    setForm((f) => ({
      ...f,
      log_sources: f.log_sources.includes(id)
        ? f.log_sources.filter((x) => x !== id)
        : [...f.log_sources, id],
    }));
  };

  const toggleResponse = (id) => {
    setForm((f) => ({
      ...f,
      auto_response: f.auto_response.includes(id)
        ? f.auto_response.filter((x) => x !== id)
        : [...f.auto_response, id],
    }));
  };

  const doDryRun = async () => {
    setError(null);
    setProvisioning(true);
    try {
      const payload = {
        host_id: form.host_id || `host-${Date.now()}`,
        display: form.display || "new-agent",
        os: form.os,
        tags: form.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        log_sources: form.log_sources,
        auto_response: form.auto_response,
      };
      const data = await apiFetch("/agents/provision/dry-run", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setInstallCmd(data.install_command || "");
      setTomlPreview(data.toml || data.config || "");
    } catch (e) {
      setError(e.message);
    } finally {
      setProvisioning(false);
    }
  };

  const copyCmd = () => {
    if (!installCmd) return;
    navigator.clipboard.writeText(installCmd).catch(() => {});
  };

  const downloadToml = () => {
    if (!tomlPreview) return;
    const blob = new Blob([tomlPreview], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "agent.toml";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="toolbar">
        <button
          onClick={() => setTab("list")}
          className={tab === "list" ? "active" : ""}
        >
          Installed agents
        </button>
        <button
          onClick={() => setTab("provision")}
          className={tab === "provision" ? "active" : ""}
        >
          Provision new
        </button>
        {tab === "list" && (
          <button onClick={loadAgents}>Refresh</button>
        )}
      </div>

      {error && <div className="error">{error}</div>}

      {tab === "list" && (
        <div>
          {agents === null && !error && (
            <div className="loading">Loading agents…</div>
          )}
          {agents && agents.length === 0 && (
            <div className="empty">
              No agents registered yet. Switch to "Provision new" to add one.
            </div>
          )}
          {agents && agents.length > 0 && (
            <table className="grid">
              <thead>
                <tr>
                  <th>host_id</th>
                  <th>display</th>
                  <th>os</th>
                  <th>tags</th>
                  <th>last_seen</th>
                  <th>status</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.host_id || a.id}>
                    <td>{(a.host_id || a.id || "?").slice(0, 8)}</td>
                    <td>{a.display || a.hostname || "—"}</td>
                    <td>{a.os || "—"}</td>
                    <td>{(a.tags || []).join(", ") || "—"}</td>
                    <td>
                      {a.last_seen
                        ? new Date(a.last_seen).toLocaleString()
                        : "never"}
                    </td>
                    <td>{a.status || (a.enrolled ? "enrolled" : "pending")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {tab === "provision" && (
        <div>
          <form
            className="alert sev-low"
            onSubmit={(e) => {
              e.preventDefault();
              doDryRun();
            }}
          >
            <div className="toolbar" style={{ marginBottom: 8 }}>
              <input
                placeholder="host_id (uuid, leave blank to auto-generate)"
                value={form.host_id}
                onChange={(e) =>
                  setForm({ ...form, host_id: e.target.value })
                }
                style={{ minWidth: 280 }}
              />
              <input
                placeholder="display name (e.g. prod-web-01)"
                value={form.display}
                onChange={(e) =>
                  setForm({ ...form, display: e.target.value })
                }
              />
              <select
                value={form.os}
                onChange={(e) => setForm({ ...form, os: e.target.value })}
              >
                {OS_OPTIONS.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
              <input
                placeholder="tags (comma-separated)"
                value={form.tags}
                onChange={(e) => setForm({ ...form, tags: e.target.value })}
                style={{ minWidth: 200 }}
              />
              <button type="submit" disabled={provisioning}>
                {provisioning ? "Generating…" : "Generate"}
              </button>
            </div>

            <div style={{ marginBottom: 12 }}>
              <h4 style={{ color: "var(--muted)", fontSize: 12 }}>
                Log sources
              </h4>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(2, 1fr)",
                  gap: 4,
                }}
              >
                {LOG_SOURCES.map((s) => (
                  <label
                    key={s.id}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 13,
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={form.log_sources.includes(s.id)}
                      onChange={() => toggleLog(s.id)}
                    />
                    {s.label}
                  </label>
                ))}
              </div>
            </div>

            <div>
              <h4 style={{ color: "var(--muted)", fontSize: 12 }}>
                Auto-response
              </h4>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(2, 1fr)",
                  gap: 4,
                }}
              >
                {RESPONSE_OPTIONS.map((r) => (
                  <label
                    key={r.id}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 13,
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={form.auto_response.includes(r.id)}
                      onChange={() => toggleResponse(r.id)}
                    />
                    {r.label}
                  </label>
                ))}
              </div>
            </div>
          </form>

          {(installCmd || tomlPreview) && (
            <div className="alert sev-low" style={{ marginTop: 12 }}>
              <div className="toolbar" style={{ marginBottom: 8 }}>
                <strong>Install command</strong>
                <button onClick={copyCmd} disabled={!installCmd}>
                  Copy
                </button>
                <button onClick={downloadToml} disabled={!tomlPreview}>
                  Download agent.toml
                </button>
              </div>
              {installCmd && (
                <pre
                  style={{
                    background: "var(--bg-2, #111)",
                    padding: 8,
                    overflow: "auto",
                    fontSize: 12,
                  }}
                >
                  {installCmd}
                </pre>
              )}
              {tomlPreview && (
                <details style={{ marginTop: 8 }}>
                  <summary>agent.toml preview</summary>
                  <pre
                    style={{
                      background: "var(--bg-2, #111)",
                      padding: 8,
                      overflow: "auto",
                      fontSize: 12,
                    }}
                  >
                    {tomlPreview}
                  </pre>
                </details>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Rules ────────────────────────────────────────────────────────────────
function RulesView() {
  const [rules, setRules] = useState(null);
  const [error, setError] = useState(null);
  const [editing, setEditing] = useState(null); // null | "new" | ruleId
  const [draft, setDraft] = useState({
    id: "",
    title: "",
    description: "",
    severity: "medium",
    mitre: "",
    logsource: { product: "linux", category: "" },
    selection: '{"EventID":1}',
    condition: "selection",
  });
  const [testInput, setTestInput] = useState("");
  const [testResult, setTestResult] = useState(null);
  const [testing, setTesting] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await apiFetch("/rules");
      setRules(data.items || data.rules || []);
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const startNew = () => {
    setEditing("new");
    setDraft({
      id: "",
      title: "",
      description: "",
      severity: "medium",
      mitre: "",
      logsource: { product: "linux", category: "" },
      selection: '{"EventID":1}',
      condition: "selection",
    });
  };

  const startEdit = (r) => {
    setEditing(r.id);
    setDraft({
      id: r.id,
      title: r.title || "",
      description: r.description || "",
      severity: r.level || r.severity || "medium",
      mitre: Array.isArray(r.tags)
        ? r.tags.find((t) => t.startsWith("attack.")) || ""
        : "",
      logsource: r.logsource || { product: "linux", category: "" },
      selection: JSON.stringify(r.detection?.selection || r.selection || {}),
      condition: r.detection?.condition || r.condition || "selection",
    });
  };

  const save = async (e) => {
    e.preventDefault();
    try {
      let sel;
      try {
        sel = JSON.parse(draft.selection);
      } catch {
        throw new Error("selection must be valid JSON");
      }
      const payload = {
        title: draft.title,
        description: draft.description,
        level: draft.severity,
        tags: draft.mitre ? [draft.mitre] : [],
        logsource: draft.logsource,
        detection: { selection: sel, condition: draft.condition },
      };
      if (editing === "new") {
        await apiFetch("/rules", {
          method: "POST",
          body: JSON.stringify({ id: draft.id, ...payload }),
        });
      } else {
        await apiFetch(`/rules/${editing}`, {
          method: "PUT",
          body: JSON.stringify(payload),
        });
      }
      setEditing(null);
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  const remove = async (id) => {
    if (!confirm(`Delete rule ${id}?`)) return;
    try {
      await apiFetch(`/rules/${id}`, { method: "DELETE" });
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  const runTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      let payload = {};
      const trimmed = testInput.trim();
      if (trimmed) {
        try {
          payload.events = JSON.parse(trimmed);
        } catch {
          payload.log_line = trimmed;
        }
      }
      const data = await apiFetch(
        `/rules/${encodeURIComponent(draft.id || editing || "")}/test`,
        { method: "POST", body: JSON.stringify(payload) }
      );
      setTestResult(data);
    } catch (e) {
      setTestResult({ error: e.message });
    } finally {
      setTesting(false);
    }
  };

  const reloadAll = async () => {
    try {
      await apiFetch("/rules/reload", { method: "POST" });
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div>
      <div className="toolbar">
        <button onClick={startNew}>+ New rule</button>
        <button onClick={load}>Refresh</button>
        <button onClick={reloadAll}>Reload hot-reload</button>
        <span className="count">
          {rules ? `${rules.length} rules` : ""}
        </span>
      </div>

      {error && <div className="error">{error}</div>}

      {editing && (
        <form onSubmit={save} className="alert sev-medium" style={{ marginBottom: 16 }}>
          <div className="toolbar" style={{ marginBottom: 8 }}>
            <input
              placeholder="rule id (slug)"
              value={draft.id}
              onChange={(e) => setDraft({ ...draft, id: e.target.value })}
              disabled={editing !== "new"}
              required
            />
            <input
              placeholder="title"
              value={draft.title}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
              required
              style={{ minWidth: 240 }}
            />
            <select
              value={draft.severity}
              onChange={(e) =>
                setDraft({ ...draft, severity: e.target.value })
              }
            >
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="informational">informational</option>
            </select>
            <input
              placeholder="MITRE tag (e.g. attack.t1059)"
              value={draft.mitre}
              onChange={(e) => setDraft({ ...draft, mitre: e.target.value })}
            />
            <button type="submit">Save</button>
            <button type="button" onClick={() => setEditing(null)}>
              Cancel
            </button>
          </div>
          <input
            placeholder="description"
            value={draft.description}
            onChange={(e) =>
              setDraft({ ...draft, description: e.target.value })
            }
            style={{ width: "100%", marginBottom: 8 }}
          />
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr 1fr",
              gap: 8,
              marginBottom: 8,
            }}
          >
            <input
              placeholder="logsource.product"
              value={draft.logsource.product}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  logsource: { ...draft.logsource, product: e.target.value },
                })
              }
            />
            <input
              placeholder="logsource.category"
              value={draft.logsource.category}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  logsource: { ...draft.logsource, category: e.target.value },
                })
              }
            />
            <input
              placeholder="condition"
              value={draft.condition}
              onChange={(e) =>
                setDraft({ ...draft, condition: e.target.value })
              }
            />
          </div>
          <textarea
            placeholder='selection (JSON, e.g. {"EventID":1})'
            value={draft.selection}
            onChange={(e) => setDraft({ ...draft, selection: e.target.value })}
            rows={4}
            style={{
              width: "100%",
              fontFamily: "monospace",
              fontSize: 12,
              marginBottom: 8,
            }}
          />
          <div className="toolbar" style={{ marginBottom: 0 }}>
            <textarea
              placeholder="Test input — paste log line or JSON event"
              value={testInput}
              onChange={(e) => setTestInput(e.target.value)}
              rows={2}
              style={{ flex: 1, fontFamily: "monospace", fontSize: 12 }}
            />
            <button type="button" onClick={runTest} disabled={testing}>
              {testing ? "Testing…" : "Test rule"}
            </button>
          </div>
          {testResult && (
            <pre
              style={{
                background: "var(--bg-2, #111)",
                padding: 8,
                marginTop: 8,
                fontSize: 12,
              }}
            >
              {JSON.stringify(testResult, null, 2)}
            </pre>
          )}
        </form>
      )}

      {rules === null && !error && (
        <div className="loading">Loading rules…</div>
      )}
      {rules && rules.length === 0 && (
        <div className="empty">No Sigma rules loaded yet.</div>
      )}
      {rules && rules.length > 0 && (
        <div>
          {rules.map((r) => {
            const sev = (r.level || r.severity || "medium").toLowerCase();
            const mitre = Array.isArray(r.tags)
              ? r.tags.find((t) => t.startsWith("attack.")) ||
                r.tags.join(", ")
              : "";
            return (
              <div key={r.id} className={`alert sev-${sev}`}>
                <div className="row1">
                  <span className={`severity sev-${sev}`}>{sev}</span>
                  <span className="summary">
                    {r.title || r.id}
                  </span>
                </div>
                <div className="row2">
                  <span>
                    <span className="k">id: </span>
                    <span className="v">{r.id}</span>
                  </span>
                  {mitre && (
                    <span>
                      <span className="k">mitre: </span>
                      <span className="v">{mitre}</span>
                    </span>
                  )}
                  <span>
                    <span className="k">logsource: </span>
                    <span className="v">
                      {r.logsource
                        ? `${r.logsource.product || ""}${
                            r.logsource.category
                              ? "/" + r.logsource.category
                              : ""
                          }`
                        : "—"}
                    </span>
                  </span>
                </div>
                <div className="toolbar" style={{ marginTop: 8 }}>
                  <button onClick={() => startEdit(r)}>Edit</button>
                  <button onClick={() => remove(r.id)}>Delete</button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Sources ─────────────────────────────────────────────────────────────
const PLATFORMS = [
  {
    id: "cloudflare",
    label: "Cloudflare",
    desc: "Logs from Cloudflare account (zone audit, DNS, HTTP).",
    fields: ["api_token", "zone_id"],
  },
  {
    id: "aws",
    label: "AWS",
    desc: "CloudTrail / GuardDuty / VPC Flow via S3 bucket.",
    fields: ["bucket", "prefix", "region"],
  },
  {
    id: "webhook",
    label: "Webhook",
    desc: "Generic HTTPS ingest endpoint for any source.",
    fields: ["url", "shared_secret"],
  },
  {
    id: "syslog",
    label: "Syslog",
    desc: "RFC5424 syslog over UDP/TCP/TLS on the listen port.",
    fields: ["listen_addr", "transport"],
  },
];

function SourcesView() {
  const [sources, setSources] = useState(null);
  const [status, setStatus] = useState({});
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState("cloudflare");
  const [form, setForm] = useState({});
  const [submitting, setSubmitting] = useState(false);
  const [testing, setTesting] = useState(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const data = await apiFetch("/sources");
      const list = data.items || data.sources || [];
      setSources(list);
      // fetch status per source in parallel
      const statuses = await Promise.all(
        list.map((s) =>
          apiFetch(`/sources/${encodeURIComponent(s.id)}/status`)
            .then((r) => [s.id, r])
            .catch((e) => [s.id, { error: e.message }])
        )
      );
      setStatus(Object.fromEntries(statuses));
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const plat = PLATFORMS.find((p) => p.id === selected);

  const submit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await apiFetch(`/sources/${selected}`, {
        method: "POST",
        body: JSON.stringify(form),
      });
      setForm({});
      load();
    } catch (e2) {
      setError(e2.message);
    } finally {
      setSubmitting(false);
    }
  };

  const test = async (id) => {
    setTesting(id);
    try {
      const r = await apiFetch(
        `/sources/${encodeURIComponent(id)}/test`,
        { method: "POST" }
      );
      setStatus((s) => ({ ...s, [id]: { ...s[id], last_test: r } }));
    } catch (e) {
      setStatus((s) => ({ ...s, [id]: { ...s[id], last_test: { error: e.message } } }));
    } finally {
      setTesting(null);
    }
  };

  const rotate = async (id) => {
    try {
      await apiFetch(`/sources/${encodeURIComponent(id)}/rotate-key`, {
        method: "POST",
      });
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  const remove = async (id) => {
    if (!confirm(`Remove source ${id}?`)) return;
    try {
      await apiFetch(`/sources/${encodeURIComponent(id)}`, {
        method: "DELETE",
      });
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div>
      <div className="toolbar">
        <button onClick={load}>Refresh</button>
        <span className="count">
          {sources ? `${sources.length} sources` : ""}
        </span>
      </div>

      {error && <div className="error">{error}</div>}

      <h3 style={{ color: "var(--muted)", fontSize: 13, marginBottom: 8 }}>
        Add new source
      </h3>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: 8,
          marginBottom: 12,
        }}
      >
        {PLATFORMS.map((p) => (
          <button
            key={p.id}
            onClick={() => {
              setSelected(p.id);
              setForm({});
            }}
            className={`card ${selected === p.id ? "active" : ""}`}
            style={{
              textAlign: "left",
              padding: 10,
              border:
                selected === p.id
                  ? "1px solid var(--accent)"
                  : "1px solid var(--border)",
              background: "var(--bg-1)",
              color: "var(--fg)",
              cursor: "pointer",
            }}
          >
            <strong>{p.label}</strong>
            <div style={{ fontSize: 11, color: "var(--muted)", marginTop: 4 }}>
              {p.desc}
            </div>
          </button>
        ))}
      </div>

      {plat && (
        <form
          onSubmit={submit}
          className="alert sev-low"
          style={{ marginBottom: 16 }}
        >
          <div className="toolbar" style={{ marginBottom: 0 }}>
            {plat.fields.map((f) => (
              <input
                key={f}
                placeholder={f}
                value={form[f] || ""}
                onChange={(e) =>
                  setForm({ ...form, [f]: e.target.value })
                }
                required
                type={f.includes("secret") || f.includes("token") ? "password" : "text"}
              />
            ))}
            <button type="submit" disabled={submitting}>
              {submitting ? "Saving…" : `Add ${plat.label}`}
            </button>
          </div>
        </form>
      )}

      <h3 style={{ color: "var(--muted)", fontSize: 13, marginBottom: 8 }}>
        Configured sources
      </h3>
      {sources === null && !error && (
        <div className="loading">Loading sources…</div>
      )}
      {sources && sources.length === 0 && (
        <div className="empty">No sources configured yet.</div>
      )}
      {sources && sources.length > 0 && (
        <table className="grid">
          <thead>
            <tr>
              <th>id</th>
              <th>platform</th>
              <th>status</th>
              <th>last_event</th>
              <th>actions</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => {
              const st = status[s.id] || {};
              return (
                <tr key={s.id}>
                  <td>{s.id.slice(0, 8)}</td>
                  <td>{s.platform || s.kind || "—"}</td>
                  <td>
                    {st.error
                      ? `error: ${st.error}`
                      : st.connected === true
                        ? "connected"
                        : st.connected === false
                          ? "disconnected"
                          : st.healthy === true
                            ? "healthy"
                            : "—"}
                    {st.last_test && (
                      <div style={{ fontSize: 11, color: "var(--muted)" }}>
                        test:{" "}
                        {st.last_test.ok
                          ? "ok"
                          : st.last_test.error || "failed"}
                      </div>
                    )}
                  </td>
                  <td>
                    {st.last_event_at
                      ? new Date(st.last_event_at).toLocaleString()
                      : s.last_event_at
                        ? new Date(s.last_event_at).toLocaleString()
                        : "never"}
                  </td>
                  <td>
                    <button
                      onClick={() => test(s.id)}
                      disabled={testing === s.id}
                    >
                      {testing === s.id ? "Testing…" : "Test"}
                    </button>{" "}
                    <button onClick={() => rotate(s.id)}>Rotate key</button>{" "}
                    <button onClick={() => remove(s.id)}>Delete</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ─── Root ─────────────────────────────────────────────────────────────────
function App() {
  const [route] = useHashRoute();
  let view = null;
  if (route.startsWith("/agents")) view = <AgentsView />;
  else if (route.startsWith("/hunt")) view = <HuntView />;
  else if (route.startsWith("/evidence")) view = <EvidenceView />;
  else if (route.startsWith("/rules")) view = <RulesView />;
  else if (route.startsWith("/sources")) view = <SourcesView />;
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

/**
 * Dashboard — upload (with log-type selector) + uploads list + Correlate.
 * Author: Matthew Faber
 */
"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import { AuthGate } from "@/components/AuthGate";

type Upload = {
  id: string; filename: string; size_bytes: number; log_type: string;
  status: string; event_count: number; anomaly_count: number; created_at: string;
};

const LOG_TYPES = [
  { v: "auto",     label: "Auto-detect" },
  { v: "proxy",    label: "🌐  Web proxy (ZScaler)" },
  { v: "email",    label: "📧  Email security" },
  { v: "endpoint", label: "🖥  Endpoint / EDR" },
  { v: "cloud",    label: "☁  Cloud (Azure AD)" },
];

function typeBadge(t: string) {
  const map: Record<string, string> = {
    proxy: "🌐 proxy", email: "📧 email", endpoint: "🖥 endpoint", cloud: "☁ cloud",
  };
  return map[t] ?? t;
}
function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function Inner() {
  const router = useRouter();
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [file, setFile] = useState<File | null>(null);
  const [logType, setLogType] = useState("auto");
  const [filterType, setFilterType] = useState("all");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function refresh() {
    const r = await api<{ uploads: Upload[] }>("/uploads");
    setUploads(r.uploads);
  }
  useEffect(() => {
    refresh().catch((e) => setErr(e instanceof ApiError ? e.message : "failed to load"));
  }, []);

  async function upload(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true); setErr(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      fd.append("log_type", logType);
      await api("/uploads", { method: "POST", body: fd });
      setFile(null);
      const el = document.getElementById("file-input") as HTMLInputElement | null;
      if (el) el.value = "";
      await refresh();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "upload failed");
    } finally { setBusy(false); }
  }

  async function remove(id: string) {
    if (!confirm("Delete this upload and all its events?")) return;
    await api(`/uploads/${id}`, { method: "DELETE" });
    await refresh();
  }

  const doneCount = uploads.filter((u) => u.status === "done").length;
  const visibleUploads = filterType === "all"
    ? uploads
    : uploads.filter((u) => u.log_type === filterType);

  return (
    <div className="space-y-6">
      <section className="panel">
        <h2 className="text-lg font-semibold mb-3">Upload a log file</h2>
        <p className="text-sm text-slate-400 mb-3">
          Supported types: web proxy, email security, endpoint / EDR, cloud sign-ins.
          All formats are JSON-Lines (one JSON object per line). See <code>samples/</code>.
        </p>
        <form onSubmit={upload} className="flex items-center gap-3 flex-wrap">
          <select
            className="input max-w-xs"
            value={logType}
            onChange={(e) => setLogType(e.target.value)}
          >
            {LOG_TYPES.map((t) => <option key={t.v} value={t.v}>{t.label}</option>)}
          </select>
          <input
            id="file-input" type="file"
            accept=".log,.json,.txt,.ndjson"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="text-sm text-slate-300"
          />
          <button type="submit" className="btn" disabled={!file || busy}>
            {busy ? "Analyzing…" : "Upload & analyze"}
          </button>
        </form>
        {busy && (
          <p className="text-xs text-slate-400 mt-2">
            Parsing, detecting anomalies (mapped to MITRE ATT&CK), and querying
            Azure AI Foundry for the top-5 analyst narratives…
          </p>
        )}
        {err && <p className="text-red-400 text-sm mt-2">{err}</p>}
      </section>

      <section className="panel">
        <div className="flex items-center justify-between mb-3 flex-wrap gap-3">
          <h2 className="text-lg font-semibold">Previous uploads</h2>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400">Filter:</span>
            {[
              { v: "all",      label: "All" },
              { v: "proxy",    label: "🌐 Proxy" },
              { v: "email",    label: "📧 Email" },
              { v: "endpoint", label: "🖥 Endpoint" },
              { v: "cloud",    label: "☁ Cloud" },
            ].map((f) => (
              <button
                key={f.v}
                onClick={() => setFilterType(f.v)}
                className={`text-xs px-2 py-1 rounded border transition ${
                  filterType === f.v
                    ? "border-accent bg-accent/15 text-accent"
                    : "border-slate-700 text-slate-400 hover:text-slate-200"
                }`}
              >
                {f.label}
              </button>
            ))}
            <button
              className="btn ml-3"
              disabled={doneCount < 2}
              title={doneCount < 2 ? "Upload at least 2 logs to correlate" : "Find cross-log attack chains"}
              onClick={() => router.push("/correlation")}
            >
              🔗 Correlate {doneCount >= 2 ? `(${doneCount} logs)` : ""}
            </button>
          </div>
        </div>
        {uploads.length === 0 ? (
          <p className="text-slate-400 text-sm">
            No uploads yet. Try the alice attack story — upload these three
            files in any order, then click Correlate:
            <span className="block mt-2 text-slate-300">
              📧 sample-email-phishing.log<br/>
              🖥 sample-endpoint-edr.log<br/>
              ☁ sample-cloud-azuread.log
            </span>
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-slate-400 text-left">
              <tr>
                <th className="py-2">File</th><th>Type</th><th>Size</th>
                <th>Events</th><th>Anomalies</th><th>Status</th><th>When</th><th></th>
              </tr>
            </thead>
            <tbody>
              {visibleUploads.map((u) => (
                <tr key={u.id} className="border-t border-slate-800">
                  <td className="py-2">
                    <Link className="text-accent hover:underline" href={`/analysis/${u.id}`}>{u.filename}</Link>
                  </td>
                  <td className="text-slate-300">{typeBadge(u.log_type)}</td>
                  <td>{formatBytes(u.size_bytes)}</td>
                  <td>{u.event_count.toLocaleString()}</td>
                  <td>
                    {u.anomaly_count > 0
                      ? <span className="badge-high">{u.anomaly_count}</span>
                      : <span className="text-slate-500">0</span>}
                  </td>
                  <td className="text-slate-300">{u.status}</td>
                  <td className="text-slate-400">{new Date(u.created_at).toLocaleString()}</td>
                  <td><button className="btn-secondary" onClick={() => remove(u.id)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}

export default function DashboardPage() {
  return <AuthGate><Inner /></AuthGate>;
}

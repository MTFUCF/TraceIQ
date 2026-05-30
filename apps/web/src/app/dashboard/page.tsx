/**
 * Dashboard — upload a new log file + list of previous uploads.
 * Author: Matthew Faber
 */
"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { AuthGate } from "@/components/AuthGate";

type Upload = {
  id: string;
  filename: string;
  size_bytes: number;
  status: string;
  event_count: number;
  anomaly_count: number;
  created_at: string;
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function Inner() {
  const [uploads, setUploads] = useState<Upload[]>([]);
  const [file, setFile] = useState<File | null>(null);
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
    setBusy(true);
    setErr(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      await api("/uploads", { method: "POST", body: fd });
      setFile(null);
      const el = document.getElementById("file-input") as HTMLInputElement | null;
      if (el) el.value = "";
      await refresh();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "upload failed");
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    if (!confirm("Delete this upload and all its events?")) return;
    await api(`/uploads/${id}`, { method: "DELETE" });
    await refresh();
  }

  return (
    <div className="space-y-6">
      <section className="panel">
        <h2 className="text-lg font-semibold mb-3">Upload a log file</h2>
        <p className="text-sm text-slate-400 mb-3">
          ZScaler-style JSON-Lines (.log, .json, .txt) — one JSON object per line.
          See <code>samples/</code> in the repo for examples.
        </p>
        <form onSubmit={upload} className="flex items-center gap-3 flex-wrap">
          <input
            id="file-input"
            type="file"
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
            Parsing, detecting anomalies, and querying Azure AI Foundry for top-N
            explanations. This is synchronous and may take a few seconds…
          </p>
        )}
        {err && <p className="text-red-400 text-sm mt-2">{err}</p>}
      </section>

      <section className="panel">
        <h2 className="text-lg font-semibold mb-3">Previous uploads</h2>
        {uploads.length === 0 ? (
          <p className="text-slate-400 text-sm">No uploads yet. Drop a log file above to get started.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-slate-400 text-left">
              <tr>
                <th className="py-2">File</th>
                <th>Size</th>
                <th>Events</th>
                <th>Anomalies</th>
                <th>Status</th>
                <th>When</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {uploads.map((u) => (
                <tr key={u.id} className="border-t border-slate-800">
                  <td className="py-2">
                    <Link className="text-accent hover:underline" href={`/analysis/${u.id}`}>
                      {u.filename}
                    </Link>
                  </td>
                  <td>{formatBytes(u.size_bytes)}</td>
                  <td>{u.event_count.toLocaleString()}</td>
                  <td>
                    {u.anomaly_count > 0 ? (
                      <span className="badge-high">{u.anomaly_count}</span>
                    ) : (
                      <span className="text-slate-500">0</span>
                    )}
                  </td>
                  <td className="text-slate-300">{u.status}</td>
                  <td className="text-slate-400">
                    {new Date(u.created_at).toLocaleString()}
                  </td>
                  <td>
                    <button className="btn-secondary" onClick={() => remove(u.id)}>
                      Delete
                    </button>
                  </td>
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
  return (
    <AuthGate>
      <Inner />
    </AuthGate>
  );
}

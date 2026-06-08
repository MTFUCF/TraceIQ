/**
 * Analysis view — timeline, summary, MITRE-annotated anomalies, and events.
 * Author: Matthew Faber
 */
"use client";
import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer,
  CartesianGrid, Legend, BarChart, Bar,
} from "recharts";
import { api } from "@/lib/api";
import { AuthGate } from "@/components/AuthGate";
import { MitreBadge } from "@/components/MitreBadge";
import { ChatPanel } from "@/components/ChatPanel";

type MitreMapping = { tacticId: string; tacticName: string; techniqueId: string; techniqueName: string };
type Summary = {
  upload: { id: string; filename: string; log_type: string; status: string; event_count: number; anomaly_count: number };
  stats: { total: string; blocked: string; allowed: string; unique_ips: string; unique_users: string; first_ts: string | null; last_ts: string | null };
  topIps: { client_ip: string; count: number }[];
  topHosts: { host: string; count: number }[];
};
type Anomaly = {
  id: number; rule: string; reason: string; confidence: number; severity: string;
  ai_explanation: string | null; mitre: MitreMapping | null; metadata: Record<string, unknown>;
  event_id: number | null; line_number: number | null; occurred_at: string | null;
};
type EventRow = {
  id: number; source_type: string; line_number: number; occurred_at: string | null;
  user_name: string | null; client_ip: string | null; action: string | null;
  url: string | null; host: string | null; status_code: number | null;
  is_anomaly: boolean;
};
type Bucket = { bucket: string; total: number; blocked: number; anomalies: number };

function Card({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="panel">
      <div className="text-slate-400 text-xs uppercase tracking-wider">{label}</div>
      <div className="text-2xl mt-1 text-slate-100">{value}</div>
    </div>
  );
}
function sevBadge(s: string) { return s === "high" ? "badge-high" : s === "medium" ? "badge-medium" : "badge-low"; }
function typeLabel(t: string) {
  const map: Record<string, string> = { proxy: "🌐 Web Proxy", email: "📧 Email", endpoint: "🖥 Endpoint / EDR", cloud: "☁ Cloud" };
  return map[t] ?? t;
}

function Inner() {
  const { id } = useParams<{ id: string }>();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [buckets, setBuckets] = useState<Bucket[]>([]);
  const [showOnlyAnomalies, setShowOnlyAnomalies] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set(["high", "medium", "low"]));

  useEffect(() => {
    Promise.all([
      api<Summary>(`/uploads/${id}`),
      api<{ anomalies: Anomaly[] }>(`/uploads/${id}/anomalies`),
      api<{ events: EventRow[] }>(`/uploads/${id}/events?limit=500`),
      api<{ buckets: Bucket[] }>(`/uploads/${id}/timeline`),
    ]).then(([s, a, e, t]) => { setSummary(s); setAnomalies(a.anomalies); setEvents(e.events); setBuckets(t.buckets); });
  }, [id]);

  const filteredEvents = useMemo(
    () => (showOnlyAnomalies ? events.filter((e) => e.is_anomaly) : events),
    [events, showOnlyAnomalies],
  );

  const filteredAnomalies = useMemo(
    () => anomalies.filter((a) => severityFilter.has(a.severity)),
    [anomalies, severityFilter],
  );

  function toggleSev(s: string) {
    const next = new Set(severityFilter);
    if (next.has(s)) next.delete(s); else next.add(s);
    setSeverityFilter(next);
  }

  if (!summary) return <p className="text-slate-400">Loading analysis…</p>;
  const s = summary.stats;
  const timelineData = buckets.map((b) => ({
    time: new Date(b.bucket).toLocaleTimeString(),
    total: b.total, blocked: b.blocked, anomalies: b.anomalies,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">
          {summary.upload.filename}
          <span className="ml-3 text-sm text-slate-400 font-normal">{typeLabel(summary.upload.log_type)}</span>
        </h1>
        <p className="text-slate-400 text-sm">
          {s.first_ts && s.last_ts
            ? `Activity from ${new Date(s.first_ts).toLocaleString()} to ${new Date(s.last_ts).toLocaleString()}`
            : "No timestamped events found."}
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card label="Events" value={Number(s.total).toLocaleString()} />
        <Card label="Allowed / Success" value={Number(s.allowed).toLocaleString()} />
        <Card label="Blocked / Failed" value={Number(s.blocked).toLocaleString()} />
        <Card label="Unique IPs" value={Number(s.unique_ips).toLocaleString()} />
        <Card label="Anomalies" value={summary.upload.anomaly_count} />
      </div>

      <section className="panel">
        <h2 className="text-lg font-semibold mb-3">Event timeline (per minute)</h2>
        <div style={{ width: "100%", height: 260 }}>
          <ResponsiveContainer>
            <LineChart data={timelineData}>
              <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
              <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#0b1020", border: "1px solid #334155" }} labelStyle={{ color: "#cbd5e1" }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line type="monotone" dataKey="total" stroke="#5eead4" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="blocked" stroke="#f59e0b" dot={false} />
              <Line type="monotone" dataKey="anomalies" stroke="#ef4444" dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <div className="grid md:grid-cols-2 gap-4">
        <section className="panel">
          <h2 className="text-lg font-semibold mb-3">Top client IPs</h2>
          <div style={{ width: "100%", height: 200 }}>
            <ResponsiveContainer>
              <BarChart data={summary.topIps} layout="vertical">
                <CartesianGrid stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="client_ip" stroke="#64748b" tick={{ fontSize: 11 }} width={110} />
                <Tooltip contentStyle={{ background: "#0b1020", border: "1px solid #334155" }} />
                <Bar dataKey="count" fill="#5eead4" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
        <section className="panel">
          <h2 className="text-lg font-semibold mb-3">Top hosts / apps</h2>
          <div style={{ width: "100%", height: 200 }}>
            <ResponsiveContainer>
              <BarChart data={summary.topHosts} layout="vertical">
                <CartesianGrid stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="host" stroke="#64748b" tick={{ fontSize: 11 }} width={140} />
                <Tooltip contentStyle={{ background: "#0b1020", border: "1px solid #334155" }} />
                <Bar dataKey="count" fill="#818cf8" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <h2 className="text-lg font-semibold">
            Anomalies <span className="text-slate-400 text-sm">({filteredAnomalies.length} / {anomalies.length})</span>
          </h2>
          <div className="flex gap-1.5">
            <span className="text-xs text-slate-400 self-center mr-1">Severity:</span>
            {(["high", "medium", "low"] as const).map((s) => (
              <button
                key={s}
                onClick={() => toggleSev(s)}
                className={`text-xs px-2 py-1 rounded border transition ${
                  severityFilter.has(s)
                    ? "border-accent bg-accent/15 text-accent"
                    : "border-slate-700 text-slate-500 hover:text-slate-300"
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
        {filteredAnomalies.length === 0 ? (
          <p className="text-slate-400 text-sm">
            {anomalies.length === 0 ? "No anomalies detected. 🎉" : "No anomalies match the current filters."}
          </p>
        ) : (
          <ul className="space-y-3">
            {filteredAnomalies.map((a) => (
              <li key={a.id} className="border border-slate-700 rounded p-3 bg-slate-900/60">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={sevBadge(a.severity)}>{a.severity}</span>
                  <code className="text-xs text-slate-400">{a.rule}</code>
                  <span className="text-xs text-slate-500">confidence {(a.confidence * 100).toFixed(0)}%</span>
                  {a.line_number && <span className="text-xs text-slate-500">· line {a.line_number}</span>}
                  {a.mitre && <MitreBadge m={a.mitre} />}
                </div>
                <p className="mt-2 text-slate-100">{a.reason}</p>
                {a.ai_explanation && (
                  <div className="mt-2 p-2 rounded bg-slate-950/80 border border-slate-800">
                    <div className="text-[10px] uppercase tracking-wider text-accent mb-1">
                      AI analyst note (Azure AI Foundry)
                    </div>
                    <p className="text-sm text-slate-200 whitespace-pre-wrap">{a.ai_explanation}</p>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Events</h2>
          <label className="text-sm text-slate-300 inline-flex items-center gap-2">
            <input type="checkbox" checked={showOnlyAnomalies}
              onChange={(e) => setShowOnlyAnomalies(e.target.checked)} />
            Show only anomalies
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-slate-400 text-left">
              <tr>
                <th className="py-1 px-2">#</th><th className="px-2">Time</th>
                <th className="px-2">User</th><th className="px-2">Source IP</th>
                <th className="px-2">Action</th><th className="px-2">Host / App</th>
                <th className="px-2">URL / Process</th><th className="px-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((e) => (
                <tr key={e.id}
                    className={`border-t border-slate-800 ${e.is_anomaly ? "bg-red-950/40" : ""}`}
                    title={e.is_anomaly ? "Flagged by anomaly detector" : undefined}>
                  <td className="py-1 px-2 text-slate-500">{e.line_number}</td>
                  <td className="px-2 text-slate-400">
                    {e.occurred_at ? new Date(e.occurred_at).toLocaleTimeString() : "—"}
                  </td>
                  <td className="px-2">{e.user_name ?? "—"}</td>
                  <td className="px-2">{e.client_ip ?? "—"}</td>
                  <td className="px-2">{e.action ?? "—"}</td>
                  <td className="px-2">{e.host ?? "—"}</td>
                  <td className="px-2 max-w-[280px] truncate">{e.url ?? "—"}</td>
                  <td className="px-2">{e.status_code ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {events.length === 500 && (
          <p className="text-xs text-slate-500 mt-2">
            Showing first 500 events. Pagination is an exercise left for follow-up work.
          </p>
        )}
      </section>

      <ChatPanel
        endpoint={`/uploads/${id}/chat`}
        title="💬 Ask about this upload"
        intro={`Ask anything about ${summary.upload.filename}. The assistant is grounded on this file's events, anomalies, and MITRE mappings.`}
        suggested={[
          "Summarize the top risks in this upload",
          "Which user has the most anomalous activity?",
          "Walk me through the highest-severity anomaly",
          "What investigation steps do you recommend?",
        ]}
      />
    </div>
  );
}

export default function AnalysisPage() {
  return <AuthGate><Inner /></AuthGate>;
}

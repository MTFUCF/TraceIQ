/**
 * Correlation view — cross-upload attack chains.
 *
 * Author: Matthew Faber
 *
 * Calls POST /correlate, then renders each chain as:
 *   - Header: time range, source types covered, anomaly count
 *   - Entities pivoted on (emails, users, IPs, hashes)
 *   - MITRE ATT&CK techniques covered (clickable badges)
 *   - AI-written narrative (Foundry) — the "story"
 *   - Timeline of events (anomalies in red), each labeled with its source type
 */
"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { AuthGate } from "@/components/AuthGate";
import { MitreBadge } from "@/components/MitreBadge";

type Mitre = { tacticId: string; tacticName: string; techniqueId: string; techniqueName: string };
type ChainEvent = {
  uploadId: string; sourceType: string; eventId: string | null;
  occurredAt: string | null; summary: string; isAnomaly: boolean;
  severity: "low" | "medium" | "high" | null; mitre: Mitre | null;
};
type Entity = { type: string; value: string };
type Chain = {
  id: string; entities: Entity[]; sourceTypes: string[];
  startedAt: string | null; endedAt: string | null; anomalyCount: number;
  events: ChainEvent[]; mitre: Mitre[]; aiNarrative: string | null;
};

function sourceBadge(t: string) {
  const map: Record<string, string> = {
    proxy: "🌐 proxy", email: "📧 email", endpoint: "🖥 endpoint", cloud: "☁ cloud",
  };
  return map[t] ?? t;
}
function entityBadge(e: Entity) {
  const icon = ({ email: "✉", user: "👤", ip: "🖧", host: "🏢", sha256: "#️⃣" } as Record<string, string>)[e.type] ?? "•";
  return (
    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 mr-2 mb-1 inline-block">
      {icon} {e.type}: <span className="text-accent">{e.value.length > 24 ? e.value.slice(0, 22) + "…" : e.value}</span>
    </span>
  );
}
function sevDot(s: string | null) {
  if (s === "high") return "bg-red-500";
  if (s === "medium") return "bg-amber-400";
  if (s === "low") return "bg-slate-500";
  return "bg-slate-600";
}

function Inner() {
  const [chains, setChains] = useState<Chain[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  async function run() {
    setBusy(true); setErr(null);
    try {
      const r = await api<{ chains: Chain[] }>("/correlate", { method: "POST", body: JSON.stringify({}) });
      setChains(r.chains);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "correlation failed");
    } finally { setBusy(false); }
  }
  useEffect(() => { run(); }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Cross-log correlation</h1>
          <p className="text-slate-400 text-sm">
            Attack chains linking events across multiple log types via shared
            entities (user, IP, file hash, host) within 24h.
          </p>
        </div>
        <div className="flex gap-2">
          <Link href="/dashboard" className="btn-secondary">← Back to uploads</Link>
          <button className="btn" onClick={run} disabled={busy}>
            {busy ? "Correlating…" : "🔄 Re-correlate"}
          </button>
        </div>
      </div>

      {err && <p className="text-red-400 text-sm">{err}</p>}
      {busy && !chains && (
        <p className="text-slate-400 text-sm">
          Pulling events from every "done" upload, walking the timeline, and asking
          Azure AI Foundry to write a narrative for each chain…
        </p>
      )}
      {chains && chains.length === 0 && (
        <div className="panel">
          <p className="text-slate-300">
            No cross-log chains found. The correlator only surfaces chains that
            span <strong>2+ log types</strong> AND contain at least one
            anomaly — it doesn't repeat the per-upload findings.
          </p>
          <p className="text-slate-400 text-sm mt-2">
            Tip: upload <code>sample-email-phishing.log</code>,&nbsp;
            <code>sample-endpoint-edr.log</code>, and&nbsp;
            <code>sample-cloud-azuread.log</code> together — they tell the
            "alice gets phished" story across all three log types.
          </p>
        </div>
      )}

      {chains && chains.map((c) => (
        <article key={c.id} className="panel space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-lg font-semibold">Attack chain · {c.id}</h2>
            <span className="badge-high">{c.anomalyCount} anomalies</span>
            {c.sourceTypes.map((t) => (
              <span key={t} className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                {sourceBadge(t)}
              </span>
            ))}
            <span className="text-xs text-slate-500">
              {c.startedAt && c.endedAt
                ? `${new Date(c.startedAt).toLocaleString()} → ${new Date(c.endedAt).toLocaleString()}`
                : "no timestamps"}
            </span>
          </div>

          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400 mb-1">Entities pivoted on</div>
            <div>{c.entities.map((e, i) => <span key={i}>{entityBadge(e)}</span>)}</div>
          </div>

          {c.mitre.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wider text-slate-400 mb-1">MITRE ATT&amp;CK techniques</div>
              <div className="flex flex-wrap gap-1.5">{c.mitre.map((m, i) => <MitreBadge key={i} m={m} />)}</div>
            </div>
          )}

          {c.aiNarrative && (
            <div className="p-3 rounded bg-slate-950/80 border border-indigo-500/40">
              <div className="text-[10px] uppercase tracking-wider text-accent mb-1">
                Senior SOC analyst narrative (Azure AI Foundry)
              </div>
              <p className="text-sm text-slate-100 whitespace-pre-wrap">{c.aiNarrative}</p>
            </div>
          )}

          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400 mb-2">Timeline</div>
            <ol className="space-y-2">
              {c.events.map((ev, i) => (
                <li key={i}
                    className={`flex items-start gap-3 text-sm p-2 rounded ${
                      ev.isAnomaly ? "bg-red-950/30 border border-red-900/50" : "bg-slate-900/40"
                    }`}>
                  <span className={`w-2 h-2 rounded-full mt-1.5 ${sevDot(ev.severity)}`}></span>
                  <div className="text-xs text-slate-500 w-28 shrink-0">
                    {ev.occurredAt ? new Date(ev.occurredAt).toLocaleTimeString() : "—"}
                  </div>
                  <div className="text-xs text-slate-400 w-20 shrink-0">{sourceBadge(ev.sourceType)}</div>
                  <div className="flex-1">
                    <div className="text-slate-100">{ev.summary}</div>
                    {ev.mitre && <div className="mt-1"><MitreBadge m={ev.mitre} /></div>}
                  </div>
                  <Link className="text-xs text-accent hover:underline shrink-0"
                        href={`/analysis/${ev.uploadId}`}>open upload →</Link>
                </li>
              ))}
            </ol>
          </div>
        </article>
      ))}
    </div>
  );
}

export default function CorrelationPage() {
  return <AuthGate><Inner /></AuthGate>;
}

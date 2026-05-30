/**
 * Correlation view — cross-upload attack chains with filtering + path graph.
 *
 * Author: Matthew Faber
 *
 * Calls POST /correlate, then renders each chain with:
 *   - Header: time range, source types covered, anomaly count
 *   - Entities pivoted on
 *   - MITRE ATT&CK techniques covered (clickable badges)
 *   - AI-written narrative (Foundry)
 *   - **Attack path graph** (SVG swimlane visualisation — new)
 *   - Filterable event timeline
 *
 * Filters apply at two levels:
 *   - Chain-level: only show chains that contain at least one matching event
 *   - Event-level: hide events within a chain that don't match
 * Both filter on source type, severity, anomaly-only.
 */
"use client";
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { AuthGate } from "@/components/AuthGate";
import { MitreBadge } from "@/components/MitreBadge";
import { AttackPathGraph } from "@/components/AttackPathGraph";

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

const SOURCE_TYPES = ["proxy", "email", "endpoint", "cloud"] as const;
const SEVERITIES = ["high", "medium", "low"] as const;

function sourceBadge(t: string) {
  return ({ proxy: "🌐 proxy", email: "📧 email", endpoint: "🖥 endpoint", cloud: "☁ cloud" } as Record<string, string>)[t] ?? t;
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

  // Filter state — all start permissive.
  const [enabledTypes, setEnabledTypes] = useState<Set<string>>(new Set(SOURCE_TYPES));
  const [enabledSeverities, setEnabledSeverities] = useState<Set<string>>(new Set([...SEVERITIES, "none"]));
  const [anomaliesOnly, setAnomaliesOnly] = useState(false);

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

  function toggle<T extends string>(set: Set<T>, setter: (s: Set<T>) => void, v: T) {
    const next = new Set(set);
    if (next.has(v)) next.delete(v); else next.add(v);
    setter(next);
  }

  function eventMatches(e: ChainEvent): boolean {
    if (!enabledTypes.has(e.sourceType)) return false;
    if (anomaliesOnly && !e.isAnomaly) return false;
    const sev = e.severity ?? "none";
    if (!enabledSeverities.has(sev)) return false;
    return true;
  }

  // Apply filters to chains. A chain stays if it has >=1 matching event,
  // and we filter its event list down to matches.
  const filteredChains = useMemo(() => {
    if (!chains) return null;
    return chains
      .map((c) => ({
        ...c,
        events: c.events.filter(eventMatches),
      }))
      .filter((c) => c.events.length > 0);
  }, [chains, enabledTypes, enabledSeverities, anomaliesOnly]);

  const filterStats = useMemo(() => {
    if (!chains || !filteredChains) return null;
    const totalEvents = chains.reduce((s, c) => s + c.events.length, 0);
    const shownEvents = filteredChains.reduce((s, c) => s + c.events.length, 0);
    return { chains: chains.length, shownChains: filteredChains.length, totalEvents, shownEvents };
  }, [chains, filteredChains]);

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

      {/* ---------- Filter bar ---------- */}
      {chains && chains.length > 0 && (
        <section className="panel">
          <div className="flex flex-wrap gap-4 items-center">
            <div>
              <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">Source type</div>
              <div className="flex gap-1.5">
                {SOURCE_TYPES.map((t) => (
                  <button
                    key={t}
                    onClick={() => toggle(enabledTypes, setEnabledTypes, t)}
                    className={`text-xs px-2 py-1 rounded border transition ${
                      enabledTypes.has(t)
                        ? "border-accent bg-accent/15 text-accent"
                        : "border-slate-700 text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {sourceBadge(t)}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider text-slate-400 mb-1">Severity</div>
              <div className="flex gap-1.5">
                {(["high", "medium", "low", "none"] as const).map((s) => (
                  <button
                    key={s}
                    onClick={() => toggle(enabledSeverities, setEnabledSeverities, s)}
                    className={`text-xs px-2 py-1 rounded border transition ${
                      enabledSeverities.has(s)
                        ? "border-accent bg-accent/15 text-accent"
                        : "border-slate-700 text-slate-500 hover:text-slate-300"
                    }`}
                  >
                    {s === "none" ? "context" : s}
                  </button>
                ))}
              </div>
            </div>
            <label className="text-sm text-slate-300 inline-flex items-center gap-2 self-end pb-1">
              <input
                type="checkbox"
                checked={anomaliesOnly}
                onChange={(e) => setAnomaliesOnly(e.target.checked)}
              />
              Anomalies only
            </label>
            {filterStats && (
              <div className="ml-auto text-xs text-slate-500 self-end pb-1">
                Showing {filterStats.shownChains}/{filterStats.chains} chains ·{" "}
                {filterStats.shownEvents}/{filterStats.totalEvents} events
              </div>
            )}
          </div>
        </section>
      )}

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
      {chains && chains.length > 0 && filteredChains && filteredChains.length === 0 && (
        <p className="text-slate-400 text-sm italic">
          No chains match the current filters. Loosen them above.
        </p>
      )}

      {filteredChains && filteredChains.map((c) => (
        <article key={c.id} className="panel space-y-3">
          <div className="flex items-center gap-3 flex-wrap">
            <h2 className="text-lg font-semibold">Attack chain · {c.id}</h2>
            <span className="badge-high">{c.events.filter((e) => e.isAnomaly).length} anomalies</span>
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

          {/* ---------- Attack path graph ---------- */}
          <div>
            <div className="text-xs uppercase tracking-wider text-slate-400 mb-2">Attack path</div>
            <AttackPathGraph events={c.events} />
          </div>

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

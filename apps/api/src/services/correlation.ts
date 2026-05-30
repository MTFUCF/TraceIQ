/**
 * Cross-upload correlation engine.
 *
 * Author: Matthew Faber
 *
 * The correlator takes ALL uploads belonging to a user (or a selected
 * subset) and finds **attack chains** — sequences of related events that
 * cross log types and tell a coherent story (e.g. phishing email →
 * malware on endpoint → suspicious cloud sign-in).
 *
 * Algorithm:
 *   1. Pool all events (each row tagged with its upload_id and source_type)
 *      and all anomalies across the selected uploads.
 *   2. Extract **entities** from each event/anomaly. Today we pivot on:
 *        - email address     (from email recipient/sender or AAD principal)
 *        - user name         (UPN, email local-part, EDR logged-in user)
 *        - client IP
 *        - file SHA256       (from email attachment or EDR file write)
 *        - hostname / endpoint name
 *      An entity is normalised to lowercase so "Alice@CORP.io" ==
 *      "alice@corp.io".
 *   3. Group events by entity and time. Walk chronologically — when an
 *      event shares an entity with a chain's recent (within 24h) tail, it
 *      joins the chain. Otherwise it seeds a new chain.
 *   4. Keep only chains that touch **2+ source_types** and have at least
 *      one anomaly. Single-source-type chains aren't really "correlations"
 *      — the per-upload analysis already shows them.
 *   5. Rank chains by (anomaly_count desc, distinct_source_types desc,
 *      anomaly_severity_sum desc) and return the top 10.
 *   6. For each chain, ask Azure AI Foundry to write a 4-5 sentence
 *      analyst narrative (best-effort; chain still returned if Foundry is
 *      not configured or fails).
 *
 * Why these design choices?
 *   - "Same entity within 24h" is the simplest definition of correlation
 *     that catches multi-stage attacks (Mandiant's median dwell time for
 *     opportunistic attacks is < 24h) without joining unrelated incidents
 *     weeks apart.
 *   - Filtering to 2+ source_types is what makes the result a CROSS-LOG
 *     finding — that's the value-add over per-file analysis.
 *   - Sequential ordering by anomaly count first means "most evidence
 *     first" which is what an analyst wants on the triage screen.
 */
import { query } from "../db/client.js";
import { explainChain } from "./foundry.js";
import type { MitreMapping } from "./mitre.js";

const WINDOW_MS = 24 * 60 * 60 * 1000;

export interface ChainEvent {
  uploadId: string;
  sourceType: string;
  eventId: string | null;
  anomalyId: string | null;
  occurredAt: string | null;
  summary: string;
  isAnomaly: boolean;
  severity: "low" | "medium" | "high" | null;
  mitre: MitreMapping | null;
}

export interface Entity {
  type: "email" | "user" | "ip" | "host" | "sha256";
  value: string;
}

export interface Chain {
  id: string;
  entities: Entity[];
  sourceTypes: string[];
  startedAt: string | null;
  endedAt: string | null;
  anomalyCount: number;
  events: ChainEvent[];
  mitre: MitreMapping[];
  aiNarrative: string | null;
}

interface PooledEvent {
  uploadId: string;
  sourceType: string;
  eventId: string;
  anomalyId: string | null;
  occurredAt: Date | null;
  userName: string | null;
  clientIp: string | null;
  host: string | null;
  url: string | null;
  action: string | null;
  details: Record<string, unknown> | null;
  isAnomaly: boolean;
  reason: string | null;
  severity: "low" | "medium" | "high" | null;
  mitre: MitreMapping | null;
}

function entitiesFor(e: PooledEvent): Entity[] {
  const out: Entity[] = [];
  if (e.userName) {
    const lc = e.userName.toLowerCase();
    if (lc.includes("@")) out.push({ type: "email", value: lc });
    else out.push({ type: "user", value: lc });
    // also add local-part of an email as a user pivot so an email recipient
    // (alice@corp.io) joins with the EDR logged-in user (alice).
    if (lc.includes("@")) out.push({ type: "user", value: lc.split("@")[0] });
  }
  if (e.clientIp) out.push({ type: "ip", value: e.clientIp });
  if (e.host) out.push({ type: "host", value: e.host.toLowerCase() });
  const sha = (e.details?.attachmentSha256 ?? e.details?.fileSha256) as string | undefined;
  if (sha) out.push({ type: "sha256", value: sha.toLowerCase() });
  return out;
}

function eventSummary(e: PooledEvent): string {
  if (e.isAnomaly && e.reason) return e.reason;
  switch (e.sourceType) {
    case "email": {
      const subj = e.details?.subject ? `"${e.details.subject}"` : "(no subject)";
      return `Email to ${e.userName}: ${subj}${e.action ? ` [${e.action}]` : ""}`;
    }
    case "endpoint": {
      const proc = e.details?.processName ?? e.url ?? "process";
      return `Endpoint ${e.host}: ${proc}${e.action ? ` [${e.action}]` : ""}`;
    }
    case "cloud":
      return `Cloud sign-in: ${e.userName} from ${e.clientIp}${e.action ? ` [${e.action}]` : ""}`;
    case "proxy":
    default:
      return `Proxy ${e.action ?? ""}: ${e.userName ?? ""} -> ${e.host ?? e.url ?? ""}`.trim();
  }
}

export async function correlate(userId: string, uploadIds?: string[]): Promise<Chain[]> {
  // Fetch the set of uploads we'll consider. Only "done" uploads are useful
  // — anything else has no anomalies / events ready.
  const uploadsRes = uploadIds && uploadIds.length > 0
    ? await query<{ id: string }>(
        "SELECT id FROM uploads WHERE user_id=$1 AND status='done' AND id = ANY($2::uuid[])",
        [userId, uploadIds],
      )
    : await query<{ id: string }>(
        "SELECT id FROM uploads WHERE user_id=$1 AND status='done'",
        [userId],
      );
  const ids = uploadsRes.rows.map((r) => r.id);
  if (ids.length === 0) return [];

  // Pull anomalies + their referenced events from each upload. We only
  // include "interesting" non-anomalous events as connectors — joining the
  // full event stream would generate thousands of trivial nodes.
  const rows = await query<any>(
    `SELECT e.upload_id, e.source_type, e.id AS event_id, a.id AS anomaly_id,
            e.occurred_at, e.user_name, e.client_ip, e.host, e.url, e.action,
            e.details,
            (a.id IS NOT NULL) AS is_anomaly,
            a.reason, a.severity, a.mitre
       FROM events e
       LEFT JOIN anomalies a ON a.event_id = e.id
      WHERE e.upload_id = ANY($1::uuid[])
        AND (a.id IS NOT NULL OR e.user_name IS NOT NULL)
      ORDER BY e.occurred_at NULLS LAST, e.id`,
    [ids],
  );

  const pool: PooledEvent[] = rows.rows.map((r) => ({
    uploadId: r.upload_id,
    sourceType: r.source_type,
    eventId: r.event_id,
    anomalyId: r.anomaly_id,
    occurredAt: r.occurred_at ? new Date(r.occurred_at) : null,
    userName: r.user_name,
    clientIp: r.client_ip,
    host: r.host,
    url: r.url,
    action: r.action,
    details: r.details,
    isAnomaly: !!r.is_anomaly,
    reason: r.reason,
    severity: r.severity,
    mitre: r.mitre,
  }));

  // Build chains by walking events in chronological order. For each event,
  // find the most recent chain that shares an entity within the time window.
  // If none, start a new chain.
  type RawChain = {
    id: string;
    entities: Map<string, Entity>; // key = `${type}:${value}`
    events: PooledEvent[];
    sourceTypes: Set<string>;
    lastTs: number;
    mitreById: Map<string, MitreMapping>;
  };
  const chains: RawChain[] = [];

  for (const ev of pool) {
    const ents = entitiesFor(ev);
    if (ents.length === 0) continue;
    const ts = ev.occurredAt?.getTime() ?? 0;

    let joined = false;
    // Iterate chains newest-first for tight locality.
    for (let i = chains.length - 1; i >= 0; i--) {
      const c = chains[i];
      if (ts && c.lastTs && ts - c.lastTs > WINDOW_MS) continue;
      if (ents.some((e) => c.entities.has(`${e.type}:${e.value}`))) {
        for (const e of ents) c.entities.set(`${e.type}:${e.value}`, e);
        c.events.push(ev);
        c.sourceTypes.add(ev.sourceType);
        c.lastTs = ts || c.lastTs;
        if (ev.mitre) c.mitreById.set(ev.mitre.techniqueId, ev.mitre);
        joined = true;
        break;
      }
    }
    if (!joined) {
      const entMap = new Map<string, Entity>();
      for (const e of ents) entMap.set(`${e.type}:${e.value}`, e);
      const mitreMap = new Map<string, MitreMapping>();
      if (ev.mitre) mitreMap.set(ev.mitre.techniqueId, ev.mitre);
      chains.push({
        id: `chain-${chains.length + 1}`,
        entities: entMap,
        events: [ev],
        sourceTypes: new Set([ev.sourceType]),
        lastTs: ts,
        mitreById: mitreMap,
      });
    }
  }

  // Filter to multi-source-type chains with >=1 anomaly, then rank.
  const sevWeight = { low: 1, medium: 2, high: 3 } as const;
  const ranked = chains
    .filter((c) => c.sourceTypes.size >= 2 && c.events.some((e) => e.isAnomaly))
    .map((c) => {
      const anomCount = c.events.filter((e) => e.isAnomaly).length;
      const sevSum = c.events
        .filter((e) => e.isAnomaly && e.severity)
        .reduce((s, e) => s + sevWeight[e.severity!], 0);
      return { c, anomCount, sevSum };
    })
    .sort((a, b) => b.anomCount - a.anomCount || b.c.sourceTypes.size - a.c.sourceTypes.size || b.sevSum - a.sevSum)
    .slice(0, 10);

  // Materialise the public shape.
  const finalChains: Chain[] = ranked.map(({ c }) => {
    const sorted = [...c.events].sort(
      (a, b) => (a.occurredAt?.getTime() ?? 0) - (b.occurredAt?.getTime() ?? 0),
    );
    return {
      id: c.id,
      entities: Array.from(c.entities.values()),
      sourceTypes: Array.from(c.sourceTypes),
      startedAt: sorted[0].occurredAt?.toISOString() ?? null,
      endedAt: sorted[sorted.length - 1].occurredAt?.toISOString() ?? null,
      anomalyCount: sorted.filter((e) => e.isAnomaly).length,
      events: sorted.map((e) => ({
        uploadId: e.uploadId,
        sourceType: e.sourceType,
        eventId: e.eventId,
        anomalyId: e.anomalyId,
        occurredAt: e.occurredAt?.toISOString() ?? null,
        summary: eventSummary(e),
        isAnomaly: e.isAnomaly,
        severity: e.severity,
        mitre: e.mitre,
      })),
      mitre: Array.from(c.mitreById.values()),
      aiNarrative: null,
    };
  });

  // LLM enrichment (best-effort; never blocks).
  for (const ch of finalChains) {
    ch.aiNarrative = await explainChain(ch);
  }

  return finalChains;
}

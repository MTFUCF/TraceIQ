/**
 * Per-upload + per-correlation chat assistant.
 *
 * Author: Matthew Faber
 *
 * Two scopes are supported:
 *   - "upload"      → context is built from one uploads row + its events,
 *                     anomalies, and summary stats.
 *   - "correlation" → context is built from a fresh correlation run across
 *                     all of the user's "done" uploads (AI narratives are
 *                     skipped because the chat itself is the narrative).
 *
 * Context is purposely compact (top-N anomalies / events) so we stay well
 * inside the token budget for gpt-4o-mini. The conversation history is
 * loaded from chat_messages and trimmed to the most recent 16 turns before
 * being passed to the model.
 */
import { query } from "../db/client.js";
import { chatComplete, type ChatMessage } from "./foundry.js";
import { correlate } from "./correlation.js";

const HISTORY_TURNS = 16;

const UPLOAD_SYSTEM = `You are TraceIQ's SOC assistant for a single log upload.
You ground every answer in the structured CONTEXT provided in the next system message: upload metadata, summary stats, top talkers, anomalies (with MITRE ATT&CK mappings), and sample events.
Rules:
  - If the answer isn't in the context, say so plainly; do NOT invent IPs, users, timestamps, or MITRE techniques.
  - Prefer concrete numbers and entity names from the context over generic advice.
  - Keep answers tight (1-4 short paragraphs or a small bulleted list).
  - When you reference an anomaly, mention its rule id and MITRE technique id when available.`;

const CORRELATION_SYSTEM = `You are TraceIQ's senior SOC assistant for cross-log correlation.
The CONTEXT in the next system message contains the user's correlated attack chains: the entities each chain pivots on, the source types covered, MITRE ATT&CK techniques, and a chronological list of events.
Rules:
  - Reason across log types (proxy / email / endpoint / cloud) when the question allows.
  - Cite chain ids (e.g. "chain-2") and MITRE technique ids when relevant.
  - If the user asks about an entity, user, IP, host, or hash, search the provided chains first; if it isn't present, say so.
  - Keep answers tight (1-4 short paragraphs or a small bulleted list).`;

export type ChatScope = "upload" | "correlation";

export interface StoredMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  created_at: string;
}

export async function listMessages(
  userId: string,
  scopeType: ChatScope,
  scopeId: string,
): Promise<StoredMessage[]> {
  const r = await query<StoredMessage>(
    `SELECT id::text, role, content, created_at
       FROM chat_messages
      WHERE user_id=$1 AND scope_type=$2 AND scope_id=$3
      ORDER BY id ASC`,
    [userId, scopeType, scopeId],
  );
  return r.rows;
}

async function persist(
  userId: string,
  scopeType: ChatScope,
  scopeId: string,
  role: "user" | "assistant",
  content: string,
): Promise<StoredMessage> {
  const r = await query<StoredMessage>(
    `INSERT INTO chat_messages (user_id, scope_type, scope_id, role, content)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id::text, role, content, created_at`,
    [userId, scopeType, scopeId, role, content],
  );
  return r.rows[0];
}

// ----------------------------------------------------------------------
// Context builders. Each returns a compact JSON blob that we hand to the
// model as a second system message. We trim aggressively so the prompt
// stays under ~6k tokens even for big uploads.
// ----------------------------------------------------------------------

async function buildUploadContext(userId: string, uploadId: string): Promise<string | null> {
  const u = await query<any>(
    `SELECT id, filename, log_type, status, event_count, anomaly_count,
            size_bytes, created_at, completed_at
       FROM uploads WHERE id=$1 AND user_id=$2`,
    [uploadId, userId],
  );
  if (u.rowCount === 0) return null;

  const stats = await query<any>(
    `SELECT COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE action ILIKE 'block%' OR action ILIKE 'quarantin%' OR action ILIKE 'fail%')::int AS blocked,
            COUNT(*) FILTER (WHERE action ILIKE 'allow%' OR action ILIKE 'deliver%' OR action ILIKE 'success%')::int AS allowed,
            COUNT(DISTINCT client_ip)::int AS unique_ips,
            COUNT(DISTINCT user_name)::int AS unique_users,
            MIN(occurred_at) AS first_ts,
            MAX(occurred_at) AS last_ts
       FROM events WHERE upload_id=$1`,
    [uploadId],
  );
  const topIps = await query<any>(
    `SELECT client_ip, COUNT(*)::int AS count
       FROM events WHERE upload_id=$1 AND client_ip IS NOT NULL
       GROUP BY client_ip ORDER BY count DESC LIMIT 8`,
    [uploadId],
  );
  const topHosts = await query<any>(
    `SELECT host, COUNT(*)::int AS count
       FROM events WHERE upload_id=$1 AND host IS NOT NULL
       GROUP BY host ORDER BY count DESC LIMIT 8`,
    [uploadId],
  );
  const topUsers = await query<any>(
    `SELECT user_name, COUNT(*)::int AS count
       FROM events WHERE upload_id=$1 AND user_name IS NOT NULL
       GROUP BY user_name ORDER BY count DESC LIMIT 8`,
    [uploadId],
  );
  const anomalies = await query<any>(
    `SELECT a.rule, a.reason, a.confidence, a.severity, a.ai_explanation, a.mitre,
            e.line_number, e.occurred_at, e.user_name, e.client_ip, e.host, e.action
       FROM anomalies a LEFT JOIN events e ON e.id = a.event_id
      WHERE a.upload_id=$1
      ORDER BY a.confidence DESC LIMIT 20`,
    [uploadId],
  );
  const sample = await query<any>(
    `SELECT line_number, occurred_at, user_name, client_ip, action, host, url, status_code
       FROM events WHERE upload_id=$1
      ORDER BY line_number LIMIT 30`,
    [uploadId],
  );

  return JSON.stringify({
    upload: u.rows[0],
    summary: stats.rows[0],
    topClientIps: topIps.rows,
    topHosts: topHosts.rows,
    topUsers: topUsers.rows,
    anomalies: anomalies.rows,
    sampleEvents: sample.rows,
  }, null, 2);
}

async function buildCorrelationContext(userId: string): Promise<string | null> {
  const chains = await correlate(userId, undefined, { skipAi: true });
  if (chains.length === 0) {
    // Still build a tiny context so the model can answer "no chains" gracefully.
    const uploads = await query<any>(
      `SELECT id, filename, log_type, status, event_count, anomaly_count
         FROM uploads WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`,
      [userId],
    );
    return JSON.stringify({ chains: [], uploads: uploads.rows }, null, 2);
  }
  const trimmed = chains.slice(0, 6).map((c) => ({
    id: c.id,
    entities: c.entities,
    sourceTypes: c.sourceTypes,
    startedAt: c.startedAt,
    endedAt: c.endedAt,
    anomalyCount: c.anomalyCount,
    mitre: c.mitre,
    events: c.events.slice(0, 25).map((e) => ({
      t: e.occurredAt,
      src: e.sourceType,
      anomaly: e.isAnomaly,
      severity: e.severity,
      summary: e.summary,
      mitre: e.mitre?.techniqueId ?? null,
    })),
  }));
  return JSON.stringify({ chains: trimmed }, null, 2);
}

// ----------------------------------------------------------------------
// Public entry point: handle one chat turn.
// ----------------------------------------------------------------------

export async function handleChatTurn(
  userId: string,
  scopeType: ChatScope,
  scopeId: string,
  userMessage: string,
): Promise<{ user: StoredMessage; assistant: StoredMessage }> {
  const trimmed = userMessage.trim();
  if (!trimmed) throw new Error("message is empty");
  if (trimmed.length > 4000) throw new Error("message too long (4000 char max)");

  const user = await persist(userId, scopeType, scopeId, "user", trimmed);

  const context = scopeType === "upload"
    ? await buildUploadContext(userId, scopeId)
    : await buildCorrelationContext(userId);

  if (context === null && scopeType === "upload") {
    const a = await persist(userId, scopeType, scopeId, "assistant",
      "I couldn't load this upload — it may have been deleted.");
    return { user, assistant: a };
  }

  const history = await listMessages(userId, scopeType, scopeId);
  const recent = history.slice(-HISTORY_TURNS);

  const messages: ChatMessage[] = [
    { role: "system", content: scopeType === "upload" ? UPLOAD_SYSTEM : CORRELATION_SYSTEM },
    { role: "system", content: `CONTEXT (JSON):\n${context ?? "{}"}` },
    ...recent.map((m) => ({ role: m.role as "user" | "assistant", content: m.content })),
  ];

  const reply = await chatComplete(messages, { maxTokens: 600, temperature: 0.2 });
  const assistantText = reply ??
    "Azure AI Foundry isn't reachable right now — I can't answer until the model endpoint is configured.";

  const assistant = await persist(userId, scopeType, scopeId, "assistant", assistantText);
  return { user, assistant };
}

export async function clearMessages(
  userId: string,
  scopeType: ChatScope,
  scopeId: string,
): Promise<void> {
  await query(
    `DELETE FROM chat_messages WHERE user_id=$1 AND scope_type=$2 AND scope_id=$3`,
    [userId, scopeType, scopeId],
  );
}

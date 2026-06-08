/**
 * Azure AI Foundry — anomaly explanations + chain narratives.
 *
 * Author: Matthew Faber
 *
 * --------- Why Azure AI Foundry (vs raw Azure OpenAI)? ---------
 * Azure AI Foundry is Microsoft's unified model platform. A Foundry project
 * gives you one endpoint that fronts many model families (OpenAI, Phi,
 * Llama, Mistral) — switching models becomes a config change, not a code
 * change. We deploy `gpt-4o-mini` inside the Foundry project because it's
 * fast, cheap, and the outputs we need (analyst narratives) are short.
 *
 * --------- Where do we use AI in TraceIQ? ---------
 *   1. Single-anomaly explanation (top-5 by confidence per upload) — short
 *      2-3 sentence analyst note next to each flagged event.
 *   2. Cross-upload chain narrative — for each correlated attack chain the
 *      model writes a 4-5 sentence "what happened, what to do" story. This
 *      is what turns a tabular timeline into something a tier-1 analyst can
 *      paste into a ticket.
 *
 * --------- Failure mode ---------
 * If Foundry isn't configured or errors, we silently return null. Anomalies
 * and chains are still returned with their deterministic data — the AI
 * narrative is purely additive.
 */
import ModelClient, { isUnexpected } from "@azure-rest/ai-inference";
import { AzureKeyCredential } from "@azure/core-auth";
import { config, isFoundryConfigured } from "../config.js";
import type { Anomaly } from "./anomaly.js";
import type { Chain } from "./correlation.js";

const ANOMALY_SYSTEM = `You are a SOC analyst assistant. Given a structured anomaly detected in a log, write a 2-3 sentence narrative for a tier-1 analyst.
Cover: (1) what the activity looks like, (2) what threat it could indicate, (3) one concrete next step. Be concise and factual.`;

const CHAIN_SYSTEM = `You are a senior SOC analyst. Given a CHRONOLOGICAL chain of events that a correlator linked together because they share entities (user, IP, file hash, host) within 24 hours, write a 4-5 sentence incident narrative for the on-call team.
Cover: (1) the likely attack story in order, (2) which MITRE ATT&CK tactics are involved, (3) the affected user/host, (4) two concrete containment / investigation steps. Use plain language. Do NOT invent facts that aren't in the events.`;

function client() {
  return ModelClient(config.foundry.endpoint, new AzureKeyCredential(config.foundry.apiKey));
}

export async function explainAnomaly(a: Anomaly): Promise<string | null> {
  if (!isFoundryConfigured()) return null;
  try {
    const c = client();
    const r = await c.path("/chat/completions").post({
      body: {
        model: config.foundry.deployment,
        messages: [
          { role: "system", content: ANOMALY_SYSTEM },
          {
            role: "user",
            content: `Anomaly:\n${JSON.stringify(
              { rule: a.rule, severity: a.severity, confidence: a.confidence, reason: a.reason, mitre: a.mitre, metadata: a.metadata },
              null, 2,
            )}\n\nWrite the analyst narrative now.`,
          },
        ],
        temperature: 0.2,
        max_tokens: 220,
      },
    });
    if (isUnexpected(r)) { console.warn("[foundry] anomaly response unexpected", r.status); return null; }
    return (r.body.choices?.[0]?.message?.content as string)?.trim() ?? null;
  } catch (err) {
    console.warn("[foundry] anomaly explain failed:", (err as Error).message);
    return null;
  }
}

export async function enrichTopAnomalies(anomalies: Anomaly[], topN = 5): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  if (!isFoundryConfigured() || anomalies.length === 0) return out;
  const ranked = anomalies
    .map((a, i) => ({ a, i }))
    .sort((x, y) => y.a.confidence - x.a.confidence)
    .slice(0, topN);
  for (const { a, i } of ranked) {
    const txt = await explainAnomaly(a);
    if (txt) out.set(i, txt);
  }
  return out;
}

export type ChatRole = "system" | "user" | "assistant";
export interface ChatMessage { role: ChatRole; content: string; }

/**
 * Generic chat-completion call used by the per-upload and per-correlation
 * chatbots. Returns null if Foundry isn't configured or the call fails, so
 * callers can degrade gracefully (we surface a friendly message in the UI).
 */
export async function chatComplete(
  messages: ChatMessage[],
  opts: { maxTokens?: number; temperature?: number } = {},
): Promise<string | null> {
  if (!isFoundryConfigured()) return null;
  try {
    const c = client();
    const r = await c.path("/chat/completions").post({
      body: {
        model: config.foundry.deployment,
        messages,
        temperature: opts.temperature ?? 0.2,
        max_tokens: opts.maxTokens ?? 600,
      },
    });
    if (isUnexpected(r)) { console.warn("[foundry] chat response unexpected", r.status); return null; }
    return (r.body.choices?.[0]?.message?.content as string)?.trim() ?? null;
  } catch (err) {
    console.warn("[foundry] chat failed:", (err as Error).message);
    return null;
  }
}

export async function explainChain(chain: Chain): Promise<string | null> {
  if (!isFoundryConfigured()) return null;
  try {
    const c = client();
    const payload = {
      entities: chain.entities,
      sourceTypes: chain.sourceTypes,
      mitre: chain.mitre,
      events: chain.events.map((e) => ({
        t: e.occurredAt, source: e.sourceType,
        anomaly: e.isAnomaly, severity: e.severity, summary: e.summary,
      })),
    };
    const r = await c.path("/chat/completions").post({
      body: {
        model: config.foundry.deployment,
        messages: [
          { role: "system", content: CHAIN_SYSTEM },
          { role: "user", content: `Attack chain:\n${JSON.stringify(payload, null, 2)}\n\nWrite the incident narrative now.` },
        ],
        temperature: 0.2,
        max_tokens: 400,
      },
    });
    if (isUnexpected(r)) { console.warn("[foundry] chain response unexpected", r.status); return null; }
    return (r.body.choices?.[0]?.message?.content as string)?.trim() ?? null;
  } catch (err) {
    console.warn("[foundry] chain explain failed:", (err as Error).message);
    return null;
  }
}

/**
 * Azure AI Foundry client — anomaly explanations.
 *
 * Author: Matthew Faber
 *
 * --------- Why Azure AI Foundry (vs raw Azure OpenAI)? ---------
 * Azure AI Foundry is Microsoft's unified model platform. A Foundry project
 * gives you:
 *   - A single endpoint that fronts many model families (OpenAI, Phi, Llama,
 *     Mistral) — switching models becomes a config change, not a code change.
 *   - Per-project quota, content safety, evaluation, and observability.
 *   - The same SDKs (`@azure-rest/ai-inference`) talk to ANY Foundry-deployed
 *     model. We deploy `gpt-4o-mini` for this app because it's fast and cheap
 *     and we only need short, structured outputs.
 *
 * --------- Where do we use AI in loginsight? ---------
 *   - Anomaly explanation enrichment (this file). The deterministic detector
 *     (services/anomaly.ts) flags entries and writes a structured `reason`.
 *     For the top-N (default 5) most suspicious anomalies we ask the model
 *     to write a 2-3 sentence analyst-facing narrative: what likely
 *     happened, what to check next, and how severe it is.
 *   - Nothing else. Parsing, detection, scoring are all deterministic.
 *
 * --------- Failure mode ---------
 * If Foundry isn't configured or returns an error, we silently skip the
 * enrichment step — the structured anomalies are still returned to the UI.
 * The app NEVER blocks on the LLM call.
 */
import ModelClient, { isUnexpected } from "@azure-rest/ai-inference";
import { AzureKeyCredential } from "@azure/core-auth";
import { config, isFoundryConfigured } from "../config.js";
import type { Anomaly } from "./anomaly.js";

const SYSTEM_PROMPT = `You are a SOC analyst assistant. Given a structured anomaly detected in a web proxy log, write a 2-3 sentence narrative for a tier-1 analyst.
Cover: (1) what the activity looks like, (2) what threat it could indicate, (3) one concrete next step. Be concise, factual, and avoid jargon the analyst already knows.`;

function buildClient() {
  return ModelClient(
    config.foundry.endpoint,
    new AzureKeyCredential(config.foundry.apiKey),
  );
}

export async function explainAnomaly(a: Anomaly): Promise<string | null> {
  if (!isFoundryConfigured()) return null;
  try {
    const client = buildClient();
    const userPayload = {
      rule: a.rule,
      severity: a.severity,
      confidence: a.confidence,
      reason: a.reason,
      metadata: a.metadata,
    };
    const response = await client.path("/chat/completions").post({
      body: {
        model: config.foundry.deployment,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          {
            role: "user",
            content: `Anomaly:\n${JSON.stringify(userPayload, null, 2)}\n\nWrite the analyst narrative now.`,
          },
        ],
        temperature: 0.2,
        max_tokens: 220,
      },
    });
    if (isUnexpected(response)) {
      console.warn("[foundry] unexpected response", response.status, response.body);
      return null;
    }
    const text = response.body.choices?.[0]?.message?.content;
    return typeof text === "string" ? text.trim() : null;
  } catch (err) {
    console.warn("[foundry] explain failed:", (err as Error).message);
    return null;
  }
}

/**
 * Enrich the top-N most suspicious anomalies (by confidence). We deliberately
 * cap the number of LLM calls — a noisy upload could otherwise rack up tokens.
 */
export async function enrichTopAnomalies(
  anomalies: Anomaly[],
  topN = 5,
): Promise<Map<number, string>> {
  const out = new Map<number, string>();
  if (!isFoundryConfigured() || anomalies.length === 0) return out;
  const ranked = anomalies
    .map((a, i) => ({ a, i }))
    .sort((x, y) => y.a.confidence - x.a.confidence)
    .slice(0, topN);
  // Sequential to keep token-per-second well below quota for the demo tier.
  for (const { a, i } of ranked) {
    const text = await explainAnomaly(a);
    if (text) out.set(i, text);
  }
  return out;
}

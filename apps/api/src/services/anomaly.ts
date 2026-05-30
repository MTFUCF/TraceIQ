/**
 * Statistical anomaly detection.
 *
 * Author: Matthew Faber
 *
 * The objective from the PDF says: highlight anomalous entries, explain why,
 * and provide a confidence score. We implement that with a deterministic
 * rules engine first, then optionally enrich the top results with an LLM
 * narrative (see services/foundry.ts).
 *
 * Why not "just use an LLM"?
 *   - Explainability. SOC analysts need to know *why* an alert fired. A rule
 *     ("client X sent 240 requests in 60s vs a baseline of 12/min") is far
 *     more actionable than "the model thinks it's suspicious".
 *   - Cost & latency. Rules run over a million-row file in seconds with no
 *     API calls. We only spend tokens on the top-N enrichment.
 *   - Determinism. Same input → same anomalies. Easier to test and demo.
 *
 * The LLM's job is to take the structured anomaly and write a short
 * analyst-facing narrative — not to find anomalies on its own.
 *
 * ---- Rules implemented ----
 *  R1  burst_from_ip      One client IP making an outlier-high number of
 *                         requests within a single minute (z-score > 3 on
 *                         that IP's per-minute request distribution).
 *  R2  high_block_ratio   A client IP whose Blocked/Total ratio is >= 50%
 *                         AND has at least 10 requests (filters noise).
 *  R3  malicious_category A request whose urlcategory is in a known-bad
 *                         list (Malware, Phishing, Botnet, Spyware, ...).
 *  R4  rare_user_agent    A User-Agent string seen exactly once across the
 *                         whole file, paired with non-2xx status. Useful for
 *                         detecting bespoke scanner or implant traffic.
 *  R5  large_exfil        A single request with bytesout > 10 MB (possible
 *                         data exfiltration).
 *
 * Each anomaly carries a confidence in [0,1]. Confidences are tuned so the UI
 * can sort and threshold meaningfully — they are NOT calibrated probabilities.
 */
import type { ParsedEvent } from "./parser.js";

export interface Anomaly {
  eventIndex: number | null; // index into the input events array; null => upload-level
  rule: string;
  reason: string;
  confidence: number;        // 0..1
  severity: "low" | "medium" | "high";
  metadata: Record<string, unknown>;
}

const MALICIOUS_CATEGORIES = new Set([
  "Malware",
  "Phishing",
  "Botnet",
  "Spyware",
  "Command and Control",
  "Cryptocurrency Mining",
  "Adware",
]);

function mean(xs: number[]): number {
  return xs.length === 0 ? 0 : xs.reduce((a, b) => a + b, 0) / xs.length;
}

function stdev(xs: number[]): number {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  const v = xs.reduce((s, x) => s + (x - m) ** 2, 0) / (xs.length - 1);
  return Math.sqrt(v);
}

export function detectAnomalies(events: ParsedEvent[]): Anomaly[] {
  const anomalies: Anomaly[] = [];

  // ---------- R1: burst_from_ip ----------
  // Group requests by (ip, minute) and z-score within each IP.
  type Bucket = { eventIndex: number; minuteKey: string };
  const byIp = new Map<string, Map<string, number[]>>(); // ip -> minuteKey -> event indices
  events.forEach((e, idx) => {
    if (!e.clientIp || !e.occurredAt) return;
    const minute = new Date(
      Math.floor(e.occurredAt.getTime() / 60000) * 60000,
    ).toISOString();
    let m = byIp.get(e.clientIp);
    if (!m) {
      m = new Map();
      byIp.set(e.clientIp, m);
    }
    let arr = m.get(minute);
    if (!arr) {
      arr = [];
      m.set(minute, arr);
    }
    arr.push(idx);
  });

  for (const [ip, perMinute] of byIp) {
    const counts = Array.from(perMinute.values()).map((a) => a.length);
    if (counts.length < 3) continue; // not enough history to judge
    const mu = mean(counts);
    const sd = stdev(counts);
    if (sd === 0) continue;
    for (const [minute, idxs] of perMinute) {
      const c = idxs.length;
      const z = (c - mu) / sd;
      if (z > 3 && c >= 20) {
        // Attach to the first event in the burst so the UI can scroll to it.
        anomalies.push({
          eventIndex: idxs[0],
          rule: "burst_from_ip",
          reason: `IP ${ip} made ${c} requests in 1 minute (baseline ${mu.toFixed(
            1,
          )}/min, z=${z.toFixed(1)}).`,
          confidence: Math.min(1, 0.6 + (z - 3) * 0.1),
          severity: z > 6 ? "high" : "medium",
          metadata: { ip, minute, count: c, baseline: mu, z },
        });
      }
    }
  }

  // ---------- R2: high_block_ratio ----------
  type Tally = { total: number; blocked: number; firstIdx: number };
  const ipTally = new Map<string, Tally>();
  events.forEach((e, idx) => {
    if (!e.clientIp) return;
    let t = ipTally.get(e.clientIp);
    if (!t) {
      t = { total: 0, blocked: 0, firstIdx: idx };
      ipTally.set(e.clientIp, t);
    }
    t.total += 1;
    if (e.action && /block/i.test(e.action)) t.blocked += 1;
  });
  for (const [ip, t] of ipTally) {
    if (t.total >= 10) {
      const ratio = t.blocked / t.total;
      if (ratio >= 0.5) {
        anomalies.push({
          eventIndex: t.firstIdx,
          rule: "high_block_ratio",
          reason: `IP ${ip} had ${t.blocked}/${t.total} (${Math.round(
            ratio * 100,
          )}%) requests blocked — possible policy probing or compromised host.`,
          confidence: Math.min(1, 0.5 + ratio * 0.4),
          severity: ratio >= 0.8 ? "high" : "medium",
          metadata: { ip, total: t.total, blocked: t.blocked, ratio },
        });
      }
    }
  }

  // ---------- R3: malicious_category ----------
  events.forEach((e, idx) => {
    if (e.urlCategory && MALICIOUS_CATEGORIES.has(e.urlCategory)) {
      anomalies.push({
        eventIndex: idx,
        rule: "malicious_category",
        reason: `Request to ${e.host ?? e.url ?? "unknown"} categorised as "${e.urlCategory}".`,
        confidence: 0.9,
        severity: "high",
        metadata: { category: e.urlCategory, url: e.url, host: e.host },
      });
    }
  });

  // ---------- R4: rare_user_agent ----------
  const uaCount = new Map<string, number[]>();
  events.forEach((e, idx) => {
    if (!e.userAgent) return;
    let arr = uaCount.get(e.userAgent);
    if (!arr) {
      arr = [];
      uaCount.set(e.userAgent, arr);
    }
    arr.push(idx);
  });
  for (const [ua, idxs] of uaCount) {
    if (idxs.length === 1) {
      const idx = idxs[0];
      const e = events[idx];
      // Pair with a non-2xx response — a lone UA hitting normal pages is noise.
      if (e.statusCode && e.statusCode >= 400) {
        anomalies.push({
          eventIndex: idx,
          rule: "rare_user_agent",
          reason: `User-Agent "${ua}" appears only once in the file and the request returned HTTP ${e.statusCode}.`,
          confidence: 0.55,
          severity: "low",
          metadata: { userAgent: ua, statusCode: e.statusCode },
        });
      }
    }
  }

  // ---------- R5: large_exfil ----------
  const TEN_MB = 10 * 1024 * 1024;
  events.forEach((e, idx) => {
    if (e.bytesOut && e.bytesOut >= TEN_MB) {
      anomalies.push({
        eventIndex: idx,
        rule: "large_exfil",
        reason: `Single request uploaded ${(e.bytesOut / 1024 / 1024).toFixed(
          1,
        )} MB to ${e.host ?? e.url ?? "unknown"} — possible exfiltration.`,
        confidence: 0.75,
        severity: "high",
        metadata: { bytesOut: e.bytesOut, url: e.url, host: e.host },
      });
    }
  });

  return anomalies;
}

/**
 * Anomaly detection — dispatcher + per-source-type detectors.
 *
 * Author: Matthew Faber
 *
 * Each detector is a pure function: ParsedEvent[] -> Anomaly[]. Rules are
 * deterministic; an LLM enrichment pass runs separately for the top-N
 * (see services/foundry.ts).
 *
 * Every Anomaly carries a MITRE ATT&CK mapping (tactic + technique) — both
 * for analyst context in the UI and as a join key for the cross-upload
 * correlator (services/correlation.ts).
 */
import type { ParsedEvent, SourceType } from "./events.js";
import { MITRE_BY_RULE, type MitreMapping } from "./mitre.js";

export interface Anomaly {
  eventIndex: number | null;
  rule: string;
  reason: string;
  confidence: number;
  severity: "low" | "medium" | "high";
  mitre: MitreMapping | null;
  metadata: Record<string, unknown>;
}

function emit(rule: string, partial: Omit<Anomaly, "rule" | "mitre">): Anomaly {
  return { ...partial, rule, mitre: MITRE_BY_RULE[rule] ?? null };
}

function mean(xs: number[]) { return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0; }
function stdev(xs: number[]) {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  return Math.sqrt(xs.reduce((s, x) => s + (x - m) ** 2, 0) / (xs.length - 1));
}

// =====================================================================
// PROXY detectors
// =====================================================================
const MALICIOUS_CATEGORIES = new Set([
  "Malware", "Phishing", "Botnet", "Spyware",
  "Command and Control", "Cryptocurrency Mining", "Adware",
]);

function detectProxy(events: ParsedEvent[]): Anomaly[] {
  const out: Anomaly[] = [];

  // R1: burst_from_ip (z-score OR absolute >= 50/min)
  const byIp = new Map<string, Map<string, number[]>>();
  events.forEach((e, idx) => {
    if (!e.clientIp || !e.occurredAt) return;
    const minute = new Date(Math.floor(e.occurredAt.getTime() / 60000) * 60000).toISOString();
    let m = byIp.get(e.clientIp);
    if (!m) { m = new Map(); byIp.set(e.clientIp, m); }
    let arr = m.get(minute);
    if (!arr) { arr = []; m.set(minute, arr); }
    arr.push(idx);
  });
  for (const [ip, perMin] of byIp) {
    const counts = Array.from(perMin.values()).map((a) => a.length);
    const mu = mean(counts), sd = stdev(counts);
    for (const [minute, idxs] of perMin) {
      const c = idxs.length;
      const zOutlier = counts.length >= 3 && sd > 0 && (c - mu) / sd > 3 && c >= 20;
      const absoluteHigh = c >= 50;
      if (!zOutlier && !absoluteHigh) continue;
      const z = sd > 0 ? (c - mu) / sd : 0;
      out.push(emit("burst_from_ip", {
        eventIndex: idxs[0],
        reason: zOutlier
          ? `IP ${ip} made ${c} requests in 1 minute (baseline ${mu.toFixed(1)}/min, z=${z.toFixed(1)}).`
          : `IP ${ip} made ${c} requests in 1 minute — well above normal browsing.`,
        confidence: zOutlier ? Math.min(1, 0.6 + (z - 3) * 0.1) : Math.min(1, 0.5 + c / 200),
        severity: c >= 100 || z > 6 ? "high" : "medium",
        metadata: { ip, minute, count: c, baseline: mu, z },
      }));
    }
  }

  // R2: high_block_ratio
  const ipTally = new Map<string, { total: number; blocked: number; firstIdx: number }>();
  events.forEach((e, idx) => {
    if (!e.clientIp) return;
    let t = ipTally.get(e.clientIp);
    if (!t) { t = { total: 0, blocked: 0, firstIdx: idx }; ipTally.set(e.clientIp, t); }
    t.total += 1;
    if (e.action && /block/i.test(e.action)) t.blocked += 1;
  });
  for (const [ip, t] of ipTally) {
    if (t.total >= 10 && t.blocked / t.total >= 0.5) {
      const ratio = t.blocked / t.total;
      out.push(emit("high_block_ratio", {
        eventIndex: t.firstIdx,
        reason: `IP ${ip} had ${t.blocked}/${t.total} (${Math.round(ratio * 100)}%) requests blocked — possible policy probing or compromised host.`,
        confidence: Math.min(1, 0.5 + ratio * 0.4),
        severity: ratio >= 0.8 ? "high" : "medium",
        metadata: { ip, total: t.total, blocked: t.blocked, ratio },
      }));
    }
  }

  // R3: malicious_category
  events.forEach((e, idx) => {
    if (e.urlCategory && MALICIOUS_CATEGORIES.has(e.urlCategory)) {
      out.push(emit("malicious_category", {
        eventIndex: idx,
        reason: `Request to ${e.host ?? e.url ?? "unknown"} categorised as "${e.urlCategory}".`,
        confidence: 0.9, severity: "high",
        metadata: { category: e.urlCategory, url: e.url, host: e.host },
      }));
    }
  });

  // R4: rare_user_agent
  const uaCount = new Map<string, number[]>();
  events.forEach((e, idx) => {
    if (!e.userAgent) return;
    let arr = uaCount.get(e.userAgent);
    if (!arr) { arr = []; uaCount.set(e.userAgent, arr); }
    arr.push(idx);
  });
  for (const [ua, idxs] of uaCount) {
    if (idxs.length === 1) {
      const idx = idxs[0]; const e = events[idx];
      if (e.statusCode && e.statusCode >= 400) {
        out.push(emit("rare_user_agent", {
          eventIndex: idx,
          reason: `User-Agent "${ua}" appears only once in the file and the request returned HTTP ${e.statusCode}.`,
          confidence: 0.55, severity: "low",
          metadata: { userAgent: ua, statusCode: e.statusCode },
        }));
      }
    }
  }

  // R5: large_exfil
  const TEN_MB = 10 * 1024 * 1024;
  events.forEach((e, idx) => {
    if (e.bytesOut && e.bytesOut >= TEN_MB) {
      out.push(emit("large_exfil", {
        eventIndex: idx,
        reason: `Single request uploaded ${(e.bytesOut / 1024 / 1024).toFixed(1)} MB to ${e.host ?? e.url ?? "unknown"} — possible exfiltration.`,
        confidence: 0.75, severity: "high",
        metadata: { bytesOut: e.bytesOut, url: e.url, host: e.host },
      }));
    }
  });

  return out;
}

// =====================================================================
// EMAIL detectors
// =====================================================================
function detectEmail(events: ParsedEvent[]): Anomaly[] {
  const out: Anomaly[] = [];
  events.forEach((e, idx) => {
    if (e.urlCategory && /phish/i.test(e.urlCategory)) {
      out.push(emit("phishing_email", {
        eventIndex: idx,
        reason: `Phishing email from ${e.details?.sender ?? "unknown"} to ${e.userName} — subject "${e.details?.subject ?? "(none)"}".`,
        confidence: 0.88, severity: "high",
        metadata: { recipient: e.userName, sender: e.details?.sender, url: e.url, subject: e.details?.subject },
      }));
    }
    if (e.urlCategory && /malware/i.test(e.urlCategory) && e.details?.attachment) {
      out.push(emit("malware_attachment", {
        eventIndex: idx,
        reason: `Email to ${e.userName} carried a malware attachment "${e.details.attachment}" (sha256 ${(e.details.attachmentSha256 as string)?.slice(0, 12) ?? "n/a"}…).`,
        confidence: 0.92, severity: "high",
        metadata: {
          recipient: e.userName, attachment: e.details.attachment,
          attachmentSha256: e.details.attachmentSha256,
        },
      }));
    }
  });
  return out;
}

// =====================================================================
// ENDPOINT detectors
// =====================================================================
const SHELLS = new Set(["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]);
const OFFICE = new Set(["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]);

function detectEndpoint(events: ParsedEvent[]): Anomaly[] {
  const out: Anomaly[] = [];
  events.forEach((e, idx) => {
    const d = e.details ?? {};
    if (e.urlCategory && /malware/i.test(e.urlCategory)) {
      out.push(emit("malware_detected", {
        eventIndex: idx,
        reason: `Malware detected on ${e.host}: family "${d.malwareFamily ?? "unknown"}" — file ${d.fileSha256 ? "sha256 " + (d.fileSha256 as string).slice(0, 12) + "…" : e.url}.`,
        confidence: 0.92, severity: "high",
        metadata: { endpoint: e.host, user: e.userName, file: e.url, sha256: d.fileSha256, family: d.malwareFamily },
      }));
    }
    const parent = (d.parentProcess as string | null)?.toLowerCase();
    const proc = (d.processName as string | null)?.toLowerCase();
    if (parent && proc && OFFICE.has(parent) && SHELLS.has(proc)) {
      out.push(emit("office_spawns_shell", {
        eventIndex: idx,
        reason: `${parent} spawned ${proc} on ${e.host} (user ${e.userName}) — common malicious-macro behaviour.`,
        confidence: 0.82, severity: "high",
        metadata: { endpoint: e.host, user: e.userName, parent, child: proc, commandLine: d.commandLine },
      }));
    }
    if (e.statusCode && e.statusCode >= 70 && proc && !OFFICE.has(parent ?? "")) {
      out.push(emit("suspicious_process", {
        eventIndex: idx,
        reason: `${proc} on ${e.host} scored ${e.statusCode}/100 by EDR.`,
        confidence: Math.min(1, e.statusCode / 100),
        severity: e.statusCode >= 85 ? "high" : "medium",
        metadata: { endpoint: e.host, user: e.userName, process: proc, score: e.statusCode },
      }));
    }
  });
  return out;
}

// =====================================================================
// CLOUD detectors (Azure AD sign-ins)
// =====================================================================
const COUNTRY_LATLON: Record<string, [number, number]> = {
  "US": [37, -95], "GB": [54, -2], "DE": [51, 10], "FR": [46, 2],
  "RU": [60, 100], "CN": [35, 105], "IN": [22, 78], "BR": [-10, -55],
  "AU": [-25, 135], "JP": [36, 138], "ZA": [-29, 24], "CA": [56, -106],
  "NL": [52, 5], "SE": [62, 15], "SG": [1, 103],
};

function haversineKm(a: [number, number], b: [number, number]): number {
  const toRad = (d: number) => (d * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(b[0] - a[0]);
  const dLon = toRad(b[1] - a[1]);
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a[0])) * Math.cos(toRad(b[0])) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(x));
}

function detectCloud(events: ParsedEvent[]): Anomaly[] {
  const out: Anomaly[] = [];

  events.forEach((e, idx) => {
    if (e.urlCategory && /^(high|medium)$/i.test(e.urlCategory)) {
      out.push(emit("high_risk_signin", {
        eventIndex: idx,
        reason: `Azure AD flagged ${e.userName}'s sign-in from ${e.clientIp} (${e.details?.country ?? "?"}) as ${e.urlCategory} risk.`,
        confidence: e.urlCategory.toLowerCase() === "high" ? 0.88 : 0.62,
        severity: e.urlCategory.toLowerCase() === "high" ? "high" : "medium",
        metadata: { user: e.userName, ip: e.clientIp, country: e.details?.country, risk: e.urlCategory },
      }));
    }
  });

  const byUser = new Map<string, { idx: number; t: number; ok: boolean }[]>();
  events.forEach((e, idx) => {
    if (!e.userName || !e.occurredAt) return;
    let arr = byUser.get(e.userName);
    if (!arr) { arr = []; byUser.set(e.userName, arr); }
    arr.push({ idx, t: e.occurredAt.getTime(), ok: e.action === "Success" });
  });
  for (const [user, hits] of byUser) {
    hits.sort((a, b) => a.t - b.t);
    for (let i = 0; i < hits.length; i++) {
      const window = hits.filter((h) => h.t - hits[i].t <= 10 * 60_000 && h.t >= hits[i].t);
      const failed = window.filter((h) => !h.ok).length;
      if (failed >= 8) {
        out.push(emit("failed_login_burst", {
          eventIndex: hits[i].idx,
          reason: `${user} had ${failed} failed sign-ins within 10 minutes — possible password spray / brute force.`,
          confidence: Math.min(1, 0.5 + failed / 30),
          severity: failed >= 20 ? "high" : "medium",
          metadata: { user, failed, windowMinutes: 10 },
        }));
        break;
      }
    }
  }
  for (const [user, hits] of byUser) {
    const ok = hits.filter((h) => h.ok).sort((a, b) => a.t - b.t);
    for (let i = 1; i < ok.length; i++) {
      const a = events[ok[i - 1].idx];
      const b = events[ok[i].idx];
      const cA = a.details?.country as string | null;
      const cB = b.details?.country as string | null;
      if (!cA || !cB || cA === cB) continue;
      const llA = COUNTRY_LATLON[cA]; const llB = COUNTRY_LATLON[cB];
      if (!llA || !llB) continue;
      const km = haversineKm(llA, llB);
      const hours = (ok[i].t - ok[i - 1].t) / 3_600_000;
      if (km > 800 && hours < 2) {
        out.push(emit("impossible_travel", {
          eventIndex: ok[i].idx,
          reason: `${user} signed in from ${cA} then ${cB} (~${Math.round(km)} km) within ${hours.toFixed(1)} h — physically impossible.`,
          confidence: 0.9, severity: "high",
          metadata: { user, from: cA, to: cB, km: Math.round(km), hours },
        }));
      }
    }
  }
  return out;
}

// =====================================================================
// Dispatcher
// =====================================================================
export function detectAnomalies(events: ParsedEvent[], sourceType: SourceType): Anomaly[] {
  switch (sourceType) {
    case "email":    return detectEmail(events);
    case "endpoint": return detectEndpoint(events);
    case "cloud":    return detectCloud(events);
    case "proxy":
    default:         return detectProxy(events);
  }
}

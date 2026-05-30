/**
 * Shared event model used across all log-type parsers.
 *
 * Author: Matthew Faber
 *
 * Every parser produces ParsedEvent[] with the same shape. The detector
 * downstream doesn't care which parser produced the event — it dispatches
 * by sourceType when it needs type-specific logic.
 *
 * `details` is the escape hatch — type-specific fields go here (e.g. email
 * subject, malware family, sign-in country) without polluting the schema.
 */
export type SourceType = "proxy" | "email" | "endpoint" | "cloud";

export interface ParsedEvent {
  sourceType: SourceType;
  lineNumber: number;
  occurredAt: Date | null;
  userName: string | null;     // actor / recipient / principal
  clientIp: string | null;     // source IP (endpoint IP for EDR)
  action: string | null;       // Allowed|Blocked|Detected|Quarantined|Success|Failure
  url: string | null;          // URL / file path / process path
  host: string | null;         // host / endpoint name / app
  urlCategory: string | null;  // proxy category | malware family | app category
  statusCode: number | null;
  bytesOut: number | null;
  bytesIn: number | null;
  userAgent: string | null;
  details: Record<string, unknown> | null;
  rawLine: string;
}

export function safeDate(v: unknown): Date | null {
  if (typeof v !== "string") return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function safeStr(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  return String(v);
}

export function safeInt(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

export function hostFromUrl(url: string | null): string | null {
  if (!url) return null;
  try { return new URL(url).hostname; } catch { return null; }
}

/**
 * ZScaler-style web proxy log parser.
 *
 * Author: Matthew Faber
 *
 * ZScaler customers can pick from many feed formats (key=value, CSV, JSON,
 * tab-delimited). For loginsight we standardise on a JSON-Lines variant —
 * one JSON object per line — because:
 *   1. It's the format ZScaler's NSS recommends for SIEM ingestion.
 *   2. It survives field reordering and missing fields gracefully.
 *   3. It's easy for an analyst to hand-craft a test file.
 *
 * If a line is not valid JSON we tolerate it but still record it as a raw
 * row (status_code/etc. left null). That way one corrupt line doesn't kill
 * an entire upload.
 *
 * Expected fields (all optional except `datetime`):
 *   datetime      ISO 8601 timestamp string
 *   user          username / email
 *   clientip      source IP
 *   action        "Allowed" | "Blocked"
 *   url           full URL requested
 *   host          hostname extracted from URL
 *   urlcategory   ZScaler category (e.g. "Malware", "News")
 *   status        HTTP status code
 *   bytesout      bytes uploaded by client
 *   bytesin       bytes downloaded from origin
 *   useragent     User-Agent string
 */

export interface ParsedEvent {
  lineNumber: number;
  occurredAt: Date | null;
  userName: string | null;
  clientIp: string | null;
  action: string | null;
  url: string | null;
  host: string | null;
  urlCategory: string | null;
  statusCode: number | null;
  bytesOut: number | null;
  bytesIn: number | null;
  userAgent: string | null;
  rawLine: string;
}

function safeDate(v: unknown): Date | null {
  if (typeof v !== "string") return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

function safeStr(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  return String(v);
}

function safeInt(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function hostFromUrl(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname;
  } catch {
    // Tolerate non-absolute URLs (e.g. proxied CONNECT lines).
    return null;
  }
}

export function parseLogText(text: string): ParsedEvent[] {
  const events: ParsedEvent[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    let obj: Record<string, unknown> = {};
    try {
      obj = JSON.parse(line);
    } catch {
      // Keep the raw line so the UI can still surface it, but null out fields.
      events.push({
        lineNumber: i + 1,
        occurredAt: null,
        userName: null,
        clientIp: null,
        action: null,
        url: null,
        host: null,
        urlCategory: null,
        statusCode: null,
        bytesOut: null,
        bytesIn: null,
        userAgent: null,
        rawLine: line,
      });
      continue;
    }
    const url = safeStr(obj.url);
    events.push({
      lineNumber: i + 1,
      occurredAt: safeDate(obj.datetime),
      userName: safeStr(obj.user),
      clientIp: safeStr(obj.clientip),
      action: safeStr(obj.action),
      url,
      host: safeStr(obj.host) ?? hostFromUrl(url),
      urlCategory: safeStr(obj.urlcategory),
      statusCode: safeInt(obj.status),
      bytesOut: safeInt(obj.bytesout),
      bytesIn: safeInt(obj.bytesin),
      userAgent: safeStr(obj.useragent),
      rawLine: line,
    });
  }
  return events;
}

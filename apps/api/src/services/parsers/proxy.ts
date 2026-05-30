/**
 * ZScaler-style web proxy parser (JSON-Lines).
 * Author: Matthew Faber
 *
 * Expected fields (all optional except `datetime`):
 *   datetime, user, clientip, action, url, host, urlcategory,
 *   status, bytesout, bytesin, useragent
 */
import { type ParsedEvent, safeDate, safeStr, safeInt, hostFromUrl } from "../events.js";

export function parseProxyLog(text: string): ParsedEvent[] {
  const out: ParsedEvent[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    let o: Record<string, unknown> = {};
    try { o = JSON.parse(line); } catch {
      out.push({
        sourceType: "proxy", lineNumber: i + 1, occurredAt: null,
        userName: null, clientIp: null, action: null, url: null, host: null,
        urlCategory: null, statusCode: null, bytesOut: null, bytesIn: null,
        userAgent: null, details: null, rawLine: line,
      });
      continue;
    }
    const url = safeStr(o.url);
    out.push({
      sourceType: "proxy",
      lineNumber: i + 1,
      occurredAt: safeDate(o.datetime),
      userName: safeStr(o.user),
      clientIp: safeStr(o.clientip),
      action: safeStr(o.action),
      url,
      host: safeStr(o.host) ?? hostFromUrl(url),
      urlCategory: safeStr(o.urlcategory),
      statusCode: safeInt(o.status),
      bytesOut: safeInt(o.bytesout),
      bytesIn: safeInt(o.bytesin),
      userAgent: safeStr(o.useragent),
      details: null,
      rawLine: line,
    });
  }
  return out;
}

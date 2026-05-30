/**
 * Cloud sign-in / audit log parser (Azure AD shape, JSON-Lines).
 *
 * Author: Matthew Faber
 *
 * Inspired by Azure Active Directory Sign-In logs. One line per sign-in.
 *
 * Expected fields:
 *   datetime, principal           UPN / email
 *   app_display_name              e.g. "Office 365 SharePoint Online"
 *   client_ip
 *   country, city
 *   action                        Success | Failure
 *   status_code                   e.g. 0 (success) or 50126 (bad password)
 *   user_agent
 *   risk_level                    none | low | medium | high
 *   mfa_required                  bool
 *   conditional_access            applied/blocked
 */
import { type ParsedEvent, safeDate, safeStr, safeInt } from "../events.js";

export function parseCloudLog(text: string): ParsedEvent[] {
  const out: ParsedEvent[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    let o: Record<string, unknown> = {};
    try { o = JSON.parse(line); } catch {
      out.push(emptyCloudEvent(i + 1, line));
      continue;
    }
    out.push({
      sourceType: "cloud",
      lineNumber: i + 1,
      occurredAt: safeDate(o.datetime),
      userName: safeStr(o.principal),
      clientIp: safeStr(o.client_ip),
      action: safeStr(o.action),
      url: null,
      host: safeStr(o.app_display_name),
      urlCategory: safeStr(o.risk_level),
      statusCode: safeInt(o.status_code),
      bytesOut: null,
      bytesIn: null,
      userAgent: safeStr(o.user_agent),
      details: {
        country: safeStr(o.country),
        city: safeStr(o.city),
        mfaRequired: typeof o.mfa_required === "boolean" ? o.mfa_required : null,
        conditionalAccess: safeStr(o.conditional_access),
      },
      rawLine: line,
    });
  }
  return out;
}

function emptyCloudEvent(lineNumber: number, raw: string): ParsedEvent {
  return {
    sourceType: "cloud", lineNumber, occurredAt: null,
    userName: null, clientIp: null, action: null, url: null, host: null,
    urlCategory: null, statusCode: null, bytesOut: null, bytesIn: null,
    userAgent: null, details: null, rawLine: raw,
  };
}

/**
 * Email security log parser (JSON-Lines).
 *
 * Author: Matthew Faber
 *
 * Inspired by Microsoft Defender for Office 365 / Mimecast / Proofpoint
 * message-tracking exports. One line per email event.
 *
 * Expected fields:
 *   datetime, recipient, sender, sender_domain, subject, action,
 *   verdict       e.g. Clean | Phishing | Malware | Spam
 *   url           first/primary URL in body (if any)
 *   attachment    filename or null
 *   attachment_sha256
 *   client_ip     sending mail server IP
 */
import { type ParsedEvent, safeDate, safeStr, hostFromUrl } from "../events.js";

export function parseEmailLog(text: string): ParsedEvent[] {
  const out: ParsedEvent[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    let o: Record<string, unknown> = {};
    try { o = JSON.parse(line); } catch {
      out.push(emptyEmailEvent(i + 1, line));
      continue;
    }
    const url = safeStr(o.url);
    out.push({
      sourceType: "email",
      lineNumber: i + 1,
      occurredAt: safeDate(o.datetime),
      userName: safeStr(o.recipient),               // pivot: recipient address
      clientIp: safeStr(o.client_ip),               // sending MTA IP
      action: safeStr(o.action),                    // Delivered|Quarantined|Blocked
      url,                                          // link inside email
      host: safeStr(o.sender_domain) ?? hostFromUrl(url),
      urlCategory: safeStr(o.verdict),              // Clean|Phishing|Malware
      statusCode: null,
      bytesOut: null,
      bytesIn: null,
      userAgent: null,
      details: {
        sender: safeStr(o.sender),
        subject: safeStr(o.subject),
        attachment: safeStr(o.attachment),
        attachmentSha256: safeStr(o.attachment_sha256),
      },
      rawLine: line,
    });
  }
  return out;
}

function emptyEmailEvent(lineNumber: number, raw: string): ParsedEvent {
  return {
    sourceType: "email", lineNumber, occurredAt: null,
    userName: null, clientIp: null, action: null, url: null, host: null,
    urlCategory: null, statusCode: null, bytesOut: null, bytesIn: null,
    userAgent: null, details: null, rawLine: raw,
  };
}

/**
 * Endpoint / EDR log parser (JSON-Lines).
 *
 * Author: Matthew Faber
 *
 * Inspired by Microsoft Defender for Endpoint advanced hunting exports and
 * CrowdStrike Falcon Data Replicator events. One line per endpoint event.
 *
 * Expected fields:
 *   datetime, endpoint        endpoint hostname
 *   user                      logged-in user
 *   process_name              e.g. "powershell.exe"
 *   command_line              full command line
 *   file_path                 file written / accessed
 *   file_sha256
 *   parent_process            e.g. "outlook.exe"
 *   action                    Detected|Blocked|Allowed
 *   verdict                   Malware|Suspicious|Clean
 *   malware_family            e.g. "Emotet"
 *   severity_score            0..100
 *   src_ip                    endpoint IP if known
 */
import { type ParsedEvent, safeDate, safeStr, safeInt } from "../events.js";

export function parseEndpointLog(text: string): ParsedEvent[] {
  const out: ParsedEvent[] = [];
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    let o: Record<string, unknown> = {};
    try { o = JSON.parse(line); } catch {
      out.push(emptyEndpointEvent(i + 1, line));
      continue;
    }
    out.push({
      sourceType: "endpoint",
      lineNumber: i + 1,
      occurredAt: safeDate(o.datetime),
      userName: safeStr(o.user),
      clientIp: safeStr(o.src_ip),
      action: safeStr(o.action),
      url: safeStr(o.file_path) ?? safeStr(o.process_name),
      host: safeStr(o.endpoint),
      urlCategory: safeStr(o.verdict) ?? safeStr(o.malware_family),
      statusCode: safeInt(o.severity_score),
      bytesOut: null,
      bytesIn: null,
      userAgent: null,
      details: {
        processName: safeStr(o.process_name),
        parentProcess: safeStr(o.parent_process),
        commandLine: safeStr(o.command_line),
        fileSha256: safeStr(o.file_sha256),
        malwareFamily: safeStr(o.malware_family),
      },
      rawLine: line,
    });
  }
  return out;
}

function emptyEndpointEvent(lineNumber: number, raw: string): ParsedEvent {
  return {
    sourceType: "endpoint", lineNumber, occurredAt: null,
    userName: null, clientIp: null, action: null, url: null, host: null,
    urlCategory: null, statusCode: null, bytesOut: null, bytesIn: null,
    userAgent: null, details: null, rawLine: raw,
  };
}

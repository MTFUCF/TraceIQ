/**
 * Parser dispatcher.
 *
 * Author: Matthew Faber
 *
 * Each supported log type has its own parser in services/parsers/*.ts. The
 * dispatcher picks one based on the SourceType the user (or auto-detect)
 * chose at upload time.
 */
import type { ParsedEvent, SourceType } from "./events.js";
import { parseProxyLog } from "./parsers/proxy.js";
import { parseEmailLog } from "./parsers/email.js";
import { parseEndpointLog } from "./parsers/endpoint.js";
import { parseCloudLog } from "./parsers/cloud.js";

export const SUPPORTED_LOG_TYPES: SourceType[] = ["proxy", "email", "endpoint", "cloud"];

export function detectLogType(text: string): SourceType {
  const lines = text.split(/\r?\n/).filter((l) => l.trim()).slice(0, 20);
  let email = 0, endpoint = 0, cloud = 0, proxy = 0;
  for (const line of lines) {
    try {
      const o = JSON.parse(line);
      if (o.recipient || o.subject || o.sender) email++;
      else if (o.process_name || o.process || o.file_path || o.endpoint || o.severity_score) endpoint++;
      else if (o.signin_id || o.app_display_name || o.country || (o.principal && o.location)) cloud++;
      else proxy++;
    } catch { /* ignore */ }
  }
  const counts: [SourceType, number][] = [
    ["email", email], ["endpoint", endpoint], ["cloud", cloud], ["proxy", proxy],
  ];
  counts.sort((a, b) => b[1] - a[1]);
  return counts[0][1] > 0 ? counts[0][0] : "proxy";
}

export function parseLogText(text: string, sourceType: SourceType): ParsedEvent[] {
  switch (sourceType) {
    case "email":    return parseEmailLog(text);
    case "endpoint": return parseEndpointLog(text);
    case "cloud":    return parseCloudLog(text);
    case "proxy":
    default:         return parseProxyLog(text);
  }
}

export type { ParsedEvent, SourceType } from "./events.js";

// Sample log generator.
// Author: Matthew Faber
//
// Run with:  node samples/generate.js
//
// Produces two files in this folder:
//   sample-benign.log      ~300 lines of normal-looking proxy traffic.
//   sample-suspicious.log  ~400 lines with planted anomalies that exercise
//                          every rule in apps/api/src/services/anomaly.ts:
//                            R1 burst_from_ip       (a 60-second burst)
//                            R2 high_block_ratio    (a probing host)
//                            R3 malicious_category  (a "Malware" call)
//                            R4 rare_user_agent     (one-off UA + 4xx)
//                            R5 large_exfil         (single 50 MB POST)
//
// Output format matches the parser in apps/api/src/services/parser.ts —
// one JSON object per line (NDJSON / JSON-Lines).

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

const USERS = ["alice@corp.io", "bob@corp.io", "carol@corp.io", "dave@corp.io"];
const NORMAL_IPS = ["10.0.1.12", "10.0.1.34", "10.0.2.45", "10.0.2.71"];
const NORMAL_HOSTS = [
  ["news.ycombinator.com", "News"],
  ["github.com", "Computer and Internet Info"],
  ["docs.microsoft.com", "Computer and Internet Info"],
  ["www.cnn.com", "News"],
  ["stackoverflow.com", "Computer and Internet Info"],
];
const NORMAL_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function benignLine(t) {
  const [host, cat] = pick(NORMAL_HOSTS);
  const action = Math.random() < 0.95 ? "Allowed" : "Blocked";
  const status = action === "Allowed" ? (Math.random() < 0.97 ? 200 : 304) : 403;
  return {
    datetime: new Date(t).toISOString(),
    user: pick(USERS),
    clientip: pick(NORMAL_IPS),
    action,
    url: `https://${host}/`,
    host,
    urlcategory: cat,
    status,
    bytesout: 400 + Math.floor(Math.random() * 800),
    bytesin: 1500 + Math.floor(Math.random() * 20000),
    useragent: NORMAL_UA,
  };
}

function build(count, baseTs) {
  const lines = [];
  for (let i = 0; i < count; i++) {
    lines.push(JSON.stringify(benignLine(baseTs + i * 1500))); // ~40/min
  }
  return lines;
}

// --- benign file ---
const baseBenign = Date.parse("2025-04-12T13:00:00Z");
const benign = build(300, baseBenign);
writeFileSync(path.join(here, "sample-benign.log"), benign.join("\n") + "\n");

// --- suspicious file: start with the same benign baseline, then inject ---
const baseSus = Date.parse("2025-04-12T15:00:00Z");
const sus = build(300, baseSus);

// R1: burst_from_ip — 60 requests in ~45 seconds from 10.0.99.99
const burstBase = baseSus + 60_000;
for (let i = 0; i < 60; i++) {
  sus.push(JSON.stringify({
    datetime: new Date(burstBase + i * 700).toISOString(),
    user: "scanner@corp.io",
    clientip: "10.0.99.99",
    action: "Allowed",
    url: `https://api.internal.corp.io/users/${i}`,
    host: "api.internal.corp.io",
    urlcategory: "Computer and Internet Info",
    status: 200,
    bytesout: 200,
    bytesin: 1200,
    useragent: NORMAL_UA,
  }));
}

// R2: high_block_ratio — 10.0.99.42 hits 15 blocked URLs, 2 allowed
for (let i = 0; i < 15; i++) {
  sus.push(JSON.stringify({
    datetime: new Date(baseSus + 180_000 + i * 4000).toISOString(),
    user: "mallory@corp.io",
    clientip: "10.0.99.42",
    action: "Blocked",
    url: `https://torrents${i}.example.net/`,
    host: `torrents${i}.example.net`,
    urlcategory: "Peer to Peer",
    status: 403,
    bytesout: 320, bytesin: 0,
    useragent: NORMAL_UA,
  }));
}
for (let i = 0; i < 2; i++) {
  sus.push(JSON.stringify({
    datetime: new Date(baseSus + 240_000 + i * 4000).toISOString(),
    user: "mallory@corp.io",
    clientip: "10.0.99.42",
    action: "Allowed",
    url: "https://github.com/",
    host: "github.com",
    urlcategory: "Computer and Internet Info",
    status: 200,
    bytesout: 400, bytesin: 8000,
    useragent: NORMAL_UA,
  }));
}

// R3: malicious_category — single Malware hit
sus.push(JSON.stringify({
  datetime: new Date(baseSus + 300_000).toISOString(),
  user: "dave@corp.io",
  clientip: "10.0.1.34",
  action: "Blocked",
  url: "https://evil.example.com/payload.exe",
  host: "evil.example.com",
  urlcategory: "Malware",
  status: 403,
  bytesout: 380, bytesin: 0,
  useragent: NORMAL_UA,
}));

// R4: rare_user_agent — one-off scanner UA with HTTP 404
sus.push(JSON.stringify({
  datetime: new Date(baseSus + 320_000).toISOString(),
  user: "alice@corp.io",
  clientip: "10.0.1.12",
  action: "Allowed",
  url: "https://intranet.corp.io/admin",
  host: "intranet.corp.io",
  urlcategory: "Computer and Internet Info",
  status: 404,
  bytesout: 280, bytesin: 220,
  useragent: "sqlmap/1.7.2#stable",
}));

// R5: large_exfil — single 50 MB POST to dropbox-like destination
sus.push(JSON.stringify({
  datetime: new Date(baseSus + 340_000).toISOString(),
  user: "bob@corp.io",
  clientip: "10.0.1.34",
  action: "Allowed",
  url: "https://upload.suspicious-share.com/",
  host: "upload.suspicious-share.com",
  urlcategory: "File Hosting",
  status: 200,
  bytesout: 50 * 1024 * 1024,
  bytesin: 220,
  useragent: NORMAL_UA,
}));

writeFileSync(path.join(here, "sample-suspicious.log"), sus.join("\n") + "\n");
console.log("Wrote sample-benign.log and sample-suspicious.log");

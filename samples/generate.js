// Multi-log sample generator.
// Author: Matthew Faber
//
//   node samples/generate.js
//
// Produces five files in this folder:
//   sample-benign.log              ~300 lines of normal proxy traffic
//   sample-suspicious.log          ~400 lines with planted proxy anomalies
//                                  exercising all 5 proxy rules
//   sample-email-phishing.log      Email security log — alice gets a phishing
//                                  email with a malicious attachment
//   sample-endpoint-edr.log        EDR log — alice's endpoint executes the
//                                  attachment; powershell spawned from outlook;
//                                  Defender flags the family as Emotet
//   sample-cloud-azuread.log       Azure AD sign-ins — alice's creds used from
//                                  Russia 2h later (impossible travel) plus a
//                                  failed-login burst
//
// The three "alice" files are deliberately co-timed so the correlator can
// link them into a single attack chain (phishing -> execution -> account
// takeover) spanning all three source types.

import { writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const USERS = ["alice@corp.io", "bob@corp.io", "carol@corp.io", "dave@corp.io"];
const NORMAL_IPS = ["10.0.1.12", "10.0.1.34", "10.0.2.45", "10.0.2.71"];
const NORMAL_HOSTS = [
  ["news.ycombinator.com", "News"], ["github.com", "Computer and Internet Info"],
  ["docs.microsoft.com", "Computer and Internet Info"], ["www.cnn.com", "News"],
  ["stackoverflow.com", "Computer and Internet Info"],
];
const NORMAL_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36";

const pick = (a) => a[Math.floor(Math.random() * a.length)];

// =====================================================================
// PROXY: benign + suspicious
// =====================================================================
function benignLine(t) {
  const [host, cat] = pick(NORMAL_HOSTS);
  const action = Math.random() < 0.95 ? "Allowed" : "Blocked";
  const status = action === "Allowed" ? (Math.random() < 0.97 ? 200 : 304) : 403;
  return {
    datetime: new Date(t).toISOString(),
    user: pick(USERS), clientip: pick(NORMAL_IPS), action,
    url: `https://${host}/`, host, urlcategory: cat, status,
    bytesout: 400 + Math.floor(Math.random() * 800),
    bytesin: 1500 + Math.floor(Math.random() * 20000),
    useragent: NORMAL_UA,
  };
}
function buildProxyBenign(count, baseTs) {
  const out = [];
  for (let i = 0; i < count; i++) out.push(JSON.stringify(benignLine(baseTs + i * 1500)));
  return out;
}

const baseBenign = Date.parse("2025-04-12T13:00:00Z");
writeFileSync(path.join(here, "sample-benign.log"), buildProxyBenign(300, baseBenign).join("\n") + "\n");

const baseSus = Date.parse("2025-04-12T15:00:00Z");
const sus = buildProxyBenign(300, baseSus);
// R1 burst (10.0.99.99, 60 reqs in ~42s)
const burstBase = baseSus + 60_000;
for (let i = 0; i < 60; i++) sus.push(JSON.stringify({
  datetime: new Date(burstBase + i * 700).toISOString(), user: "scanner@corp.io",
  clientip: "10.0.99.99", action: "Allowed",
  url: `https://api.internal.corp.io/users/${i}`, host: "api.internal.corp.io",
  urlcategory: "Computer and Internet Info", status: 200, bytesout: 200, bytesin: 1200, useragent: NORMAL_UA,
}));
// R2 high block ratio (10.0.99.42 — 15 blocked / 2 allowed)
for (let i = 0; i < 15; i++) sus.push(JSON.stringify({
  datetime: new Date(baseSus + 180_000 + i * 4000).toISOString(), user: "mallory@corp.io",
  clientip: "10.0.99.42", action: "Blocked",
  url: `https://torrents${i}.example.net/`, host: `torrents${i}.example.net`,
  urlcategory: "Peer to Peer", status: 403, bytesout: 320, bytesin: 0, useragent: NORMAL_UA,
}));
for (let i = 0; i < 2; i++) sus.push(JSON.stringify({
  datetime: new Date(baseSus + 240_000 + i * 4000).toISOString(), user: "mallory@corp.io",
  clientip: "10.0.99.42", action: "Allowed", url: "https://github.com/",
  host: "github.com", urlcategory: "Computer and Internet Info", status: 200,
  bytesout: 400, bytesin: 8000, useragent: NORMAL_UA,
}));
// R3 malicious category
sus.push(JSON.stringify({
  datetime: new Date(baseSus + 300_000).toISOString(), user: "dave@corp.io",
  clientip: "10.0.1.34", action: "Blocked", url: "https://evil.example.com/payload.exe",
  host: "evil.example.com", urlcategory: "Malware", status: 403,
  bytesout: 380, bytesin: 0, useragent: NORMAL_UA,
}));
// R4 rare UA
sus.push(JSON.stringify({
  datetime: new Date(baseSus + 320_000).toISOString(), user: "alice@corp.io",
  clientip: "10.0.1.12", action: "Allowed", url: "https://intranet.corp.io/admin",
  host: "intranet.corp.io", urlcategory: "Computer and Internet Info", status: 404,
  bytesout: 280, bytesin: 220, useragent: "sqlmap/1.7.2#stable",
}));
// R5 large exfil
sus.push(JSON.stringify({
  datetime: new Date(baseSus + 340_000).toISOString(), user: "bob@corp.io",
  clientip: "10.0.1.34", action: "Allowed", url: "https://upload.suspicious-share.com/",
  host: "upload.suspicious-share.com", urlcategory: "File Hosting", status: 200,
  bytesout: 50 * 1024 * 1024, bytesin: 220, useragent: NORMAL_UA,
}));
writeFileSync(path.join(here, "sample-suspicious.log"), sus.join("\n") + "\n");

// =====================================================================
// The "alice" attack — same day, timestamps line up so the correlator
// links them into one cross-log chain.
// =====================================================================
const ALICE_DAY = Date.parse("2025-04-13T10:00:00Z");
const MALWARE_SHA = "8f3a9bd2c7e514f0a1d6b2e7c4f3a8b1d0e7c6a5f2e1b3d4c5a6b7f8e9d0c1a2";

// ---------- EMAIL ----------
const emailLines = [];
for (let i = 0; i < 25; i++) {
  emailLines.push(JSON.stringify({
    datetime: new Date(ALICE_DAY + i * 5 * 60_000).toISOString(),
    recipient: pick(USERS),
    sender: ["noreply@github.com", "newsletter@hackernews.com", "alerts@docs.microsoft.com"][i % 3],
    sender_domain: ["github.com", "hackernews.com", "docs.microsoft.com"][i % 3],
    subject: ["Your weekly digest", "PR opened on your repo", "Service health update"][i % 3],
    action: "Delivered", verdict: "Clean",
    url: null, attachment: null, attachment_sha256: null,
    client_ip: ["140.82.114.6", "192.0.2.10", "20.190.190.10"][i % 3],
  }));
}
// the malicious one — landed in alice's inbox at 10:14
emailLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 14 * 60_000).toISOString(),
  recipient: "alice@corp.io",
  sender: "ceo-quick-question@corp-io.support",
  sender_domain: "corp-io.support",
  subject: "Urgent — invoice attached, please review today",
  action: "Delivered", verdict: "Phishing",
  url: "http://evil.example.com/login?ref=corp",
  attachment: "Invoice_2025-04.docm",
  attachment_sha256: MALWARE_SHA,
  client_ip: "185.220.101.5",
}));
emailLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 14 * 60_000 + 1000).toISOString(),
  recipient: "alice@corp.io",
  sender: "ceo-quick-question@corp-io.support",
  sender_domain: "corp-io.support",
  subject: "Urgent — invoice attached, please review today",
  action: "Delivered", verdict: "Malware",
  url: null, attachment: "Invoice_2025-04.docm",
  attachment_sha256: MALWARE_SHA,
  client_ip: "185.220.101.5",
}));
writeFileSync(path.join(here, "sample-email-phishing.log"), emailLines.join("\n") + "\n");

// ---------- ENDPOINT (EDR) ----------
const edrLines = [];
for (let i = 0; i < 40; i++) {
  edrLines.push(JSON.stringify({
    datetime: new Date(ALICE_DAY + i * 3 * 60_000).toISOString(),
    endpoint: "ALICE-LAPTOP-01", user: "alice",
    process_name: ["chrome.exe", "code.exe", "outlook.exe"][i % 3],
    command_line: "(redacted)",
    file_path: null, file_sha256: null,
    parent_process: "explorer.exe",
    action: "Allowed", verdict: "Clean", malware_family: null,
    severity_score: 0, src_ip: "10.0.1.12",
  }));
}
// 10:31 — alice opens the attachment. Outlook -> Word -> PowerShell.
edrLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 31 * 60_000).toISOString(),
  endpoint: "ALICE-LAPTOP-01", user: "alice",
  process_name: "winword.exe",
  command_line: "WINWORD.EXE /n \"C:\\Users\\alice\\Downloads\\Invoice_2025-04.docm\"",
  file_path: "C:\\Users\\alice\\Downloads\\Invoice_2025-04.docm",
  file_sha256: MALWARE_SHA,
  parent_process: "outlook.exe",
  action: "Allowed", verdict: "Suspicious", malware_family: null,
  severity_score: 55, src_ip: "10.0.1.12",
}));
edrLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 31 * 60_000 + 12_000).toISOString(),
  endpoint: "ALICE-LAPTOP-01", user: "alice",
  process_name: "powershell.exe",
  command_line: "powershell.exe -nop -w hidden -enc SQBFAFgAIAA...==",
  file_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  file_sha256: null,
  parent_process: "winword.exe",
  action: "Detected", verdict: "Malware",
  malware_family: "Emotet",
  severity_score: 92, src_ip: "10.0.1.12",
}));
edrLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 32 * 60_000).toISOString(),
  endpoint: "ALICE-LAPTOP-01", user: "alice",
  process_name: "rundll32.exe",
  command_line: "rundll32.exe C:\\Users\\alice\\AppData\\Local\\Temp\\emotet.dll,Control_RunDLL",
  file_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\emotet.dll",
  file_sha256: MALWARE_SHA,
  parent_process: "powershell.exe",
  action: "Blocked", verdict: "Malware",
  malware_family: "Emotet",
  severity_score: 95, src_ip: "10.0.1.12",
}));
writeFileSync(path.join(here, "sample-endpoint-edr.log"), edrLines.join("\n") + "\n");

// ---------- CLOUD (Azure AD sign-ins) ----------
const cloudLines = [];
for (let i = 0; i < 30; i++) {
  cloudLines.push(JSON.stringify({
    datetime: new Date(ALICE_DAY - 3600_000 + i * 4 * 60_000).toISOString(),
    signin_id: `s-${i}`,
    principal: pick(USERS),
    app_display_name: ["Office 365 SharePoint Online", "Microsoft Teams", "Outlook Mobile"][i % 3],
    client_ip: ["10.0.1.12", "10.0.1.34", "10.0.2.45"][i % 3],
    country: "US", city: "Seattle",
    action: "Success", status_code: 0,
    user_agent: NORMAL_UA, risk_level: "none",
    mfa_required: true, conditional_access: "satisfied",
  }));
}
// 10:50 — legit alice sign-in from Seattle
cloudLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 50 * 60_000).toISOString(),
  signin_id: "s-alice-us",
  principal: "alice@corp.io",
  app_display_name: "Office 365 SharePoint Online",
  client_ip: "10.0.1.12", country: "US", city: "Seattle",
  action: "Success", status_code: 0,
  user_agent: NORMAL_UA, risk_level: "none",
  mfa_required: true, conditional_access: "satisfied",
}));
// 11:30 — password spray
for (let i = 0; i < 12; i++) {
  cloudLines.push(JSON.stringify({
    datetime: new Date(ALICE_DAY + 90 * 60_000 + i * 30_000).toISOString(),
    signin_id: `s-fail-${i}`,
    principal: "alice@corp.io",
    app_display_name: "Office 365 Exchange Online",
    client_ip: "185.220.101.5", country: "RU", city: "Moscow",
    action: "Failure", status_code: 50126,
    user_agent: "Mozilla/5.0 (X11; Linux x86_64) curl/7.85.0",
    risk_level: "high",
    mfa_required: false, conditional_access: "blocked",
  }));
}
// 11:38 — finally succeeds (impossible travel US->RU in <1h)
cloudLines.push(JSON.stringify({
  datetime: new Date(ALICE_DAY + 98 * 60_000).toISOString(),
  signin_id: "s-alice-ru",
  principal: "alice@corp.io",
  app_display_name: "Office 365 Exchange Online",
  client_ip: "185.220.101.5", country: "RU", city: "Moscow",
  action: "Success", status_code: 0,
  user_agent: "Mozilla/5.0 (X11; Linux x86_64) curl/7.85.0",
  risk_level: "high",
  mfa_required: false, conditional_access: "satisfied",
}));
writeFileSync(path.join(here, "sample-cloud-azuread.log"), cloudLines.join("\n") + "\n");

console.log("Wrote 5 sample files");

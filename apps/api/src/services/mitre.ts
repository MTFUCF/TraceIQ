/**
 * MITRE ATT&CK tactic + technique catalog used by TraceIQ.
 *
 * Author: Matthew Faber
 *
 * Only the entries we actually map detection rules to are listed — keeping
 * this file small makes it easy to review and explain. Tactic and
 * technique IDs follow MITRE ATT&CK v15 (https://attack.mitre.org).
 *
 * Each anomaly carries a `mitre` object so the UI can show the badge and
 * link to the official ATT&CK page.
 */

export interface MitreMapping {
  tacticId: string;       // e.g. "TA0001"
  tacticName: string;     // e.g. "Initial Access"
  techniqueId: string;    // e.g. "T1566.002"
  techniqueName: string;  // e.g. "Phishing: Spearphishing Link"
}

const M = (tacticId: string, tacticName: string, techniqueId: string, techniqueName: string): MitreMapping =>
  ({ tacticId, tacticName, techniqueId, techniqueName });

export const MITRE_BY_RULE: Record<string, MitreMapping> = {
  // ---- proxy ----
  burst_from_ip:        M("TA0043", "Reconnaissance", "T1595.002", "Active Scanning: Vulnerability Scanning"),
  high_block_ratio:     M("TA0043", "Reconnaissance", "T1595",     "Active Scanning"),
  malicious_category:   M("TA0011", "Command and Control", "T1071", "Application Layer Protocol"),
  rare_user_agent:      M("TA0005", "Defense Evasion",  "T1036",   "Masquerading"),
  large_exfil:          M("TA0010", "Exfiltration",     "T1041",   "Exfiltration Over C2 Channel"),

  // ---- email ----
  phishing_email:       M("TA0001", "Initial Access",   "T1566.002", "Phishing: Spearphishing Link"),
  malware_attachment:   M("TA0001", "Initial Access",   "T1566.001", "Phishing: Spearphishing Attachment"),

  // ---- endpoint ----
  malware_detected:     M("TA0002", "Execution",        "T1204.002", "User Execution: Malicious File"),
  suspicious_process:   M("TA0002", "Execution",        "T1059",     "Command and Scripting Interpreter"),
  office_spawns_shell:  M("TA0002", "Execution",        "T1059.001", "Command and Scripting Interpreter: PowerShell"),

  // ---- cloud ----
  failed_login_burst:   M("TA0006", "Credential Access","T1110",     "Brute Force"),
  impossible_travel:    M("TA0001", "Initial Access",   "T1078.004", "Valid Accounts: Cloud Accounts"),
  high_risk_signin:     M("TA0001", "Initial Access",   "T1078",     "Valid Accounts"),
};

export function mitreUrl(m: MitreMapping): string {
  // Sub-technique URLs use slash + sub id; the catalog handles both forms.
  const [base, sub] = m.techniqueId.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

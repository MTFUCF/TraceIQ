/**
 * MITRE ATT&CK pill that links out to attack.mitre.org.
 * Author: Matthew Faber
 */
"use client";

type Mapping = { tacticId: string; tacticName: string; techniqueId: string; techniqueName: string };

function url(m: Mapping) {
  const [base, sub] = m.techniqueId.split(".");
  return sub
    ? `https://attack.mitre.org/techniques/${base}/${sub}/`
    : `https://attack.mitre.org/techniques/${base}/`;
}

export function MitreBadge({ m }: { m: Mapping }) {
  return (
    <a
      href={url(m)}
      target="_blank"
      rel="noopener noreferrer"
      className="text-[10px] inline-flex items-center gap-1 px-2 py-0.5 rounded border border-indigo-500/60 text-indigo-200 hover:bg-indigo-500/10"
      title={`${m.tacticName} → ${m.techniqueName}`}
    >
      MITRE {m.techniqueId} · {m.tacticName}
    </a>
  );
}

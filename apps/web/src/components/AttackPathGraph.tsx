/**
 * AttackPathGraph — SVG visualisation of a correlated attack chain.
 *
 * Author: Matthew Faber
 *
 * Renders the chain's events as a left-to-right swimlane diagram:
 *   - Each source type (proxy/email/endpoint/cloud) gets its own horizontal lane.
 *   - Each event is a circle plotted at its time position within its lane.
 *   - Anomalies are larger and colored by severity (red/amber/slate).
 *   - A polyline connects events in chronological order — the "kill chain path".
 *
 * Why SVG and not a graph library? The chain is always a single linear
 * sequence ordered by time — no need for force-directed layout or graph
 * routing. Hand-rolled SVG keeps the bundle small and renders crisply at
 * any zoom level.
 */
"use client";
import { useMemo } from "react";

type Mitre = { tacticId: string; tacticName: string; techniqueId: string; techniqueName: string };
type ChainEvent = {
  uploadId: string; sourceType: string; eventId: string | null;
  occurredAt: string | null; summary: string; isAnomaly: boolean;
  severity: "low" | "medium" | "high" | null; mitre: Mitre | null;
};

const LANES: { key: string; label: string }[] = [
  { key: "email",    label: "📧 Email" },
  { key: "endpoint", label: "🖥 Endpoint" },
  { key: "cloud",    label: "☁ Cloud" },
  { key: "proxy",    label: "🌐 Proxy" },
];

const LANE_COLORS: Record<string, string> = {
  email: "#a78bfa",
  endpoint: "#fb923c",
  cloud: "#60a5fa",
  proxy: "#34d399",
};

function sevColor(s: string | null, isAnomaly: boolean): string {
  if (!isAnomaly) return "#475569"; // slate-600 for non-anomalous
  if (s === "high") return "#ef4444";
  if (s === "medium") return "#f59e0b";
  if (s === "low") return "#94a3b8";
  return "#94a3b8";
}

export function AttackPathGraph({ events }: { events: ChainEvent[] }) {
  // Filter out events without timestamps — can't position them.
  const timed = useMemo(
    () => events.filter((e) => e.occurredAt).map((e) => ({ ...e, t: new Date(e.occurredAt!).getTime() })),
    [events],
  );

  if (timed.length < 2) {
    return (
      <p className="text-xs text-slate-500 italic">
        Need at least 2 timestamped events to draw a path.
      </p>
    );
  }

  const PADDING_LEFT = 90;
  const PADDING_RIGHT = 30;
  const PADDING_TOP = 22;
  const PADDING_BOTTOM = 22;
  const WIDTH = 880;
  const LANE_HEIGHT = 60;
  const HEIGHT = PADDING_TOP + LANES.length * LANE_HEIGHT + PADDING_BOTTOM;

  const tMin = timed[0].t;
  const tMax = timed[timed.length - 1].t;
  const tSpan = Math.max(tMax - tMin, 1); // avoid /0 when all events are at the same instant

  const xFor = (t: number) =>
    PADDING_LEFT + ((t - tMin) / tSpan) * (WIDTH - PADDING_LEFT - PADDING_RIGHT);
  const yFor = (sourceType: string) => {
    const idx = LANES.findIndex((l) => l.key === sourceType);
    return PADDING_TOP + (idx < 0 ? LANES.length : idx) * LANE_HEIGHT + LANE_HEIGHT / 2;
  };

  const points = timed.map((e) => ({
    ...e, x: xFor(e.t), y: yFor(e.sourceType),
    r: e.isAnomaly ? 9 : 5,
    fill: sevColor(e.severity, e.isAnomaly),
    stroke: LANE_COLORS[e.sourceType] ?? "#94a3b8",
  }));

  const polyline = points.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");

  // Time axis tick at start / mid / end.
  const ticks = [tMin, (tMin + tMax) / 2, tMax].map((t) => ({
    t, x: xFor(t),
    label: new Date(t).toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    }),
  }));

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        width="100%"
        style={{ minWidth: 600 }}
        role="img"
        aria-label="Attack path visualization"
      >
        {/* Lane backgrounds + labels */}
        {LANES.map((lane, i) => {
          const y = PADDING_TOP + i * LANE_HEIGHT;
          return (
            <g key={lane.key}>
              <rect
                x={PADDING_LEFT - 5}
                y={y}
                width={WIDTH - PADDING_LEFT - PADDING_RIGHT + 5}
                height={LANE_HEIGHT}
                fill={i % 2 === 0 ? "#0b1020" : "#0e152a"}
              />
              <line
                x1={PADDING_LEFT}
                x2={WIDTH - PADDING_RIGHT}
                y1={y + LANE_HEIGHT / 2}
                y2={y + LANE_HEIGHT / 2}
                stroke={LANE_COLORS[lane.key]}
                strokeOpacity="0.25"
                strokeDasharray="2 4"
              />
              <text
                x={PADDING_LEFT - 12}
                y={y + LANE_HEIGHT / 2 + 4}
                textAnchor="end"
                fontSize="11"
                fill={LANE_COLORS[lane.key]}
              >
                {lane.label}
              </text>
            </g>
          );
        })}

        {/* Time axis */}
        {ticks.map((t, i) => (
          <g key={i}>
            <line
              x1={t.x}
              x2={t.x}
              y1={PADDING_TOP}
              y2={HEIGHT - PADDING_BOTTOM}
              stroke="#1e293b"
              strokeWidth="1"
            />
            <text
              x={t.x}
              y={HEIGHT - 4}
              textAnchor="middle"
              fontSize="9"
              fill="#64748b"
            >
              {t.label}
            </text>
          </g>
        ))}

        {/* Connecting polyline (the kill chain) */}
        <polyline
          points={polyline}
          fill="none"
          stroke="#5eead4"
          strokeOpacity="0.55"
          strokeWidth="1.5"
          strokeLinejoin="round"
        />

        {/* Event nodes */}
        {points.map((p, i) => (
          <g key={i}>
            <circle
              cx={p.x}
              cy={p.y}
              r={p.r + (p.isAnomaly ? 2 : 0)}
              fill={p.fill}
              stroke={p.stroke}
              strokeWidth={p.isAnomaly ? 2 : 1}
              opacity={p.isAnomaly ? 1 : 0.55}
            >
              <title>
                {`${new Date(p.t).toLocaleString()}\n[${p.sourceType}] ${p.summary}${
                  p.mitre ? `\nMITRE: ${p.mitre.techniqueId} ${p.mitre.techniqueName}` : ""
                }`}
              </title>
            </circle>
            {p.isAnomaly && p.mitre && (
              <text
                x={p.x}
                y={p.y - 13}
                textAnchor="middle"
                fontSize="9"
                fill="#cbd5e1"
              >
                {p.mitre.techniqueId}
              </text>
            )}
          </g>
        ))}
      </svg>

      {/* Legend */}
      <div className="flex items-center gap-4 mt-2 text-[10px] text-slate-400">
        <span className="inline-flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> high
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> medium
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="w-2.5 h-2.5 rounded-full bg-slate-400"></span> low
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="w-2 h-2 rounded-full bg-slate-600 opacity-60"></span> non-anomalous (context)
        </span>
        <span className="ml-auto">Hover any node for details.</span>
      </div>
    </div>
  );
}

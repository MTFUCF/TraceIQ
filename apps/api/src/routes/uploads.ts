/**
 * Upload + analysis routes.
 *
 * Author: Matthew Faber
 *
 * Endpoints (all require auth):
 *   POST   /uploads               multipart "file" -> { uploadId, status }
 *          Synchronously runs parser + anomaly detection and returns the id
 *          once the row reaches status='done'. For a take-home with modest
 *          file sizes (<= 10 MB) this is the simplest UX — no queue, no
 *          polling required by the client. For larger files we'd push the
 *          parse/analyze step onto a worker and have the client poll
 *          GET /uploads/:id for status.
 *
 *   GET    /uploads               -> list current user's uploads
 *   GET    /uploads/:id           -> upload metadata + summary stats
 *   GET    /uploads/:id/events    -> paginated events (?limit, ?offset)
 *   GET    /uploads/:id/anomalies -> all anomalies (joined to event metadata)
 *   GET    /uploads/:id/timeline  -> bucketed event counts for the chart
 *   DELETE /uploads/:id           -> delete blob + cascade-delete rows
 */
import { Router } from "express";
import multer from "multer";
import { randomUUID } from "node:crypto";
import { query, pool } from "../db/client.js";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { uploadBuffer, downloadAsText } from "../services/storage.js";
import { parseLogText } from "../services/parser.js";
import { detectAnomalies } from "../services/anomaly.js";
import { enrichTopAnomalies } from "../services/foundry.js";

export const uploadsRouter = Router();

// In-memory multer; we re-stream the buffer to Blob storage. 25 MB cap fits
// well within the 32 MB body limit we set in index.ts.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
});

uploadsRouter.post(
  "/",
  requireAuth,
  upload.single("file"),
  async (req: AuthedRequest, res) => {
    if (!req.file) return res.status(400).json({ error: "file is required" });
    const userId = req.user!.id;
    const uploadId = randomUUID();
    const blobPath = `uploads/${uploadId}/${req.file.originalname}`;

    await uploadBuffer(blobPath, req.file.buffer, "text/plain");
    await query(
      `INSERT INTO uploads (id, user_id, filename, blob_path, size_bytes, status)
       VALUES ($1, $2, $3, $4, $5, 'parsing')`,
      [uploadId, userId, req.file.originalname, blobPath, req.file.size],
    );

    try {
      // ----- Parse -----
      const text = req.file.buffer.toString("utf8");
      const events = parseLogText(text);

      // Bulk-insert events. We chunk to avoid hitting the 65535 parameter
      // limit of a single Postgres extended-protocol message.
      const CHUNK = 500;
      for (let i = 0; i < events.length; i += CHUNK) {
        const slice = events.slice(i, i + CHUNK);
        const values: unknown[] = [];
        const placeholders: string[] = [];
        slice.forEach((e, idx) => {
          const base = idx * 13;
          placeholders.push(
            `($${base + 1},$${base + 2},$${base + 3},$${base + 4},$${base + 5},$${base + 6},$${base + 7},$${base + 8},$${base + 9},$${base + 10},$${base + 11},$${base + 12},$${base + 13})`,
          );
          values.push(
            uploadId,
            e.lineNumber,
            e.occurredAt,
            e.userName,
            e.clientIp,
            e.action,
            e.url,
            e.host,
            e.urlCategory,
            e.statusCode,
            e.bytesOut,
            e.bytesIn,
            e.rawLine,
          );
        });
        await query(
          `INSERT INTO events
             (upload_id, line_number, occurred_at, user_name, client_ip, action,
              url, host, url_category, status_code, bytes_out, bytes_in, raw_line)
           VALUES ${placeholders.join(",")}`,
          values,
        );
      }

      // ----- Detect anomalies -----
      await query("UPDATE uploads SET status='analyzing' WHERE id=$1", [uploadId]);
      const anomalies = detectAnomalies(events);

      // Map our in-memory eventIndex -> the BIGSERIAL `events.id` written above.
      // We fetch them ordered by line_number, which is how they were inserted.
      const rows = await query<{ id: string; line_number: number }>(
        "SELECT id, line_number FROM events WHERE upload_id=$1 ORDER BY line_number",
        [uploadId],
      );
      const lineToId = new Map<number, string>();
      rows.rows.forEach((r) => lineToId.set(r.line_number, r.id));

      // ----- LLM enrichment for top-N (best-effort, never blocks) -----
      const aiExplanations = await enrichTopAnomalies(anomalies, 5);

      for (let i = 0; i < anomalies.length; i++) {
        const a = anomalies[i];
        const eventDbId =
          a.eventIndex !== null && events[a.eventIndex]
            ? lineToId.get(events[a.eventIndex].lineNumber) ?? null
            : null;
        await query(
          `INSERT INTO anomalies
             (upload_id, event_id, rule, reason, confidence, severity, ai_explanation, metadata)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
          [
            uploadId,
            eventDbId,
            a.rule,
            a.reason,
            a.confidence,
            a.severity,
            aiExplanations.get(i) ?? null,
            JSON.stringify(a.metadata),
          ],
        );
      }

      await query(
        `UPDATE uploads
           SET status='done',
               event_count=$2,
               anomaly_count=$3,
               completed_at=NOW()
         WHERE id=$1`,
        [uploadId, events.length, anomalies.length],
      );

      res.status(201).json({
        uploadId,
        status: "done",
        eventCount: events.length,
        anomalyCount: anomalies.length,
      });
    } catch (err) {
      console.error("[uploads] processing failed:", err);
      await query(
        `UPDATE uploads SET status='error', error=$2 WHERE id=$1`,
        [uploadId, (err as Error).message],
      );
      res.status(500).json({ uploadId, status: "error", error: (err as Error).message });
    }
  },
);

uploadsRouter.get("/", requireAuth, async (req: AuthedRequest, res) => {
  const r = await query(
    `SELECT id, filename, size_bytes, status, event_count, anomaly_count,
            created_at, completed_at
       FROM uploads
      WHERE user_id=$1
      ORDER BY created_at DESC`,
    [req.user!.id],
  );
  res.json({ uploads: r.rows });
});

uploadsRouter.get("/:id", requireAuth, async (req: AuthedRequest, res) => {
  const r = await query(
    `SELECT id, filename, size_bytes, status, event_count, anomaly_count,
            created_at, completed_at, error
       FROM uploads
      WHERE id=$1 AND user_id=$2`,
    [req.params.id, req.user!.id],
  );
  if (r.rowCount === 0) return res.status(404).json({ error: "not found" });

  // Summary stats for the dashboard cards.
  const stats = await query<{
    total: string; blocked: string; allowed: string;
    unique_ips: string; unique_users: string;
    first_ts: string | null; last_ts: string | null;
  }>(
    `SELECT
       COUNT(*)::text AS total,
       COUNT(*) FILTER (WHERE action ILIKE 'block%')::text AS blocked,
       COUNT(*) FILTER (WHERE action ILIKE 'allow%')::text AS allowed,
       COUNT(DISTINCT client_ip)::text AS unique_ips,
       COUNT(DISTINCT user_name)::text AS unique_users,
       MIN(occurred_at)::text AS first_ts,
       MAX(occurred_at)::text AS last_ts
     FROM events WHERE upload_id=$1`,
    [req.params.id],
  );

  const topIps = await query(
    `SELECT client_ip, COUNT(*)::int AS count
       FROM events WHERE upload_id=$1 AND client_ip IS NOT NULL
       GROUP BY client_ip ORDER BY count DESC LIMIT 10`,
    [req.params.id],
  );

  const topHosts = await query(
    `SELECT host, COUNT(*)::int AS count
       FROM events WHERE upload_id=$1 AND host IS NOT NULL
       GROUP BY host ORDER BY count DESC LIMIT 10`,
    [req.params.id],
  );

  res.json({
    upload: r.rows[0],
    stats: stats.rows[0],
    topIps: topIps.rows,
    topHosts: topHosts.rows,
  });
});

uploadsRouter.get("/:id/events", requireAuth, async (req: AuthedRequest, res) => {
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  const offset = Math.max(Number(req.query.offset ?? 0), 0);
  // Confirm ownership before serving rows.
  const own = await query("SELECT 1 FROM uploads WHERE id=$1 AND user_id=$2", [
    req.params.id,
    req.user!.id,
  ]);
  if (own.rowCount === 0) return res.status(404).json({ error: "not found" });

  const r = await query(
    `SELECT e.id, e.line_number, e.occurred_at, e.user_name, e.client_ip,
            e.action, e.url, e.host, e.url_category, e.status_code,
            e.bytes_out, e.bytes_in, e.user_agent,
            EXISTS (SELECT 1 FROM anomalies a WHERE a.event_id = e.id) AS is_anomaly
       FROM events e
      WHERE e.upload_id=$1
      ORDER BY e.line_number
      LIMIT $2 OFFSET $3`,
    [req.params.id, limit, offset],
  );
  res.json({ events: r.rows, limit, offset });
});

uploadsRouter.get("/:id/anomalies", requireAuth, async (req: AuthedRequest, res) => {
  const own = await query("SELECT 1 FROM uploads WHERE id=$1 AND user_id=$2", [
    req.params.id,
    req.user!.id,
  ]);
  if (own.rowCount === 0) return res.status(404).json({ error: "not found" });

  const r = await query(
    `SELECT a.id, a.rule, a.reason, a.confidence, a.severity,
            a.ai_explanation, a.metadata,
            e.id AS event_id, e.line_number, e.occurred_at,
            e.client_ip, e.user_name, e.url, e.host, e.action, e.status_code
       FROM anomalies a
       LEFT JOIN events e ON e.id = a.event_id
      WHERE a.upload_id=$1
      ORDER BY a.confidence DESC, a.id`,
    [req.params.id],
  );
  res.json({ anomalies: r.rows });
});

uploadsRouter.get("/:id/timeline", requireAuth, async (req: AuthedRequest, res) => {
  const own = await query("SELECT 1 FROM uploads WHERE id=$1 AND user_id=$2", [
    req.params.id,
    req.user!.id,
  ]);
  if (own.rowCount === 0) return res.status(404).json({ error: "not found" });

  // Bucket by minute. For very long files we'd promote the bucket size, but
  // for a take-home demo (minutes-to-hours of activity) minute granularity is
  // a useful default.
  const r = await query(
    `SELECT date_trunc('minute', occurred_at) AS bucket,
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE action ILIKE 'block%')::int AS blocked,
            SUM(CASE WHEN EXISTS (
                  SELECT 1 FROM anomalies a WHERE a.event_id = events.id
                ) THEN 1 ELSE 0 END)::int AS anomalies
       FROM events
      WHERE upload_id=$1 AND occurred_at IS NOT NULL
      GROUP BY bucket
      ORDER BY bucket`,
    [req.params.id],
  );
  res.json({ buckets: r.rows });
});

uploadsRouter.delete("/:id", requireAuth, async (req: AuthedRequest, res) => {
  const own = await query<{ blob_path: string }>(
    "SELECT blob_path FROM uploads WHERE id=$1 AND user_id=$2",
    [req.params.id, req.user!.id],
  );
  if (own.rowCount === 0) return res.status(404).json({ error: "not found" });
  // Cascade handles events + anomalies; blob can be cleaned by lifecycle policy.
  await query("DELETE FROM uploads WHERE id=$1", [req.params.id]);
  res.status(204).end();
});

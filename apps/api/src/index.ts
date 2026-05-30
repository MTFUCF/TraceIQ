/**
 * traceiq API entrypoint.
 *
 * Author: Matthew Faber
 *
 * Bootstraps the Express app:
 *   - JSON + 32 MB body cap (uploads are streamed via multer separately).
 *   - Permissive CORS (the SPA in apps/web lives on a different origin).
 *   - Runs the migration so a fresh DB is usable without an extra command.
 *   - Mounts /auth and /uploads.
 *
 * Health check exists at /health for the Container Apps liveness probe.
 */
import express from "express";
import cors from "cors";
import { config } from "./config.js";
import { authRouter } from "./routes/auth.js";
import { uploadsRouter } from "./routes/uploads.js";
import { correlateRouter } from "./routes/correlate.js";
import { query } from "./db/client.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import bcrypt from "bcryptjs";

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => res.json({ ok: true, env: config.env }));

app.use("/auth", authRouter);
app.use("/uploads", uploadsRouter);
app.use("/correlate", correlateRouter);

// Centralised error handler so multer/zod errors don't leak stack traces.
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error("[api] error:", err);
  res.status(err.status ?? 500).json({ error: err.message ?? "internal error" });
});

/**
 * Run schema + seed inline on boot. Idempotent — safe on every container
 * start. Removes a deploy step from the demo and is the right size of magic
 * for a take-home; for production you'd run migrations as a Job, not on the
 * web tier.
 */
async function bootstrap() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // schema.sql is copied into dist/ by the build step's tsconfig include.
  // We resolve it relative to this file so it works in both ts-node-dev and prod.
  const candidates = [
    path.join(here, "db", "schema.sql"),
    path.join(here, "..", "src", "db", "schema.sql"),
  ];
  const schemaPath = candidates.find((p) => {
    try { readFileSync(p, "utf8"); return true; } catch { return false; }
  });
  if (!schemaPath) {
    console.warn("[bootstrap] schema.sql not found; skipping migrations");
  } else {
    const sql = readFileSync(schemaPath, "utf8");
    await query(sql);

    const existing = await query<{ id: string }>(
      "SELECT id FROM users WHERE email = $1",
      [config.seedAdmin.email],
    );
    if (existing.rowCount === 0) {
      const hash = await bcrypt.hash(config.seedAdmin.password, 10);
      await query("INSERT INTO users (email, password_hash) VALUES ($1, $2)", [
        config.seedAdmin.email,
        hash,
      ]);
      console.log(`[bootstrap] seeded admin user: ${config.seedAdmin.email}`);
    }
  }
}

bootstrap()
  .then(() => {
    app.listen(config.port, () => {
      console.log(`[api] listening on :${config.port} (${config.env})`);
    });
  })
  .catch((err) => {
    console.error("[bootstrap] failed:", err);
    process.exit(1);
  });

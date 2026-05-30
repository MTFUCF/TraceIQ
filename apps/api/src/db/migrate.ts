/**
 * One-shot migration runner.
 *
 * Author: Matthew Faber
 *
 * This intentionally avoids a heavy migration framework — the schema is small
 * and our deploy story is "drop and recreate is fine for a take-home". For
 * production you'd swap this for Prisma Migrate / node-pg-migrate so each
 * schema change is versioned and reversible.
 *
 * What it does:
 *  1. Connects with the pool from db/client.ts.
 *  2. Runs schema.sql idempotently (every statement uses IF NOT EXISTS).
 *  3. Seeds the admin user if it doesn't exist yet.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import bcrypt from "bcryptjs";
import { pool, query } from "./client.js";
import { config } from "../config.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemaPath = path.join(here, "schema.sql");

async function main() {
  const schema = readFileSync(schemaPath, "utf8");
  console.log("[migrate] applying schema…");
  await query(schema);

  console.log("[migrate] seeding admin user if absent…");
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
    console.log(`[migrate] seeded admin: ${config.seedAdmin.email}`);
  } else {
    console.log("[migrate] admin already exists");
  }

  await pool.end();
  console.log("[migrate] done");
}

main().catch((err) => {
  console.error("[migrate] failed:", err);
  process.exit(1);
});

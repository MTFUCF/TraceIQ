/**
 * PostgreSQL connection pool.
 *
 * Author: Matthew Faber
 *
 * We use a single shared Pool across the process. node-postgres' Pool
 * transparently reuses TCP connections (default 10 max) which is the right
 * choice for an HTTP server — every request grabs a client, runs a query,
 * releases it. No per-request connection cost.
 *
 * In Azure, DATABASE_URL points at Postgres Flexible Server which requires
 * TLS; the `?sslmode=require` query string in the connection string handles
 * that. Locally (Docker) it's plain TCP.
 */
import pg from "pg";
import { config } from "../config.js";

export const pool = new pg.Pool({
  connectionString: config.databaseUrl,
  // Azure Flexible Server uses a chain we don't ship, so we skip strict CA
  // verification. In production you'd pin to the Microsoft RSA Root CA.
  ssl: config.databaseUrl.includes("sslmode=require")
    ? { rejectUnauthorized: false }
    : undefined,
});

export async function query<T extends pg.QueryResultRow = any>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params as any);
}

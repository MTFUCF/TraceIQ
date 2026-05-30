/**
 * Centralised, validated environment configuration.
 *
 * Author: Matthew Faber
 *
 * Why a dedicated module?
 *  - Single source of truth. The rest of the codebase never reads
 *    `process.env` directly — they import `config` from here. That makes the
 *    full set of required env vars discoverable in one place.
 *  - Fail fast. If a required variable is missing in production we throw at
 *    startup rather than crashing on the first request that needs it.
 *  - Type safety. The exported `config` object is strongly typed so callers
 *    get autocomplete and TS errors for typos.
 */
import { config as loadEnv } from "dotenv";
loadEnv();

function required(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (v === undefined || v === "") {
    // In production we hard-fail. In development we tolerate missing AI
    // credentials so devs can still exercise auth/upload/parsing without a
    // Foundry deployment.
    if (process.env.NODE_ENV === "production") {
      throw new Error(`Missing required env var: ${name}`);
    }
    console.warn(`[config] ${name} is not set — features depending on it will be disabled.`);
    return "";
  }
  return v;
}

export const config = {
  env: process.env.NODE_ENV ?? "development",
  port: Number(process.env.PORT ?? 4000),

  jwtSecret: required("JWT_SECRET", "dev-only-secret-do-not-use-in-prod"),
  seedAdmin: {
    email: process.env.SEED_ADMIN_EMAIL ?? "admin@loginsight.local",
    password: process.env.SEED_ADMIN_PASSWORD ?? "ChangeMe123!",
  },

  databaseUrl: required("DATABASE_URL"),

  storage: {
    connectionString: required("AZURE_STORAGE_CONNECTION_STRING"),
    container: process.env.AZURE_STORAGE_CONTAINER ?? "logs",
  },

  foundry: {
    endpoint: process.env.AZURE_AI_FOUNDRY_ENDPOINT ?? "",
    apiKey: process.env.AZURE_AI_FOUNDRY_API_KEY ?? "",
    deployment: process.env.AZURE_AI_FOUNDRY_DEPLOYMENT ?? "gpt-4o-mini",
  },
} as const;

export const isFoundryConfigured = (): boolean =>
  Boolean(config.foundry.endpoint && config.foundry.apiKey);

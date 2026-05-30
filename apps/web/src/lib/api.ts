/**
 * Tiny typed fetch wrapper.
 *
 * Author: Matthew Faber
 *
 * Every API call funnels through `api()`:
 *   - Reads NEXT_PUBLIC_API_URL (baked at build time).
 *   - Adds the bearer token if one is stored in localStorage.
 *   - Throws on non-2xx so callers can `try/catch` instead of branching on
 *     response.ok everywhere.
 *   - Sniffs Content-Type so we get JSON when the server speaks JSON and
 *     text otherwise (useful for the 204 DELETE).
 */
const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const token =
    typeof window !== "undefined" ? localStorage.getItem("traceiq_token") : null;
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch { /* non-json body */ }
    if (res.status === 401 && typeof window !== "undefined") {
      localStorage.removeItem("traceiq_token");
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") ?? "";
  return (ct.includes("application/json") ? res.json() : res.text()) as Promise<T>;
}

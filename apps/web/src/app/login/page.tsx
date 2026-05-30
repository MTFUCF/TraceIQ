/**
 * Login page.
 * Author: Matthew Faber
 *
 * Posts to /auth/login, stores the JWT in localStorage, then routes to the
 * dashboard. The seed admin credentials are shown as a hint so the take-home
 * reviewer can sign in without reading the README.
 */
"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("admin@loginsight.local");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      const r = await api<{ token: string; user: { email: string } }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });
      localStorage.setItem("loginsight_token", r.token);
      router.push("/dashboard");
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "login failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-16 panel">
      <h1 className="text-xl font-semibold mb-1">Sign in</h1>
      <p className="text-slate-400 text-sm mb-4">Use your loginsight credentials.</p>
      <form onSubmit={submit} className="space-y-3">
        <input
          className="input"
          type="email"
          placeholder="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          className="input"
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {err && <p className="text-red-400 text-sm">{err}</p>}
        <button className="btn w-full" disabled={busy} type="submit">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="text-xs text-slate-500 mt-4">
        Default admin (set via env): <code>admin@loginsight.local</code>
      </p>
    </div>
  );
}

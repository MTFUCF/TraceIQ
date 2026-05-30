/**
 * Client-side auth gate.
 * Author: Matthew Faber
 *
 * Wrap any protected page with <AuthGate>...</AuthGate> to redirect
 * unauthenticated visitors to /login. Keeps page components simple.
 */
"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const token = localStorage.getItem("loginsight_token");
    if (!token) router.replace("/login");
    else setReady(true);
  }, [router]);
  if (!ready) return <p className="text-slate-400">Loading…</p>;
  return <>{children}</>;
}

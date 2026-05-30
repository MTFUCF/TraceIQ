/**
 * Root entry — sends users to /login or /dashboard based on token presence.
 * Author: Matthew Faber
 */
"use client";
import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    const token = typeof window !== "undefined" && localStorage.getItem("traceiq_token");
    router.replace(token ? "/dashboard" : "/login");
  }, [router]);
  return <p className="text-slate-400">Loading…</p>;
}

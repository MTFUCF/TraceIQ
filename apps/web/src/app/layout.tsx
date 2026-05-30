/**
 * Root layout for the loginsight web app.
 * Author: Matthew Faber
 *
 * The layout is intentionally minimal — a single header strip plus a
 * centered main column. Auth gating happens per-page in client components.
 */
import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";
import { SignOutButton } from "@/components/SignOutButton";

export const metadata: Metadata = {
  title: "loginsight",
  description: "SOC log analysis with AI-powered anomaly detection",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-slate-800 bg-panel/60 backdrop-blur sticky top-0 z-20">
          <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
            <Link href="/dashboard" className="text-accent font-semibold tracking-tight">
              loginsight<span className="text-slate-400 font-normal ml-2 text-sm">SOC log analysis</span>
            </Link>
            <nav className="text-sm text-slate-400">
              <Link href="/dashboard" className="hover:text-slate-100 mr-4">Dashboard</Link>
              <SignOutButton />
            </nav>
          </div>
        </header>
        <main className="max-w-6xl mx-auto px-4 py-6">{children}</main>
      </body>
    </html>
  );
}

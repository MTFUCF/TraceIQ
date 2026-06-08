/**
 * Reusable chat panel for the per-upload and per-correlation assistants.
 *
 * Author: Matthew Faber
 *
 * Props:
 *   endpoint  full API path that handles GET (history) / POST (turn) /
 *             DELETE (clear). Example: "/uploads/abc/chat" or "/correlate/chat".
 *   title     panel header text.
 *   intro     short helper text shown when the conversation is empty.
 *   suggested optional list of starter prompts surfaced as buttons.
 *
 * History is persisted server-side keyed by user + scope, so the conversation
 * survives reloads. The component loads it on mount and appends as the user
 * chats. On send we optimistically render the user message, then await the
 * server response (which returns both the user + assistant rows).
 */
"use client";
import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";

type Message = {
  id: string;
  role: "user" | "assistant";
  content: string;
  created_at: string;
};

export function ChatPanel({
  endpoint,
  title,
  intro,
  suggested,
}: {
  endpoint: string;
  title: string;
  intro: string;
  suggested?: string[];
}) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const scroller = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    api<{ messages: Message[] }>(endpoint)
      .then((r) => { if (mounted) setMessages(r.messages); })
      .catch((e) => { if (mounted) setErr(e instanceof ApiError ? e.message : "failed to load chat"); })
      .finally(() => { if (mounted) setLoading(false); });
    return () => { mounted = false; };
  }, [endpoint]);

  useEffect(() => {
    // Scroll to bottom on new messages.
    const el = scroller.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages, sending]);

  async function send(text: string) {
    const trimmed = text.trim();
    if (!trimmed || sending) return;
    setSending(true); setErr(null);
    // Optimistic user bubble — replaced by server copy once the turn returns.
    const optimisticId = `local-${Date.now()}`;
    setMessages((m) => [...m, { id: optimisticId, role: "user", content: trimmed, created_at: new Date().toISOString() }]);
    setInput("");
    try {
      const r = await api<{ user: Message; assistant: Message }>(endpoint, {
        method: "POST",
        body: JSON.stringify({ message: trimmed }),
      });
      setMessages((m) => {
        const without = m.filter((x) => x.id !== optimisticId);
        return [...without, r.user, r.assistant];
      });
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "send failed");
      // Roll back optimistic bubble so the user can retry.
      setMessages((m) => m.filter((x) => x.id !== optimisticId));
    } finally {
      setSending(false);
    }
  }

  async function clearHistory() {
    if (!confirm("Clear this chat history?")) return;
    try {
      await api(endpoint, { method: "DELETE" });
      setMessages([]);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "clear failed");
    }
  }

  return (
    <section className="panel">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold">{title}</h2>
        {messages.length > 0 && (
          <button onClick={clearHistory} className="text-xs text-slate-500 hover:text-slate-300">
            Clear history
          </button>
        )}
      </div>

      <div
        ref={scroller}
        className="border border-slate-800 rounded bg-slate-950/60 p-3 h-80 overflow-y-auto space-y-3"
      >
        {loading && <p className="text-slate-500 text-sm">Loading…</p>}
        {!loading && messages.length === 0 && (
          <div className="space-y-3">
            <p className="text-slate-400 text-sm">{intro}</p>
            {suggested && suggested.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {suggested.map((s) => (
                  <button
                    key={s}
                    onClick={() => send(s)}
                    className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-300 hover:border-accent hover:text-accent transition"
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
        {messages.map((m) => (
          <div key={m.id} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-sm whitespace-pre-wrap ${
                m.role === "user"
                  ? "bg-accent/15 border border-accent/40 text-slate-100"
                  : "bg-slate-900 border border-slate-700 text-slate-100"
              }`}
            >
              {m.role === "assistant" && (
                <div className="text-[10px] uppercase tracking-wider text-accent mb-1">
                  AI · Azure AI Foundry
                </div>
              )}
              {m.content}
            </div>
          </div>
        ))}
        {sending && (
          <div className="flex justify-start">
            <div className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-400">
              <span className="inline-block animate-pulse">Thinking…</span>
            </div>
          </div>
        )}
      </div>

      {err && <p className="text-red-400 text-xs mt-2">{err}</p>}

      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => { e.preventDefault(); send(input); }}
      >
        <input
          className="input flex-1"
          placeholder="Ask about this data…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={sending}
        />
        <button className="btn" type="submit" disabled={sending || !input.trim()}>
          {sending ? "…" : "Send"}
        </button>
      </form>
    </section>
  );
}

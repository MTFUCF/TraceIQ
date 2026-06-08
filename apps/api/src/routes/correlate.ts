/**
 * Correlation route.
 *
 * Author: Matthew Faber
 *
 *   POST /correlate
 *   body (optional): { uploadIds?: string[] }
 *
 * Returns the top correlated attack chains across the user's uploads.
 * See services/correlation.ts for the algorithm.
 */
import { Router } from "express";
import { z } from "zod";
import { requireAuth, type AuthedRequest } from "../middleware/auth.js";
import { correlate } from "../services/correlation.js";
import { listMessages, handleChatTurn, clearMessages } from "../services/chat.js";

export const correlateRouter = Router();

const schema = z.object({
  uploadIds: z.array(z.string().uuid()).optional(),
});

correlateRouter.post("/", requireAuth, async (req: AuthedRequest, res) => {
  const parsed = schema.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: "invalid body" });
  try {
    const chains = await correlate(req.user!.id, parsed.data.uploadIds);
    res.json({ chains });
  } catch (err) {
    console.error("[correlate] failed:", err);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ---------------------------------------------------------------------------
// Cross-upload chat assistant — grounded on the latest correlation chains.
// scope_id is the user's id so each user has a single ongoing conversation
// about their correlated incidents.
// ---------------------------------------------------------------------------

correlateRouter.get("/chat", requireAuth, async (req: AuthedRequest, res) => {
  const messages = await listMessages(req.user!.id, "correlation", req.user!.id);
  res.json({ messages });
});

correlateRouter.post("/chat", requireAuth, async (req: AuthedRequest, res) => {
  const message = typeof req.body?.message === "string" ? req.body.message : "";
  if (!message.trim()) return res.status(400).json({ error: "message is required" });
  try {
    const out = await handleChatTurn(req.user!.id, "correlation", req.user!.id, message);
    res.json(out);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

correlateRouter.delete("/chat", requireAuth, async (req: AuthedRequest, res) => {
  await clearMessages(req.user!.id, "correlation", req.user!.id);
  res.status(204).end();
});

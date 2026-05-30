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

/**
 * Auth routes — login + me.
 *
 * Author: Matthew Faber
 *
 * Endpoints:
 *   POST /auth/login      { email, password } -> { token, user }
 *   GET  /auth/me         (authed) -> { user }
 *
 * The take-home rubric says "basic authentication". We implement that as a
 * username+password form that returns a signed JWT. The frontend sends the
 * JWT on every subsequent request. We deliberately do NOT expose a public
 * /register endpoint — the seeded admin can create other accounts manually
 * via SQL (this is a demo app; uncontrolled signup is a footgun).
 */
import { Router } from "express";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { query } from "../db/client.js";
import { requireAuth, signToken, type AuthedRequest } from "../middleware/auth.js";

export const authRouter = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

authRouter.post("/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid body" });
  }
  const { email, password } = parsed.data;
  const result = await query<{ id: string; email: string; password_hash: string }>(
    "SELECT id, email, password_hash FROM users WHERE email = $1",
    [email],
  );
  const user = result.rows[0];
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });

  const token = signToken(user.id, user.email);
  res.json({ token, user: { id: user.id, email: user.email } });
});

authRouter.get("/me", requireAuth, (req: AuthedRequest, res) => {
  res.json({ user: req.user });
});

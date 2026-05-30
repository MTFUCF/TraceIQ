/**
 * JWT auth middleware.
 *
 * Author: Matthew Faber
 *
 * The frontend stores the JWT in localStorage and sends it as
 *   Authorization: Bearer <token>
 * on every API call. This middleware validates the signature + expiry and
 * attaches `req.user` for downstream handlers. Routes that don't apply it
 * (e.g. POST /auth/login) are public.
 *
 * Trade-off: localStorage is convenient but vulnerable to XSS. For a
 * production hardening pass I'd move to httpOnly cookies + CSRF tokens, but
 * the take-home rubric explicitly calls for "basic authentication" and this
 * keeps the surface small.
 */
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { config } from "../config.js";

export interface AuthedRequest extends Request {
  user?: { id: string; email: string };
}

export function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const header = req.header("authorization") ?? "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "missing bearer token" });
  }
  try {
    const decoded = jwt.verify(token, config.jwtSecret) as {
      sub: string;
      email: string;
    };
    req.user = { id: decoded.sub, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

export function signToken(userId: string, email: string): string {
  return jwt.sign({ email }, config.jwtSecret, {
    subject: userId,
    expiresIn: "12h",
  });
}

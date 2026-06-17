import { NextFunction, Request, Response } from "express";

interface RateLimitOptions {
  /** Length of the sliding window in milliseconds. */
  windowMs: number;
  /** Maximum number of requests allowed per client within the window. */
  max: number;
}

interface ClientBucket {
  count: number;
  resetAt: number;
}

/**
 * A tiny in-process, fixed-window rate limiter. Deliberately dependency-free so
 * the public, unauthenticated demo stays offline-safe (no new npm dependency).
 *
 * It is keyed on the client IP and is intended only to blunt request floods on
 * the mutating demo routes — not as a distributed, production-grade limiter.
 * Buckets are pruned lazily on access so memory stays bounded by active clients.
 */
function createRateLimiter(options: RateLimitOptions) {
  const { windowMs, max } = options;
  if (!Number.isInteger(max) || max < 1) {
    throw new Error("rate limiter max must be a positive integer");
  }
  if (!Number.isInteger(windowMs) || windowMs < 1) {
    throw new Error("rate limiter windowMs must be a positive integer");
  }

  const buckets = new Map<string, ClientBucket>();

  return function rateLimit(req: Request, res: Response, next: NextFunction): void {
    const now = Date.now();
    const key = req.ip ?? "unknown";

    let bucket = buckets.get(key);
    if (!bucket || now >= bucket.resetAt) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }

    bucket.count += 1;

    const remaining = Math.max(0, max - bucket.count);
    const retryAfterSeconds = Math.ceil((bucket.resetAt - now) / 1000);
    res.setHeader("RateLimit-Limit", String(max));
    res.setHeader("RateLimit-Remaining", String(remaining));

    if (bucket.count > max) {
      res.setHeader("Retry-After", String(retryAfterSeconds));
      res.status(429).json({ error: "too many requests" });
      return;
    }

    next();
  };
}

export { createRateLimiter };
export type { RateLimitOptions };

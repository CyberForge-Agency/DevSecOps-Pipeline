import express from "express";
import request from "supertest";
import { app } from "../../src/app";
import { BoundedMap, createItemsRouter } from "../../src/routes/items";
import { createRateLimiter } from "../../src/middleware/rate-limit";

/**
 * Body-size (413) + rate-limit (429) hardening for the public demo API (T-112).
 * The 413 test runs against the real wired `app`; the 429 test builds an
 * isolated app with a tiny limit so it stays fast and deterministic.
 */
describe("Demo API hardening (413 / 429)", () => {
  describe("body-size limit", () => {
    it("rejects an oversized JSON body with a clean 413", async () => {
      // 16kb is the configured cap; ~32kb of name comfortably exceeds it.
      const huge = "x".repeat(32 * 1024);
      const res = await request(app)
        .post("/api/items")
        .set("Content-Type", "application/json")
        .send(JSON.stringify({ name: huge }));

      expect(res.status).toBe(413);
      expect(res.body.error).toBe("request body too large");
    });

    it("still accepts a small body", async () => {
      const res = await request(app)
        .post("/api/items")
        .send({ name: "small" });

      expect(res.status).toBe(201);
    });

    it("keeps /health light (no body limit / rate limit applied)", async () => {
      const res = await request(app).get("/health");
      expect(res.status).toBe(200);
      expect(res.body.status).toBe("ok");
    });
  });

  describe("rate limiting on mutating routes", () => {
    function buildApp(max: number) {
      const limiter = createRateLimiter({ windowMs: 60_000, max });
      const a = express();
      a.use(express.json());
      a.use("/api/items", createItemsRouter(new BoundedMap(1000), limiter));
      return a;
    }

    it("returns 429 once the request budget is exceeded", async () => {
      const max = 3;
      const a = buildApp(max);

      // First `max` POSTs succeed.
      for (let i = 0; i < max; i++) {
        const ok = await request(a).post("/api/items").send({ name: `i-${i}` });
        expect(ok.status).toBe(201);
      }

      // The next POST is over budget.
      const blocked = await request(a).post("/api/items").send({ name: "over" });
      expect(blocked.status).toBe(429);
      expect(blocked.body.error).toBe("too many requests");
      expect(blocked.headers["retry-after"]).toBeDefined();
    });

    it("does not throttle reads (GET stays unlimited)", async () => {
      const a = buildApp(1);

      // Many reads in a row never hit 429 because the limiter is only on
      // the mutating routes.
      for (let i = 0; i < 5; i++) {
        const res = await request(a).get("/api/items");
        expect(res.status).toBe(200);
      }
    });
  });
});

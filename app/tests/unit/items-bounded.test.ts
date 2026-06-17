import express from "express";
import request from "supertest";
import {
  BoundedMap,
  createItemsRouter,
  DEFAULT_CAPACITY,
} from "../../src/routes/items";

/**
 * Builds an isolated app per test using the injection seam, so these assertions
 * never depend on shared global mutable state.
 */
function buildApp(cap: number) {
  const app = express();
  app.use(express.json());
  app.use("/api/items", createItemsRouter(new BoundedMap(cap)));
  return app;
}

describe("Bounded items store", () => {
  it("router accepts an injected store", async () => {
    const app = buildApp(5);
    const res = await request(app).post("/api/items").send({ name: "injected" });
    expect(res.status).toBe(201);
  });

  it("count never exceeds the cap when posting beyond it", async () => {
    const cap = 10;
    const app = buildApp(cap);

    for (let i = 0; i < cap * 3; i++) {
      const post = await request(app)
        .post("/api/items")
        .send({ name: `item-${i}` });
      expect(post.status).toBe(201);

      const list = await request(app).get("/api/items");
      expect(list.body.length).toBeLessThanOrEqual(cap);
    }

    const final = await request(app).get("/api/items");
    expect(final.body.length).toBe(cap);
  });

  it("evicts the oldest entry once capacity is reached", () => {
    const store = new BoundedMap(2);
    const mk = (id: string) => ({ id, name: id, createdAt: "" });

    store.set("a", mk("a"));
    store.set("b", mk("b"));
    store.set("c", mk("c"));

    expect(store.size).toBe(2);
    expect(store.has("a")).toBe(false); // oldest evicted
    expect(store.has("b")).toBe(true);
    expect(store.has("c")).toBe(true);
  });

  it("rejects an invalid capacity", () => {
    expect(() => new BoundedMap(0)).toThrow();
    expect(() => new BoundedMap(-1)).toThrow();
    expect(() => new BoundedMap(1.5)).toThrow();
  });

  it("exposes a sane default capacity of about 1000", () => {
    expect(DEFAULT_CAPACITY).toBe(1000);
  });
});

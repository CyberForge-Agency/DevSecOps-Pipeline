import express from "express";
import request from "supertest";
import { BoundedMap, createItemsRouter } from "../../src/routes/items";

/**
 * Each test builds its own app backed by a freshly injected store via the
 * T-111 injection seam (`createItemsRouter(new BoundedMap())`). There is no
 * shared process-global store and no GET-then-delete-all `beforeEach` reset,
 * so the suite carries no cross-test mutable state and is parallel-safe.
 */
function buildApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/items", createItemsRouter(new BoundedMap(1000)));
  return app;
}

describe("Items API", () => {
  describe("GET /api/items", () => {
    it("returns empty array initially", async () => {
      const app = buildApp();
      const response = await request(app).get("/api/items");

      expect(response.status).toBe(200);
      expect(response.body).toEqual([]);
    });
  });

  describe("POST /api/items", () => {
    it("creates an item and returns 201", async () => {
      const app = buildApp();
      const response = await request(app)
        .post("/api/items")
        .send({ name: "Test Item" });

      expect(response.status).toBe(201);
      expect(response.body).toEqual({
        id: expect.any(String),
        name: "Test Item",
        createdAt: expect.any(String),
      });
    });

    it("returns 400 when name is missing", async () => {
      const app = buildApp();
      const response = await request(app).post("/api/items").send({});

      expect(response.status).toBe(400);
      expect(response.body.error).toBe("name is required");
    });
  });

  describe("GET /api/items/:id", () => {
    it("returns a specific item", async () => {
      const app = buildApp();
      const created = await request(app).post("/api/items").send({ name: "Find Me" });
      const response = await request(app).get(`/api/items/${created.body.id}`);

      expect(response.status).toBe(200);
      expect(response.body.name).toBe("Find Me");
    });

    it("returns 404 for non-existent item", async () => {
      const app = buildApp();
      const response = await request(app).get("/api/items/nonexistent");

      expect(response.status).toBe(404);
      expect(response.body.error).toBe("item not found");
    });
  });

  describe("DELETE /api/items/:id", () => {
    it("deletes an item and returns 204", async () => {
      const app = buildApp();
      const created = await request(app).post("/api/items").send({ name: "Delete Me" });
      const response = await request(app).delete(`/api/items/${created.body.id}`);

      expect(response.status).toBe(204);
    });

    it("returns 404 for non-existent item", async () => {
      const app = buildApp();
      const response = await request(app).delete("/api/items/nonexistent");

      expect(response.status).toBe(404);
      expect(response.body.error).toBe("item not found");
    });
  });
});

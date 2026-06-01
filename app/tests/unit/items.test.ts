import request from "supertest";
import { app } from "../../src/app";

describe("Items API", () => {
  beforeEach(async () => {
    const list = await request(app).get("/api/items");
    for (const item of list.body) {
      await request(app).delete(`/api/items/${item.id}`);
    }
  });

  describe("GET /api/items", () => {
    it("returns empty array initially", async () => {
      const response = await request(app).get("/api/items");

      expect(response.status).toBe(200);
      expect(response.body).toEqual([]);
    });
  });

  describe("POST /api/items", () => {
    it("creates an item and returns 201", async () => {
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
      const response = await request(app).post("/api/items").send({});

      expect(response.status).toBe(400);
      expect(response.body.error).toBe("name is required");
    });
  });

  describe("GET /api/items/:id", () => {
    it("returns a specific item", async () => {
      const created = await request(app).post("/api/items").send({ name: "Find Me" });
      const response = await request(app).get(`/api/items/${created.body.id}`);

      expect(response.status).toBe(200);
      expect(response.body.name).toBe("Find Me");
    });

    it("returns 404 for non-existent item", async () => {
      const response = await request(app).get("/api/items/nonexistent");

      expect(response.status).toBe(404);
      expect(response.body.error).toBe("item not found");
    });
  });

  describe("DELETE /api/items/:id", () => {
    it("deletes an item and returns 204", async () => {
      const created = await request(app).post("/api/items").send({ name: "Delete Me" });
      const response = await request(app).delete(`/api/items/${created.body.id}`);

      expect(response.status).toBe(204);
    });

    it("returns 404 for non-existent item", async () => {
      const response = await request(app).delete("/api/items/nonexistent");

      expect(response.status).toBe(404);
      expect(response.body.error).toBe("item not found");
    });
  });
});

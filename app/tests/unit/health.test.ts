import request from "supertest";
import { app } from "../../src/app";

describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const response = await request(app).get("/health");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      status: "ok",
      timestamp: expect.any(String),
      version: expect.any(String),
    });
  });

  it("returns valid ISO timestamp", async () => {
    const response = await request(app).get("/health");
    const date = new Date(response.body.timestamp);

    expect(date.toISOString()).toBe(response.body.timestamp);
  });
});

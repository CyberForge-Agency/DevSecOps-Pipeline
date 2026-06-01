import request from "supertest";
import { app } from "../../src/app";

describe("GET /api/build-info", () => {
  it("returns 200 with required fields", async () => {
    const res = await request(app).get("/api/build-info");
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("git_sha");
    expect(res.body).toHaveProperty("git_ref");
    expect(res.body).toHaveProperty("build_time");
    expect(res.body).toHaveProperty("run_id");
    expect(res.body).toHaveProperty("repository");
    expect(res.body).toHaveProperty("image_uri");
    expect(res.body).toHaveProperty("image_digest");
    expect(res.body).toHaveProperty("rekor_search_url");
    expect(res.body).toHaveProperty("github_run_url");
    expect(res.body).toHaveProperty("github_commit_url");
    expect(res.body).toHaveProperty("cosign_verify_command");
    expect(res.body).toHaveProperty("cosign_attest_command");
    expect(res.body).toHaveProperty("certificate_identity_pattern");
    expect(res.body).toHaveProperty("oidc_issuer");
  });

  it("returns oidc_issuer pointing to GitHub Actions", async () => {
    const res = await request(app).get("/api/build-info");
    expect(res.body.oidc_issuer).toBe("https://token.actions.githubusercontent.com");
  });

  it("includes a cosign verify command in the response", async () => {
    const res = await request(app).get("/api/build-info");
    expect(typeof res.body.cosign_verify_command).toBe("string");
    expect(res.body.cosign_verify_command).toContain("cosign verify");
  });

  it("rekor_search_url targets search.sigstore.dev", async () => {
    const res = await request(app).get("/api/build-info");
    expect(res.body.rekor_search_url).toContain("search.sigstore.dev");
  });

  it("respects environment variables when set", async () => {
    const origUri = process.env.IMAGE_URI;
    const origDigest = process.env.IMAGE_DIGEST;
    process.env.IMAGE_URI = "myregistry.azurecr.io/test:abc123";
    process.env.IMAGE_DIGEST = "sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";

    const res = await request(app).get("/api/build-info");
    expect(res.body.image_uri).toBe("myregistry.azurecr.io/test:abc123");
    expect(res.body.image_digest).toBe(
      "sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
    );
    expect(res.body.rekor_search_url).toContain(
      "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
    );
    expect(res.body.cosign_verify_command).toContain("myregistry.azurecr.io/test:abc123");

    process.env.IMAGE_URI = origUri;
    process.env.IMAGE_DIGEST = origDigest;
  });

  it("falls back to placeholder when image env vars are unset", async () => {
    const origUri = process.env.IMAGE_URI;
    const origDigest = process.env.IMAGE_DIGEST;
    delete process.env.IMAGE_URI;
    delete process.env.IMAGE_DIGEST;

    const res = await request(app).get("/api/build-info");
    expect(res.body.image_uri).toBe("unknown");
    expect(res.body.cosign_verify_command).toContain("not yet available");

    if (origUri !== undefined) process.env.IMAGE_URI = origUri;
    if (origDigest !== undefined) process.env.IMAGE_DIGEST = origDigest;
  });
});

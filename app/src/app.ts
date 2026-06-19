import path from "path";
import fs from "fs";
import express, { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import { BoundedMap, createItemsRouter, DEFAULT_CAPACITY } from "./routes/items";
import { createRateLimiter } from "./middleware/rate-limit";

interface BuildInfo {
  git_sha: string;
  git_ref: string;
  build_time: string;
  run_id: string;
  run_number: string;
  repository: string;
  workflow_ref: string;
}

interface DeploymentInfo extends BuildInfo {
  image_uri: string;
  image_digest: string;
  run_url: string;
  rekor_search_url: string;
  github_run_url: string;
  github_commit_url: string;
  cosign_verify_command: string;
  cosign_attest_command: string;
  certificate_identity_pattern: string;
  oidc_issuer: string;
}

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
      },
    },
  }),
);
// Cap request bodies so the public demo cannot be flooded with huge payloads.
// Oversized bodies are rejected with a clean 413 by the error handler below.
app.use(express.json({ limit: "16kb" }));

// Serve the showcase page
app.use(express.static(path.join(__dirname, "public")));

// ── Read build-info baked in at Docker build time ──────────────────────────
function readBuildInfo(): BuildInfo {
  const buildInfoPath = path.join(__dirname, "build-info.json");
  try {
    const raw = fs.readFileSync(buildInfoPath, "utf-8");
    return JSON.parse(raw) as BuildInfo;
  } catch {
    return {
      git_sha: "unknown",
      git_ref: "unknown",
      build_time: "unknown",
      run_id: "unknown",
      run_number: "unknown",
      repository: "unknown",
      workflow_ref: "unknown",
    };
  }
}

const buildInfo = readBuildInfo();

app.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    version: process.env.npm_package_version || "0.1.0",
  });
});

// ── /api/build-info — verifiable deployment metadata ───────────────────────
//
// Returns everything needed to independently verify this deployment:
// - Image URI + digest (set by deploy.yml as env vars)
// - GitHub commit + workflow run URLs
// - Cosign verify command with the actual values for THIS image
// - Rekor transparency log search URL
//
// All fields are real values from this exact build/deployment, not placeholders.
app.get("/api/build-info", (_req: Request, res: Response) => {
  const repo = process.env.REPOSITORY || buildInfo.repository;
  const sha = process.env.GIT_SHA || buildInfo.git_sha;
  const runId = process.env.RUN_ID || buildInfo.run_id;
  const imageUri = process.env.IMAGE_URI || "unknown";
  const imageDigest = process.env.IMAGE_DIGEST || "unknown";
  const runUrl =
    process.env.RUN_URL ||
    `https://github.com/${repo}/actions/runs/${runId}`;

  const certIdentityPattern = `https://github.com/${repo}/.github/workflows/sign-and-attest.yml@.*`;
  const oidcIssuer = "https://token.actions.githubusercontent.com";

  // Rekor search by image digest. Anyone can paste this URL to see the
  // public transparency log entry for the signing event.
  const digestHash = imageDigest.startsWith("sha256:")
    ? imageDigest.slice("sha256:".length)
    : imageDigest;
  const rekorSearchUrl = `https://search.sigstore.dev/?hash=${digestHash}`;

  const cosignVerify = imageUri && imageUri !== "unknown"
    ? `cosign verify \\
  --certificate-identity-regexp='https://github.com/${repo}/' \\
  --certificate-oidc-issuer='${oidcIssuer}' \\
  ${imageUri}`
    : "cosign verify ... (image digest not yet available)";

  const cosignAttest = imageUri && imageUri !== "unknown"
    ? `cosign download attestation \\
  --predicate-type=https://cyclonedx.org/bom \\
  ${imageUri}`
    : "cosign download attestation ... (image digest not yet available)";

  const info: DeploymentInfo = {
    ...buildInfo,
    repository: repo,
    git_sha: sha,
    run_id: runId,
    image_uri: imageUri,
    image_digest: imageDigest,
    run_url: runUrl,
    rekor_search_url: rekorSearchUrl,
    github_run_url: runUrl,
    github_commit_url: `https://github.com/${repo}/commit/${sha}`,
    cosign_verify_command: cosignVerify,
    cosign_attest_command: cosignAttest,
    certificate_identity_pattern: certIdentityPattern,
    oidc_issuer: oidcIssuer,
  };

  res.json(info);
});

// Public, unauthenticated demo store — bounded so it cannot be flooded to OOM.
// A small in-process rate limiter blunts request floods on the mutating routes
// (POST/DELETE) only; reads, /health and /api/build-info stay unthrottled.
const itemsMutationLimiter = createRateLimiter({ windowMs: 60_000, max: 60 });
app.use(
  "/api/items",
  createItemsRouter(new BoundedMap(DEFAULT_CAPACITY), itemsMutationLimiter),
);

// JSON error handler: turn body-parser failures into clean JSON responses
// instead of express's default HTML error page (oversized body -> 413,
// malformed JSON -> 400).
app.use(
  (err: unknown, _req: Request, res: Response, next: NextFunction): void => {
    if (err && typeof err === "object" && "type" in err) {
      const type = (err as { type?: string }).type;
      if (type === "entity.too.large") {
        res.status(413).json({ error: "request body too large" });
        return;
      }
      if (type === "entity.parse.failed") {
        res.status(400).json({ error: "invalid JSON body" });
        return;
      }
    }
    next(err);
  },
);

export { app };

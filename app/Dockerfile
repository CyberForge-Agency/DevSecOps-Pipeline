# Stage 1: Build
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS builder
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build && cp -r src/public dist/public

# Build-time metadata baked into the image. These are passed by the CI workflow
# via --build-arg and become part of the image so any consumer can inspect them.
ARG GIT_SHA=unknown
ARG GIT_REF=unknown
ARG BUILD_TIME=unknown
ARG RUN_ID=unknown
ARG RUN_NUMBER=unknown
ARG REPOSITORY=unknown
ARG WORKFLOW_REF=unknown

# Write a build-info.json that the app exposes via /api/build-info.
# IMAGE_DIGEST and IMAGE_URI are unknown here (not yet computed) — they are
# injected as env vars by the deploy workflow after the registry digest is known.
RUN printf '{"git_sha":"%s","git_ref":"%s","build_time":"%s","run_id":"%s","run_number":"%s","repository":"%s","workflow_ref":"%s"}' \
  "$GIT_SHA" "$GIT_REF" "$BUILD_TIME" "$RUN_ID" "$RUN_NUMBER" "$REPOSITORY" "$WORKFLOW_REF" \
  > /build/dist/build-info.json

# OCI image labels — visible via `docker inspect` and ACR API.
LABEL org.opencontainers.image.source="https://github.com/${REPOSITORY}"
LABEL org.opencontainers.image.revision="${GIT_SHA}"
LABEL org.opencontainers.image.created="${BUILD_TIME}"
LABEL org.opencontainers.image.title="cyberforge-demo"
LABEL org.opencontainers.image.description="CyberForge DevSecOps Pipeline demo application"

# Stage 2: Production dependencies
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS deps
WORKDIR /deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# Stage 3: Runtime
# Chainguard's hardened Node image (Wolfi-based, minimal, nonroot uid 65532) is
# patched far faster than gcr.io distroless. We moved off
# gcr.io/distroless/nodejs20-debian12:nonroot because its Debian 12 libssl3 was
# stuck at 3.0.18 with 4 unpatched HIGH/CRITICAL OpenSSL CVEs (CVE-2026-31789,
# -28387, -28388, -28389) and no rebuilt base available upstream. Chainguard's
# node image ships fixed OpenSSL and scans 0 HIGH/CRITICAL.
# Pinned by digest for reproducibility; bump via the same trivy-verified flow.
FROM cgr.dev/chainguard/node:latest@sha256:045335a479d6c59bab89e3caaaf9ed2aed5528d92e2431a3e2afcbf258dba9a6
WORKDIR /app
COPY --from=deps /deps/node_modules ./node_modules
COPY --from=builder /build/dist ./dist
COPY --from=builder /build/package.json ./

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Chainguard runs as nonroot uid 65532 by default; set explicitly for clarity.
USER 65532

# The Chainguard node image's ENTRYPOINT is already /usr/bin/node, so CMD
# supplies only the script path (passed as node's argument).
CMD ["dist/index.js"]

# Reproducibility Statement (Evidence Pack Part I.4)

> Satisfies **T-55** — evidence-pack-specification.md **Part I.4** ("Reproducibility
> statement"), **§7.6** ("Reproducibility. Each release pins commit + build inputs
> (SLSA provenance) so a third party can rebuild and match the digest — the
> strongest possible 'this is really what runs in prod'") and **Appendix X.3**
> (tool & version inventory pinned by digest); struktura §11.7 pt 7
> ("Reprodukowalność").
>
> **Status of the strongest claim:** the *design-level* reproducibility chain
> (pinned commit + pinned base image + locked dependencies + signed SLSA
> provenance binding the artifact-by-digest to its inputs) is **implemented and
> verifiable today**. **Byte-for-byte digest match on independent rebuild is
> `TARGET-STATE`** — it is *not* yet demonstrated, and the precise blockers are
> enumerated in §5. This document states that boundary honestly rather than
> claiming a match that the pipeline does not yet produce. This is consistent with
> SLSA, which does **not** require verified reproducible builds — they are *one*
> optional way to corroborate provenance, not a level requirement
> ([slsa.dev FAQ](https://slsa.dev/spec/v1.0/faq)).

---

## 1. What "reproducibility" means here

Two distinct claims are often conflated. We separate them:

| Claim | Definition | Status in this repo |
| --- | --- | --- |
| **Provenance-anchored rebuild** | A third party can identify *exactly* which source commit, base image, dependency set, and build platform produced the released artifact, and re-run that build. | **IMPLEMENTED** — see §2–§4. |
| **Byte-for-byte reproducibility** | An independent rebuild from the same pinned inputs yields the **same image digest** (`sha256:…`). | **TARGET-STATE** — see §5. |
| **Verified reproducible** (SLSA term) | ≥2 *independent* rebuilders corroborate the provenance by each reproducing the artifact. | **NOT IN SCOPE** for the current single-builder pipeline; documented as a future direction in §6. |

SLSA's own framing (the authority we align to): *"Reproducible"* = identical outputs
from identical inputs; *"verified reproducible"* = multiple independent platforms
corroborate the provenance. SLSA "does not require verified reproducible builds
directly… verified reproducible builds are one option for implementing the
requirements" ([slsa.dev FAQ](https://slsa.dev/spec/v1.0/faq);
[slsa.dev v1.0 future-directions](https://slsa.dev/spec/v1.0/future-directions)).

---

## 2. The pinned inputs (what a rebuild is anchored to)

Every release pins the following. Each row is grounded in a real file in this repo.

| Input | How it is pinned | Source of truth |
| --- | --- | --- |
| **Source commit** | Full 40-char `gitCommit` recorded in SLSA provenance `resolvedDependencies[0].digest.gitCommit` and baked into the image as `org.opencontainers.image.revision`. | `scripts/generate-provenance.sh:70-73`; `app/Dockerfile:12,29` |
| **Base image** | Runtime stage pinned **by digest, not tag** (`cgr.dev/chainguard/node:latest@sha256:045335a4…`). The `:latest` tag is cosmetic; the `@sha256` is the binding. | `app/Dockerfile:48` |
| **Builder base (Node toolchain)** | Build/deps stages use `node:20-alpine`. ⚠️ **Pinned by tag, not digest** (gap — see §5). | `app/Dockerfile:2,35` |
| **Application dependencies** | `npm ci` against a committed `package-lock.json` (exact, locked versions; `--ignore-scripts`). | `app/Dockerfile:5,38` |
| **Build inputs (metadata)** | `GIT_SHA`, `GIT_REF`, `BUILD_TIME`, `RUN_ID`, `RUN_NUMBER`, `REPOSITORY`, `WORKFLOW_REF` injected as `--build-arg` and recorded in provenance `externalParameters` / `internalParameters`. | `.github/workflows/build-and-scan.yml:460-467`; `scripts/generate-provenance.sh:49-66` |
| **Build platform** | `buildType` + `builder.id` (the workflow path) recorded in provenance `runDetails.builder`. | `scripts/generate-provenance.sh:48,77-83` |
| **Output digest** | The image `sha256` from `docker/build-push-action` is the `subject[0].digest` of the provenance and the target of any rebuild comparison. | `.github/workflows/build-and-scan.yml:452,480`; `scripts/generate-provenance.sh:37-43` |
| **Toolchain (scanners/signers)** | Action SHAs + cosign/syft/opa/trivy versions — pinned-by-digest inventory (Appendix X.3). | T-72 `evidence/toolchain-inventory.json` (separate task; cross-referenced, not produced here) |

The provenance that carries these inputs is itself **DSSE/cosign-signed and
Rekor-logged** by the sign-and-attest flow, and its digest is part of the sealed
Merkle root — so the *statement of inputs* is as tamper-evident as the rest of the
pack (`scripts/seal-evidence.sh`; spec §7.1–§7.4).

---

## 3. How a third party rebuilds and compares (procedure)

A reviewer who has the Evidence Pack (or read access to the repo at the release
commit) runs the following. The `verify-reproducibility.sh` helper in this repo
automates steps 1–5 and prints a `MATCH` / `MISMATCH` / `INDETERMINATE` verdict.

```bash
# 0. Inputs you need (all are in the Evidence Pack):
#    - PROVENANCE   : the signed *.intoto.jsonl for the release
#      (or pass --git-commit / --expected-digest / --base-image directly)

# 1. Read the pinned commit + expected digest + base image from the provenance:
GIT_COMMIT=$(jq -r '.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit' provenance.intoto.jsonl)
EXPECTED_DIGEST=$(jq -r '.subject[0].digest | "sha256:" + .sha256' provenance.intoto.jsonl)

# 2. Check out the EXACT source the release was built from:
git clone https://github.com/<owner>/<repo> && cd <repo>
git checkout "$GIT_COMMIT"

# 3. Rebuild the image from the pinned Dockerfile + locked deps.
#    Re-supply the SAME build-args the original build used (commit-derived ones
#    are deterministic; RUN_ID/RUN_NUMBER are per-run — see §5):
docker build app/ \
  --build-arg GIT_SHA="$GIT_COMMIT" \
  --build-arg GIT_REF="<ref-from-provenance>" \
  --build-arg BUILD_TIME="<commit-timestamp-from-provenance>" \
  --build-arg REPOSITORY="<owner/repo>" \
  -t rebuild:local

# 4. Compute the rebuilt image's digest:
REBUILT_DIGEST=$(docker buildx imagetools inspect rebuild:local --format '{{.Manifest.Digest}}' \
                 2>/dev/null || docker inspect --format='{{index .RepoDigests 0}}' rebuild:local)

# 5. Compare:
[ "$REBUILT_DIGEST" = "$EXPECTED_DIGEST" ] && echo MATCH || echo "MISMATCH (expected $EXPECTED_DIGEST, got $REBUILT_DIGEST)"
```

Or, with the helper (preferred — handles the provenance parsing via
`scripts/_repro_parse_prov.py` and emits a machine-readable verdict for the pack):

```bash
cd Pipeline
# Default: emit the statement, no rebuild (safe anywhere) -> verdict DESIGN-ONLY.
scripts/verify-reproducibility.sh \
  --provenance evidence/provenance.intoto.jsonl \
  --emit evidence/reproducibility-statement.json

# Opt-in: actually rebuild from the pinned commit and compare digests.
scripts/verify-reproducibility.sh \
  --provenance evidence/provenance.intoto.jsonl \
  --emit evidence/reproducibility-statement.json \
  --rebuild        # requires docker; records MATCH / MISMATCH honestly
```

Behaviour (honest by design):
- no provenance + no overrides -> `INDETERMINATE` (exit 2; nothing to anchor to);
- pinned inputs, no `--rebuild` (or no docker) -> `DESIGN-ONLY`
  (`digest_match_demonstrated=false`, `byte_reproducibility_status=TARGET-STATE`);
- `--rebuild` + docker + digest match -> `MATCH` (`ACHIEVED`);
- `--rebuild` + docker + mismatch -> `MISMATCH` (exit 1; recorded faithfully).

### What a MATCH would prove
That the released image is *exactly* what this source + these inputs produce — the
strongest possible answer to "is this really what runs in prod?" (spec §7.6).

### What a MISMATCH does **not** by itself prove
A mismatch is the *expected* result today (§5) and indicates *non-determinism in the
build*, **not** tampering — embedded timestamps, layer mtimes, or builder-version
drift commonly differ. The provenance signature + Rekor entry remain the
authoritative tamper-evidence; reproducibility is a *corroborating* control on top.

---

## 4. The machine-readable artifact

`scripts/verify-reproducibility.sh` emits `evidence/reproducibility-statement.json`
into the pack. Shape (the `git_commit` and `rebuild_procedure` keys are the
T-55 verification contract):

```json
{
  "schema": "cyberforge.reproducibility-statement/v1",
  "generated_at": "2026-06-16T00:00:00Z",
  "git_commit": "<40-hex from provenance, or 'unknown'>",
  "git_ref": "<ref>",
  "expected_image_digest": "sha256:<...>",
  "base_image": "cgr.dev/chainguard/node:latest@sha256:045335a4...",
  "base_image_pinned_by_digest": true,
  "builder_base_pinned_by_digest": false,
  "dependency_lock": "app/package-lock.json (npm ci, --ignore-scripts)",
  "build_inputs": { "deterministic": ["GIT_SHA","GIT_REF","BUILD_TIME","REPOSITORY","WORKFLOW_REF"],
                     "non_deterministic": ["RUN_ID","RUN_NUMBER"] },
  "rebuild_procedure": "docs/reproducibility.md §3 / scripts/verify-reproducibility.sh",
  "rebuilt_image_digest": "sha256:<...> | null",
  "digest_match_demonstrated": false,
  "verdict": "DESIGN-ONLY | MATCH | MISMATCH | INDETERMINATE",
  "byte_reproducibility_status": "TARGET-STATE",
  "open_blockers": [ "..." ],
  "slsa_note": "SLSA does not require verified reproducible builds; this is a corroborating control."
}
```

The artifact is included in the manifest and sealed by the existing
`seal-evidence.sh` flow (so it inherits the Merkle root + RFC-3161 timestamp). It
is classified **EVIDENCE-ONLY**: it does not gate the build today (wiring into the
evidence-completeness required set is a separate post-M0 task — see follow-ups).

---

## 5. Why byte-for-byte match is `TARGET-STATE` (the honest gaps)

Independent rebuild is **not expected to match the digest today**. The concrete,
repo-grounded blockers — each fixable — are:

1. **Per-run non-deterministic build-args baked into the image.** `RUN_ID` and
   `RUN_NUMBER` change every run yet are written into `dist/build-info.json`
   (`app/Dockerfile:23-25`) from `--build-arg` (`build-and-scan.yml:464-465`).
   Any byte in the layer ⇒ different layer digest ⇒ different image digest.
   *(`GIT_SHA`, `GIT_REF`, `BUILD_TIME`, `REPOSITORY` are commit-derived and
   therefore deterministic — `BUILD_TIME` is `head_commit.timestamp`, not
   wall-clock — so those do not block a match.)*
2. **No `SOURCE_DATE_EPOCH` / timestamp rewriting.** The build does not set
   `SOURCE_DATE_EPOCH` nor BuildKit's `rewrite-timestamp`, so file mtimes and
   image-history timestamps embed build-time wall-clock values. This is the
   single most common source of container non-determinism
   ([reproducible-builds.org/docs/timestamps](https://reproducible-builds.org/docs/timestamps/);
   ["It's Not Just Timestamps: A Study on Docker Reproducibility", arXiv:2602.17678](https://arxiv.org/html/2602.17678)).
   Note even with `SOURCE_DATE_EPOCH` set, BuildKit currently applies it to image
   *metadata* but **not** to file timestamps inside layers — so this alone is
   necessary, not sufficient.
3. **Builder/deps base pinned by tag, not digest.** `node:20-alpine`
   (`app/Dockerfile:2,35`) can drift between rebuilds as Alpine/Node patch
   releases re-publish the tag. Pin by `@sha256` like the runtime stage already is.
4. **GHA build cache (`type=gha`)** (`build-and-scan.yml:457-458`) can change which
   layers are materialised vs reused; a clean-room rebuild has no cache and may
   differ. Not a *root* cause of non-determinism but a confound when comparing.
5. **No demonstrated independent rebuild yet.** No CI job currently rebuilds and
   compares; `digest_match_demonstrated` is therefore `false`. The helper supports
   running the comparison, but the result has not been recorded as `MATCH`.

> **Empirical confirmation (2026-06-16).** Building `app/` twice from *identical*
> deterministic build-args (`GIT_SHA`, `BUILD_TIME`, `REPOSITORY` fixed; second
> build `--no-cache`) produced **different** image digests
> (`sha256:7ea142dd…` vs `sha256:72e323c3…`). So the non-determinism is real and
> present even when the inputs are held constant — it comes from build-time
> timestamps / layer metadata, not from the inputs. This is *why* the status is
> `TARGET-STATE` and not merely "untested".

### The remediation path to a real digest match (future task)
- Move `RUN_ID`/`RUN_NUMBER` out of the image (keep them in *provenance* only,
  where per-run values belong — they already are, `generate-provenance.sh:60-66`).
- Set `SOURCE_DATE_EPOCH` to the commit timestamp **and** enable BuildKit
  `rewrite-timestamp`, or post-process layer mtimes.
- Pin `node:20-alpine` by digest.
- Add a CI "reproducibility" job that rebuilds clean-room and records the verdict
  into `reproducibility-statement.json` (honest `MATCH`/`MISMATCH`).
Only after a recorded `MATCH` should `byte_reproducibility_status` flip from
`TARGET-STATE` to `ACHIEVED`.

---

## 6. Relationship to the rest of the integrity chain

Reproducibility is the *seventh* and strongest link in spec §7, but it sits **on
top of** controls that already hold and do **not** depend on a digest match:

- **Signed provenance (SLSA)** binds artifact-by-digest → builder + inputs
  (`generate-provenance.sh`), DSSE/cosign-signed + Rekor-logged.
- **Manifest + Merkle root**, cosign-signed and RFC-3161 timestamped
  (`seal-evidence.sh`) — tamper-evident table of contents.
- **WORM retention** (5y) for the sealed pack.

If/when verified-reproducible rebuilders are added, they corroborate the
provenance (SLSA "verified reproducible") — but the pack is already tamper-evident
*without* them. This statement makes the boundary explicit so an auditor is not
misled into reading "reproducible" as "byte-matched today".

---

## 7. Auditor quick-check

| Question | Answer | Evidence |
| --- | --- | --- |
| Is the source commit pinned? | Yes (40-hex). | provenance `resolvedDependencies[].digest.gitCommit` |
| Is the base image pinned by digest? | Runtime: **yes**; builder/deps: **no** (tag). | `app/Dockerfile:48` vs `:2,35` |
| Are dependencies locked? | Yes (`npm ci` + `package-lock.json`). | `app/Dockerfile:5,38` |
| Is a rebuild procedure documented? | Yes (§3 + `verify-reproducibility.sh`). | this file |
| Has a digest **match** been demonstrated? | **No — TARGET-STATE.** | §5; `reproducibility-statement.json.digest_match_demonstrated=false` |
| Does SLSA require the match? | **No** — optional corroboration. | [slsa.dev FAQ](https://slsa.dev/spec/v1.0/faq) |

---

## 8. Sources

- SLSA v1.0 — Provenance: <https://slsa.dev/spec/v1.0/provenance>
- SLSA v1.0 — FAQ (reproducible vs verified-reproducible; not required): <https://slsa.dev/spec/v1.0/faq>
- SLSA v1.0 — Future directions (verified reproducible builds): <https://slsa.dev/spec/v1.0/future-directions>
- SLSA v1.0 — Verifying artifacts: <https://slsa.dev/spec/v1.0/verifying-artifacts>
- Reproducible Builds — Timestamps / `SOURCE_DATE_EPOCH`: <https://reproducible-builds.org/docs/timestamps/>
- "It's Not Just Timestamps: A Study on Docker Reproducibility" (arXiv:2602.17678): <https://arxiv.org/html/2602.17678>
- Bit-for-bit reproducible builds with Dockerfile (BuildKit `rewrite-timestamp`): <https://medium.com/nttlabs/bit-for-bit-reproducible-builds-with-dockerfile-7cc2b9faed9f>
</content>
</invoke>

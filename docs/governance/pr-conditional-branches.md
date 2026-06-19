# PR-conditional branches in CI — enumeration & control rationale (T-124)

> **What this is.** A complete, auditable enumeration of every place a GitHub
> Actions workflow under `.github/workflows/` branches on the trigger event
> (`github.event_name == 'pull_request'` vs a real `push`). The pipeline runs in
> two postures:
>
> - **push (production posture)** — the authoritative run on `main`. Sign, deploy,
>   seal, WORM-archive, and every blocking compliance gate are **enforced
>   fail-closed**. A real failure turns the run red and nothing downstream
>   proceeds.
> - **pull_request (dry-run posture)** — a PR has no production OIDC, no cloud
>   write access, and runs Terraform against ephemeral local state. Steps that
>   require those are skipped, and degrade-honest steps are reported **warn-only**
>   so the dry-run pack still assembles and self-verifies. **No PR-path silently
>   skips a gate that should block on push** — that invariant is what
>   `tests/pr-path-controls.sh` proves.
>
> **Why this matters (the risk this controls).** The danger of a two-posture
> pipeline is a *latent demotion*: a gate that is correctly warn-only on a PR but
> is also (by mistake) never enforced on push — i.e. "green on PR" masquerading as
> "green in production". Each entry below states the **push** behavior explicitly
> so that demotion is visible. The companion test fails if any documented
> conditional disappears or is rewired to the wrong kind of step.
>
> **Scope vs T-68.** This is a *static* control: it proves the enumeration matches
> the workflow source and that the gates are wired correctly. It does **not**
> exercise a live PR against a real GitHub branch-protection block — that
> behavioral proof is **T-68** and remains deferred (needs a real org + a live
> PR).
>
> **Line numbers.** `evidence-pack.yml` in particular grows over time, so absolute
> line numbers drift. The numbers below are accurate at authoring time; the
> authoritative anchor is always the **step name** (the `- name:` of the guarded
> step) and the **pattern**, both of which `tests/pr-path-controls.sh` matches
> dynamically rather than by line number. Regenerate the counts with:
>
> ```bash
> grep -rn "github.event_name" .github/workflows/
> ```

## Three mechanisms used

| Mechanism | Form | Meaning |
|---|---|---|
| **Job/step `if` gate** | `if: github.event_name != 'pull_request'` | The whole job/step is **skipped** on a PR; it runs only on push. Used for sign/deploy/WORM/Azure-login steps that have no meaning (or no creds) on a PR. |
| **Shell event guard** | `if [ "${{ github.event_name }}" != 'pull_request' ]; then … exit 1` | Inside a step, a real (non-PR) condition is a **hard fail**; on a PR the same condition degrades to a warning. Used where the step itself runs in both postures but its *enforcement* must differ. |
| **`IS_PR` / `EVIDENCE_ALLOW_DEGRADE` env** | `IS_PR: ${{ github.event_name == 'pull_request' }}` or `EVIDENCE_ALLOW_DEGRADE: ${{ github.event_name == 'pull_request' && '1' \|\| '' }}` | The step always runs, computes a verdict, and the env flag selects **block (non-PR) vs warn (PR)** inside the step body. The verdict is recorded into the pack regardless of posture. |

---

## `pipeline.yml` — top-level orchestration

| Anchor (step/job, line @ authoring) | Pattern | On `pull_request` | On `push` | Rationale / risk controlled |
|---|---|---|---|---|
| `security-gate` job input `is_pull_request` (~L54) | `github.event_name == 'pull_request'` passed to the reusable workflow | Security gate told it is a PR (selects PR-base diff scanning, degrade posture downstream) | Security gate told it is a push (full enforcement) | Propagates the single trigger signal to the reusable security-gate workflow so the same gate logic enforces on push and degrades on PR. |
| `build-and-scan` job input `push_image` (~L67) | `github.event_name != 'pull_request'` | `push_image=false` — image built + scanned but **not pushed** | `push_image=true` — image pushed to the registry | A PR must never publish an image; only a merged push produces a registry artifact that sign/deploy then consume. |
| `sign-and-attest` job (~L74) | `if: github.event_name != 'pull_request'` | **Skipped** | Runs (Cosign keyless sign + SLSA provenance + SBOM attestation) | Signing requires production OIDC and is meaningless on an unpushed image. Risk: signing a PR image would create an unattributable signature. |
| `deploy` job (~L86) | `if: github.event_name != 'pull_request'` | **Skipped** | Runs (Terraform apply + Container App deploy) | No PR may deploy to staging/prod. This is the primary deploy gate; the deploy.yml shell guards below are the fail-closed backstop. |
| `dast` job (~L99) | `if: github.event_name != 'pull_request'` | **Skipped** | Runs (DAST against the deployed app URL) | DAST needs a live deployed target, which only exists after a push deploy. |

`sign-and-attest.yml:53` references `github.event_name` only as a **Cosign
annotation** (`-a "trigger=…"`) recording the triggering event in the signature;
it is **not** a control branch and is intentionally excluded from the test's
gate set.

---

## `deploy.yml` — fail-closed deploy backstops (shell event guards)

These run inside the deploy job (which `pipeline.yml` already gates to push), so
on a PR they are normally unreached; the in-step guard is the **defense-in-depth
backstop** described in the T-74 comment at `deploy.yml:247`.

| Guarded step (line @ authoring) | Pattern | On `pull_request` | On `push` | Rationale / risk controlled |
|---|---|---|---|---|
| `Terraform Init` (guard ~L255) | `if [ … != 'pull_request' ]; then exit 1` when backend vars absent | PR dry-run: `terraform init -backend=false` on local state (warning) | **Hard fail** if backend vars are unset — refuses a real apply on ephemeral local state | A real apply on ephemeral state would make the T-62 retention OPA gate evaluate a non-authoritative plan. Fail rather than allow it. |
| `assert-crypto (T-28)` (guard ~L326) | `if [ … != 'pull_request' ]` selects block vs warn | exit ≠0 → warning (NEEDS-CI, not enforced) | exit ≠0 (crypto FAIL **or** INDETERMINATE) → **hard fail**, blocks apply | A.9 crypto posture must be proven against the live plan before WORM data lands; an honest INDETERMINATE also blocks (never a silent pass). |
| `assert-retention (T-48)` (guard ~L357) | `if [ … != 'pull_request' ]` selects block vs warn | exit ≠0 → warning | exit ≠0 (below floor / WORM off / unlocked) → **hard fail**, blocks apply | A.5 retention floor (≥1825d) + WORM-lock must hold before apply; reversible WORM downgrades to INDETERMINATE and still blocks on push. |

---

## `evidence-pack.yml` — degrade-honest gates + push-only archival

### A. Verdict steps with `IS_PR` (block on push, warn on PR; verdict always sealed)

Each step computes a real verdict, writes it into the pack regardless of posture,
and uses `IS_PR` to decide block-vs-warn. The risk controlled is "a green pack
that does not imply the gate actually passed" (blueprint §6.3-C): on push, a
blocking failure here turns the pack red.

| Guarded step (line @ authoring) | On `pull_request` | On `push` | What it gates |
|---|---|---|---|
| `Generate consolidated security report` (~L120, env L122) | WARN if zero/parse-error reports | **FAIL** if zero parsed or any required scanner errored | T-43 — a corrupt/empty scanner output can no longer pass silently. |
| `Compliance gate — aggregate A.1-A.10 (signed)` (~L278, env L280) | WARN on blocking FAIL/INDETERMINATE | **FAIL** on blocking FAIL/INDETERMINATE; missing verdict is itself a FAIL | T-30 — signed A.1–A.10 state-of-compliance; closes the warn-only hole. |
| `Compliance gate (blocking on non-PR)` (~L392, env L394) | WARN | **FAIL** (fail-closed admission, spec C.13) | Matrix blocking-failures gate. |
| `Generate Part C/D evidence (VEX, SoA maturity, residual risk, scope)` (~L444, env L446) | WARN | **FAIL** on BLOCKING (vex/applicability/risk_acceptance); soa_maturity is EVIDENCE-ONLY | T-104+ Part C/D. |
| `Generate Part C runtime/threat/cloud evidence` (~L565, env L567) | WARN | **FAIL** if required output missing/invalid | T-115/T-117/T-118. |
| `Generate reproducibility statement (T-55)` (~L661, env L663) | WARN | **FAIL** if missing/invalid | T-55 reproducibility. |
| `Generate measured tool versions (T-18/T-32)` (~L732, env L734) | WARN | **FAIL** if file empty/invalid JSON | T-18/T-32 measured toolchain versions. |
| `Generate + sign toolchain inventory (T-72)` (~L756, env L758) | WARN (degrade-honest signing) | **FAIL** if missing/invalid | T-72 toolchain inventory. |
| `Generate + sign source-control drift evidence (T-119)` (~L813, env L815) | WARN | **FAIL** on genuine drift; INDETERMINATE (no live token) is honest, not a fail | T-119 — drift is BLOCKING on push, INDETERMINATE allowed offline. |
| `Aggregate compliance-gate results (T-73)` (~L914, env L916) | WARN | **FAIL** if required aggregation missing | T-73 aggregate. |
| `Generate crosswalk, gap register, residency assertion (T-102/T-103/T-109)` (~L1049, env L1051) | WARN if any artifact missing/invalid | **FAIL** if `crosswalk.json` / `gap-register.json` / `residency.json` missing/invalid | T-102/T-103/T-109 — `residency.json` is now emitted fail-closed on push. |
| `OPA evidence completeness (blocking on non-PR)` (~L1223, env L1225) | WARN | **FAIL** on incomplete evidence | OPA completeness gate over the assembled pack. |

### B. Seal steps with `EVIDENCE_ALLOW_DEGRADE`

`EVIDENCE_ALLOW_DEGRADE` is `'1'` on a PR and **unset** on push, so the sealing
toolchain hard-fails on push when a tool/artifact is missing but soft-degrades on
a PR.

| Guarded step (line @ authoring) | On `pull_request` (`=1`) | On `push` (unset) | What it gates |
|---|---|---|---|
| `Build audit-grade PDF evidence` (~L1337, env L1342) | Missing render/verapdf/cosign → soft degrade | Missing render output / veraPDF failure / cosign failure → **hard fail** | The seal itself (qpdf→veraPDF→cosign→RFC-3161→PAdES). |
| `Sealing completeness self-test` (~L1439, env L1441) | Missing required artifact → WARN | Missing/zero-byte/invalid required integrity artifact → **hard fail** | T-58/T-42 — the complete integrity-chain artifact set must land before WORM. |

### C. Push-only `if` gates (skipped on PR)

| Guarded step (line @ authoring) | Pattern | On `pull_request` | On `push` | Rationale / risk controlled |
|---|---|---|---|---|
| `Assert Merkle-root cosign bundle (anti-regression)` (~L1410, gate L1415) | `if: github.event_name != 'pull_request'` | **Skipped** | Runs — fails hard if `merkle-root.cosign.bundle` missing/empty | §6.2-A anti-regression: the headline keyless-identity-over-Merkle-root claim must really be produced on push. |
| `Azure Login (OIDC)` (~L1491, gate L1492) | `if: github.event_name != 'pull_request'` | **Skipped** | Runs (production OIDC) | PRs have no production OIDC for blob upload. |
| `Upload to Azure Blob WORM storage` (~L1499, gate L1501) | `if: github.event_name != 'pull_request'` | **Skipped** | Runs — archives the pack to 5-year immutable WORM | A PR must never write to the production WORM store. |
| `Job Summary` WORM-status block (shell guard ~L1605) | `if [ … != "pull_request" ]` | Skips the blob-upload status lines | Renders the WORM upload status into the job summary | Reporting-only; no enforcement, but documented for completeness. |

---

## Invariants the companion test enforces

`tests/pr-path-controls.sh` (run from the `Pipeline/` directory) statically
verifies, with **non-zero exit on any violation**:

1. **Enumeration completeness** — every PR-conditional category documented above
   is still present in the workflow source (the test fails if a category drops to
   zero, catching a silent removal of a gate).
2. **Correct wiring** — the push-only `if` gates guard sign/deploy/seal/WORM
   steps (matched by step name), not innocuous steps; and the `IS_PR` /
   `EVIDENCE_ALLOW_DEGRADE` flags are wired with the exact block-vs-warn
   expression.
3. **No latent demotion** — every step whose name advertises "blocking on non-PR"
   actually carries a PR-conditional enforcement mechanism (an `if` gate, a shell
   event guard, `IS_PR`, or `EVIDENCE_ALLOW_DEGRADE`); a step that *claims* to
   block on push but has no posture switch is a finding and fails the test.
4. **Sign/deploy/DAST are PR-skipped** — the four production-only jobs in
   `pipeline.yml` each carry the `if: github.event_name != 'pull_request'` gate.

It does **not** assert a live branch-protection PR block (T-68, deferred).

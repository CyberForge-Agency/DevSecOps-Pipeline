# Gate-Enforcement Proof (T-89)

A deterministic, **local**, **founder-independent** proof that the pipeline's
security/compliance gates actually **BLOCK a bad PR / bad input** — captured as
evidence, not asserted as a slogan.

- **Script:** [`scripts/prove-gate-blocks-bad-pr.sh`](../scripts/prove-gate-blocks-bad-pr.sh)
- **Run it:** `scripts/prove-gate-blocks-bad-pr.sh`
- **Pass condition:** exit `0` and a `6/6 negative tests PASS` table.

---

## Why this exists

Every other gate in the repo answers one question: *"does the GOOD evidence pack
pass?"* A technical buyer's cheapest falsification is the **opposite** question:

> "If I hand you a BAD input, does the gate truly block — or does it wave
> everything through and only *look* like a control?"

A green CI badge proves the gates *ran*. It does **not** prove they *enforce*. A
gate that has silently regressed to `exit 0` on every input (fail-open) produces
exactly the same green badge as a working gate, right up until a real CRITICAL CVE
or an unpinned action ships to production. This is the failure mode the
compliance-matrix keystone (T-12) was built to close — the era when an empty `{}`
`security-report.json` "PASSed DORA Art.16.1.a".

This script is the standing, deterministic answer. It feeds **six known-bad
inputs** straight at the **real gate code** (the same scripts the CI jobs invoke —
no mocks, no re-implementation) and asserts each one **blocks**. Anyone can run it
in seconds, on a laptop, with no access to the founder, no GitHub credentials, and
no cloud — hence *founder-independent*.

---

## What it proves (and what it does NOT)

| | This script (T-89) | Live-PR enforcement (T-68) |
|---|---|---|
| Claim | The gate **logic** blocks bad input | The **platform** blocks a real PR/merge |
| Scope | Local, offline, deterministic | GitHub branch protection + required checks + OIDC + a real CI run |
| Evidence | This PASS/FAIL table + exit code | A real blocked PR / required-check failure recorded in CI |
| Status | **Provable now** (below) | **NEEDS-CI** — cannot be faked here |

**Honesty boundary (explicit):** this proof demonstrates that the gate *code*
correctly rejects bad inputs. It does **NOT** claim that a live GitHub Pull Request
was blocked by branch protection, that required status checks are wired, or that
merge/deploy was actually prevented on the platform. That platform-binding claim is
**T-68** and requires a real CI run plus repository settings (OIDC, required
checks, branch protection) — it is labelled **NEEDS-CI** and is *not* asserted
here. The two are complementary: T-89 proves the lock works; T-68 proves the lock
is fitted to the door.

The harness is also designed to be **non-vacuous**. A gate that blocks *everything*
(fail-closed on all input) is just as broken as one that blocks *nothing* — it is
not enforcing, it is refusing. So for every case where a "good" counterpart is
cheap to build (a, c, d, f), the script *also* feeds the **good** input and asserts
the gate **passes** it. A case is only a PASS when **both** halves hold: the bad
input blocks **and** the good input passes.

---

## The six negative tests

Each row feeds a known-bad input to the **real** gate and asserts it blocks
(non-zero exit, or a non-empty OPA `deny` set). Exit-code convention follows the
shared T-33 envelope: `0 = PASS`, `1 = FAIL (blocking)`, `2 = INDETERMINATE
(blocking)` — both `1` and `2` are "blocked".

| ID | Bad input | Real gate exercised | Expected block |
|----|-----------|---------------------|----------------|
| a | `security-report.json` with 1 **CRITICAL** CVE | `scripts/generate-compliance-matrix.sh` | exit `1` (vuln-scan row FAIL) |
| b | **empty `{}`** evidence dir | `generate-compliance-matrix.sh` **and** `aggregate-compliance.py --no-run` | both non-zero (INDETERMINATE — no silent PASS) |
| c | SARIF document with `version: 2.0.0` | `scripts/validators/sarif_conformance.py` | exit `1` (known-bad format FAIL) |
| d | WORM retention of **365 days** (`< 1825` floor) | `scripts/validators/assert-retention.py` | exit `1` (below DORA 5-year floor FAIL) |
| e | planted unpinned `actions/checkout@v4` | `scripts/check-action-pins.sh` | exit `1` (mutable-tag ref FAIL) |
| f | OPA deployment-gate input `critical_cves: 1` | `opa eval … data.compliance.deployment.deny` | `deny` set **non-empty** (deploy blocked) |

Case **(f)** mirrors the *exact* invocation in
[`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml) — the same
`opa eval -d policies/deployment-gate.rego -i <input> 'data.compliance.deployment.deny'
--format raw` query whose non-empty result the deploy job treats as a hard
`exit 1`.

---

## How to run it (founder-independent walkthrough)

No founder, no credentials, no cloud required. From the Pipeline repo root:

```bash
# 1. Prerequisites (the same tools the gates themselves use):
#    bash, python3, jq, opa   — the script preflights these and refuses to fake a
#    pass if any are missing (an un-exercisable gate is reported as FAIL, never PASS).

# 2. Run the proof:
scripts/prove-gate-blocks-bad-pr.sh
echo "exit code: $?"     # 0 == every bad input was correctly blocked
```

The script creates **all** of its fixtures under `mktemp -d` and removes them on
exit via a `trap`. **It never writes into the repo working tree.** Re-running it is
idempotent and deterministic — same inputs, same table, every time.

Interpreting the result:

- **Exit `0` + `6/6 negative tests PASS`** — the gate enforcement logic works. The
  gates reject bad input and accept good input.
- **Exit `1`** — a gate either let a bad input through (regressed **open** — the
  dangerous case) or blocked a good input (regressed **closed** — refusing, not
  enforcing) or could not be exercised (missing dependency). Do **not** trust the
  green pipeline until the named case is fixed.

---

## Captured output of one run

The literal output of one run on `2026-06-17` (exit code `0`):

```text
== T-89 gate-enforcement proof: feeding KNOWN-BAD inputs at the REAL gates ==
   workspace: /tmp/prove-gate-bHkLGo (mktemp; auto-removed; repo working tree untouched)

+----+--------------------------------------------------------------+---------+
| ID | NEGATIVE TEST (bad input must BLOCK)                         | VERDICT |
+----+--------------------------------------------------------------+---------+
| a  | 1 CRITICAL CVE -> compliance-matrix                          | PASS    |
| b  | empty {} evidence dir -> matrix + aggregate                  | PASS    |
| c  | SARIF version 2.0.0 -> sarif_conformance                     | PASS    |
| d  | WORM retention 365d (<1825 floor) -> assert-retention        | PASS    |
| e  | unpinned actions/checkout@v4 -> check-action-pins            | PASS    |
| f  | OPA deployment-gate critical_cves=1 -> deny                  | PASS    |
+----+--------------------------------------------------------------+---------+

Detail:
  (a) PASS
      blocked: gate exit 1 (non-zero); control good (0-CRITICAL vuln-scan row=PASS) passed (exit 0)
  (b) PASS
      blocked: matrix exit 1, aggregate exit 1 (both non-zero; no silent PASS)
  (c) PASS
      blocked: gate exit 1 (non-zero); control good (SARIF 2.1.0) passed (exit 0)
  (d) PASS
      blocked: gate exit 1 (non-zero); control good (1825d locked) passed (exit 0)
  (e) PASS
      blocked: gate exit 1 (non-zero); control good (SHA-pinned checkout) passed (exit 0)
  (f) PASS
      blocked: deny=["Cannot deploy with 1 critical CVEs"] (len 1); control good input deny empty (len 0)

RESULT: 6/6 negative tests PASS — every bad input was correctly BLOCKED.
        The gate ENFORCEMENT LOGIC works locally (NOT a live-PR claim; see T-68 / NEEDS-CI).
```

> The `workspace:` path contains a per-run random suffix from `mktemp` and is
> removed on exit, so it differs between runs; everything else is deterministic.

---

## Relationship to other gates

- **T-12 / T-19** (`generate-compliance-matrix.sh`) — the content-validated
  compliance matrix this proof exercises for cases (a) and (b).
- **T-30** (`aggregate-compliance.py`) — the organizational gate exercised for the
  aggregate half of case (b).
- **T-125** (`sarif_conformance.py`) — the SARIF 2.1.0 conformance gate, case (c).
- **T-48** (`assert-retention.py`) — the A.5 retention/WORM floor, case (d).
- **T-71** (`check-action-pins.sh`) — the unpinned-action supply-chain guard, case (e).
- **deployment-gate.rego** (exercised live by `deploy.yml`) — the admission policy,
  case (f).
- **T-68** (NEEDS-CI) — the *live-PR* enforcement claim this proof deliberately does
  **not** make. See the boundary table above.

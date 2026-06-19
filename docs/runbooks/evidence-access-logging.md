# Evidence-Pack Store Access Logging (tamper-evident)

> SPEC §7 item 7 — tamper-evident audit logging of the **evidence pack store
> itself**: who read, listed, or exported a sealed evidence pack.
>
> Control id: **A.7.7** · Validator: `scripts/validators/check_access_log.py` ·
> Artifact: `access-log-posture.json` · Tier: **EVIDENCE-ONLY**

## Why this control exists

The pipeline already proves *integrity* of each sealed pack (Merkle manifest +
cosign signature + RFC-3161 timestamp). Integrity answers "was the pack
altered?" It does **not** answer "**who looked at it, and did anyone try to
export or delete it?**" An auditor assessing the chain-of-custody of evidence
asks for an access trail over the evidence store, and that trail must itself be
tamper-evident — otherwise an attacker (or an insider) who exfiltrates a pack
could also scrub the record of having done so.

This control records access events (read / list / export / download /
delete-attempt) against the evidence container and binds them into an
append-only **hash chain** so that any deletion or reordering of past entries is
detectable.

## Target design (Azure)

```
                 read/list/export/delete on evidence container
Evidence Blob container ─────────────────────────────────────────►
        │  (StorageRead, StorageWrite, StorageDelete log categories)
        │  Azure Storage *diagnostic settings*
        ▼
Azure Monitor diagnostic pipeline
        │  routed to a DEDICATED, SEPARATE Storage account
        ▼
Immutable (WORM) append-only log container
   - time-based retention policy (>= evidence retention window)
   - legal hold capable
   - the identity that can WRITE logs cannot DELETE/OVERWRITE them
```

Key properties:

1. **Separation of duties** — diagnostic logs land in a *different* storage
   account from the evidence packs. Compromising the evidence container does not
   grant the ability to rewrite its access history.
2. **Immutability (WORM)** — the log container carries an Azure Blob
   *immutability policy* (time-based retention + optional legal hold). Once
   written, an access record cannot be modified or deleted until the retention
   window expires. This is the platform-level tamper-evidence.
3. **Hash chain (defence in depth / portability)** — on export, each access
   record is normalised into a chain entry that carries `prev_hash`
   (the previous entry's hash) and `entry_hash` (sha256 over this entry's
   canonical payload, which *includes* `prev_hash`). The genesis entry uses the
   all-zero hash. This makes tamper-evidence verifiable **offline and
   independently of Azure** — a single removed or edited record breaks the
   chain. The schema for the exported log is
   `schemas/access-log-posture.schema.json`.

### How the diagnostic setting is provisioned

- Enable a **diagnostic setting** on the evidence Storage account targeting the
  blob service, with categories `StorageRead`, `StorageWrite`, `StorageDelete`.
- Route to a **dedicated immutable log container** in a separate storage account
  (Terraform: `azurerm_monitor_diagnostic_setting` +
  `azurerm_storage_container_immutability_policy`).
- Set the immutability retention to **>= the evidence retention window** so the
  access trail outlives the packs it protects.

## The exported log format

An export job reads the Azure diagnostic logs and emits
`evidence/access-log.jsonl` (one JSON entry per line) or a wrapper object
matching `schemas/access-log-posture.schema.json`. Each entry:

```json
{
  "seq": 0,
  "timestamp": "2026-06-18T09:00:00Z",
  "operation": "export",
  "principal": "auditor@bank.example",
  "object_path": "evidence/pack-2026-06-18.tar.gz",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "entry_hash": "<sha256 of canonical payload incl. prev_hash>"
}
```

`entry_hash = sha256( canonical_json( {all fields except entry_hash} ) )` where
the canonical form is `json.dumps(payload, sort_keys=True,
separators=(",", ":"))`. The chain rule: `entries[N].prev_hash ==
entries[N-1].entry_hash`, and `entries[0].prev_hash` is 64 zero hex chars.

## What the validator asserts (and why it is honest)

`check_access_log.py` looks for the exported access log and:

- **PASS** — the log is present, schema-valid, non-empty, and the hash chain
  verifies end to end (every `prev_hash` links, every `entry_hash` recomputes).
- **FAIL** — the log is present but the chain is **broken** (a recomputed hash
  mismatches, a `prev_hash` does not link, or sequence numbers are not
  contiguous). A broken chain is positive evidence of tampering / corruption.
- **INDETERMINATE** — **no exported access log is present** (the honest offline
  default), or the log is present but empty. There is no live Azure diagnostic
  log offline, so the validator does **not** fabricate a PASS; it states plainly
  that the live evidence-store access log is missing and what is required to
  produce it.

Because the live capture is an Azure *runtime* concern (it cannot be proven from
inside an offline pipeline run), the control is **EVIDENCE-ONLY**: the
INDETERMINATE/FAIL verdict is recorded with its measured chain length but never
blocks the build. It surfaces the gap honestly rather than hiding it.

## Honest current state

There is **no live Azure Storage diagnostic log and no immutable log container
provisioned yet**, and therefore no exported `access-log.jsonl`. The validator
consequently emits **INDETERMINATE** with the detail "no live evidence-store
access log (needs Azure Storage diagnostic logs -> immutable container)". This
is the truthful posture: the design is specified above, but the runtime evidence
does not yet exist, so no PASS is claimed.

## Remediation (to reach PASS)

1. Provision the diagnostic setting + immutable log container per the Terraform
   sketch above.
2. Stand up the export job that converts Azure diagnostic logs into the
   hash-chained `access-log.jsonl` (or wrapper object) per the schema.
3. Include `evidence/access-log.jsonl` in the evidence pack so
   `check_access_log.py` can verify the chain and emit PASS.

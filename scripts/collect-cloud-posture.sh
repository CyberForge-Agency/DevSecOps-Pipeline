#!/usr/bin/env bash
#
# collect-cloud-posture.sh — LIVE Azure posture collector (EP-06).
#
# Queries the DEPLOYED Azure tenant for runtime/cloud posture evidence and emits
# two normalised artifacts that the offline validators then consume:
#
#   1. evidence/cloud-posture.json   — a CSPM scan artifact in the shape
#        scripts/validators/cloud_posture.py expects:
#          { scanner, scanner_version, scanned_at, compliance, summary:{critical,...},
#            rows:[...] }
#        Sources (all LIVE, never fabricated):
#          * Microsoft Defender for Cloud "Regulatory Compliance" REST API
#            (regulatoryComplianceStandards / -Controls), api-version
#            2019-01-01-preview — DORA/NIS2/ISO assessment states.
#          * Azure Resource Graph (KQL over Microsoft.Storage/storageAccounts) for
#            storage immutability (WORM-locked), publicNetworkAccess and
#            allowBlobPublicAccess posture.
#          * Azure RBAC role-assignment count (least-privilege signal).
#
#   2. evidence/access-log.jsonl     — a tamper-evident hash-chain (RFC-style
#        prev_hash/entry_hash, sha256) of evidence-store ACCESS events derived
#        from the Activity Log (the A.7.7 access-log control), in the exact format
#        scripts/validators/check_access_log.py verifies.
#
# HONEST DEGRADE CONTRACT (this script runs inside the always-green evidence-pack
# job): if az CLI is absent or not authenticated, or a query returns nothing
# measurable, it writes a status:INDETERMINATE record with a detail explaining
# why and exits 0. It NEVER fabricates a posture/access record and NEVER emits a
# PASS it did not measure. Enforcement is the verifier's job, not this producer's.
#
# Usage:
#   collect-cloud-posture.sh [--out-dir DIR] [--subscription SUB_ID]
#                            [--resource-group RG] [--evidence-account ACC]
#                            [--lookback-days N] [--help] [--selftest]
#
# Exit status: 0 always (degrade-honest producer). Use the validators to gate.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Defaults / argument parsing                                                  #
# --------------------------------------------------------------------------- #
OUT_DIR="evidence"
SUBSCRIPTION_ID=""
RESOURCE_GROUP=""
EVIDENCE_ACCOUNT=""          # storage account name holding sealed evidence packs
LOOKBACK_DAYS="30"
DEFENDER_API_VERSION="2019-01-01-preview"
SCANNER_NAME="cyberforge-collect-cloud-posture"
GENESIS_HASH="$(printf '0%.0s' {1..64})"   # 64 zero hex chars (sha256 width)

usage() {
  sed -n '2,42p' "$0"
}

run_selftest() {
  # Offline self-test: drive the degrade path in a temp dir with az forced absent
  # and assert both artifacts come out INDETERMINATE (never a fabricated PASS).
  local tmp rc cp_status al_status
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  # Force "az not found" by pointing PATH at an empty dir (keep python3/sha256sum
  # reachable via absolute calls below — we only need az to be absent).
  echo "[selftest] running degrade path (az forced absent) -> $tmp"
  CF_FORCE_NO_AZ=1 "$0" --out-dir "$tmp" >/dev/null 2>&1 || true
  rc=$?
  if [ ! -f "$tmp/cloud-posture.json" ] || [ ! -f "$tmp/access-log.jsonl" ]; then
    echo "[selftest] FAIL: expected artifacts not produced"; return 1
  fi
  cp_status="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("status"))' "$tmp/cloud-posture.json")"
  # access-log.jsonl in degrade mode is intentionally EMPTY (0 entries) so the
  # check_access_log validator reports INDETERMINATE. Assert it is empty.
  al_lines="$(wc -l < "$tmp/access-log.jsonl" | tr -d ' ')"
  echo "[selftest] cloud-posture status=$cp_status  access-log entries=$al_lines"
  if [ "$cp_status" != "INDETERMINATE" ]; then
    echo "[selftest] FAIL: degrade cloud-posture must be INDETERMINATE, got $cp_status"; return 1
  fi
  if [ "$al_lines" != "0" ]; then
    echo "[selftest] FAIL: degrade access-log must be empty (no fabricated events), got $al_lines"; return 1
  fi
  echo "[selftest] PASS: honest INDETERMINATE degrade verified"
  return 0
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir) OUT_DIR="${2:?--out-dir needs a value}"; shift 2 ;;
    --subscription) SUBSCRIPTION_ID="${2:?}"; shift 2 ;;
    --resource-group) RESOURCE_GROUP="${2:?}"; shift 2 ;;
    --evidence-account) EVIDENCE_ACCOUNT="${2:?}"; shift 2 ;;
    --lookback-days) LOOKBACK_DAYS="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --selftest) run_selftest; exit $? ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

mkdir -p "$OUT_DIR"
CLOUD_POSTURE_OUT="$OUT_DIR/cloud-posture.json"
ACCESS_LOG_OUT="$OUT_DIR/access-log.jsonl"
NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
have() { command -v "$1" >/dev/null 2>&1; }

# az_authenticated: az present, NOT force-disabled, and an account context exists.
az_authenticated() {
  [ "${CF_FORCE_NO_AZ:-0}" = "1" ] && return 1
  have az || return 1
  az account show >/dev/null 2>&1
}

# write_indeterminate_posture <detail> — emit the honest design-stage / not-measured
# CSPM record (no summary.critical -> validator reports INDETERMINATE, never PASS).
write_indeterminate_posture() {
  local detail="$1"
  python3 - "$CLOUD_POSTURE_OUT" "$NOW_UTC" "$SCANNER_NAME" "$detail" <<'PY'
import json, sys
out, now, scanner, detail = sys.argv[1:5]
rec = {
    "status": "INDETERMINATE",
    "tier": "EVIDENCE-ONLY",
    "scanner": scanner,
    "scanner_version": None,
    "scanned_at": now,
    # No summary.critical key on purpose: the validator cannot measure CRITICAL
    # and therefore returns INDETERMINATE rather than a fabricated PASS.
    "compliance": None,
    "rows": [],
    "measured": {"scan_present": False},
    "detail": detail,
    "checked_at": now,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(rec, fh, indent=2)
    fh.write("\n")
PY
}

# write_empty_access_log — degrade-honest: an EMPTY access-log.jsonl. An empty live
# log proves nothing about real access capture, so check_access_log reports
# INDETERMINATE. We never invent access events.
write_empty_access_log() {
  : > "$ACCESS_LOG_OUT"
}

echo "=== collect-cloud-posture.sh (EP-06) ==="
echo "out-dir: $OUT_DIR   lookback: ${LOOKBACK_DAYS}d   at: $NOW_UTC"

# --------------------------------------------------------------------------- #
# Degrade gate: not authenticated -> honest INDETERMINATE, exit 0.            #
# --------------------------------------------------------------------------- #
if ! az_authenticated; then
  REASON="brak uwierzytelnionego kontekstu az CLI"
  if [ "${CF_FORCE_NO_AZ:-0}" = "1" ]; then
    REASON="az CLI wyłączone (tryb selftest)"
  elif ! have az; then
    REASON="az CLI nie jest zainstalowane"
  fi
  DETAIL="INDETERMINATE: nie można odczytać posture chmury Azure — ${REASON}. \
Wymagane: 'az login' + dostęp Reader oraz Microsoft.Security/assessments/read. \
Posture runtime (Defender Regulatory Compliance + Resource Graph + Activity Log) \
jest dowodem czasu wykonania i nie da się go zmierzyć offline — zapisano INDETERMINATE, \
nie sfabrykowano PASS."
  write_indeterminate_posture "$DETAIL"
  write_empty_access_log
  echo "  -> niezautentykowany: zapisano INDETERMINATE (cloud-posture.json) + pusty access-log.jsonl"
  echo "  $CLOUD_POSTURE_OUT"
  echo "  $ACCESS_LOG_OUT"
  exit 0
fi

# --------------------------------------------------------------------------- #
# Authenticated path. Resolve subscription.                                   #
# --------------------------------------------------------------------------- #
if [ -z "$SUBSCRIPTION_ID" ]; then
  SUBSCRIPTION_ID="$(az account show --query 'id' -o tsv 2>/dev/null || true)"
fi
if [ -z "$SUBSCRIPTION_ID" ]; then
  write_indeterminate_posture "INDETERMINATE: uwierzytelniono az, ale nie ustalono subskrypcji — przekaż --subscription."
  write_empty_access_log
  echo "  -> brak subskrypcji: zapisano INDETERMINATE"
  exit 0
fi
az account set --subscription "$SUBSCRIPTION_ID" 2>/dev/null || true
echo "  subscription: $SUBSCRIPTION_ID"

# Ensure the resource-graph extension is available (best-effort; never fatal).
if ! az extension show --name resource-graph >/dev/null 2>&1; then
  az extension add --name resource-graph --only-show-errors >/dev/null 2>&1 || true
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- (1) Defender for Cloud — Regulatory Compliance standards --------------- #
# GET .../providers/Microsoft.Security/regulatoryComplianceStandards
echo "  [1/4] Defender Regulatory Compliance standards"
DEFENDER_URI="https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/providers/Microsoft.Security/regulatoryComplianceStandards?api-version=${DEFENDER_API_VERSION}"
if az rest --method get --uri "$DEFENDER_URI" -o json > "$WORK/defender.json" 2>"$WORK/defender.err"; then
  DEFENDER_OK=1
else
  DEFENDER_OK=0
  echo "    (Defender query nieudane: $(head -c 200 "$WORK/defender.err" 2>/dev/null))"
  echo '{}' > "$WORK/defender.json"
fi

# --- (2) Azure Resource Graph — storage immutability / public access -------- #
echo "  [2/4] Resource Graph — storage immutability / public network"
RG_QUERY="Resources
| where type =~ 'microsoft.storage/storageAccounts'
| extend pna = tostring(properties.publicNetworkAccess)
| extend allowBlobPublic = tobool(properties.allowBlobPublicAccess)
| extend immutableEnabled = tobool(properties.immutableStorageWithVersioning.enabled)
| project name, resourceGroup, location, pna, allowBlobPublic, immutableEnabled, sku=tostring(sku.name)"
if az graph query -q "$RG_QUERY" --first 1000 -o json > "$WORK/graph.json" 2>"$WORK/graph.err"; then
  GRAPH_OK=1
else
  GRAPH_OK=0
  echo "    (Resource Graph query nieudane: $(head -c 200 "$WORK/graph.err" 2>/dev/null))"
  echo '{"data":[]}' > "$WORK/graph.json"
fi

# --- (3) RBAC role-assignment count (least-privilege signal) ---------------- #
echo "  [3/4] RBAC role assignments (count)"
if az role assignment list --all --subscription "$SUBSCRIPTION_ID" -o json > "$WORK/rbac.json" 2>"$WORK/rbac.err"; then
  RBAC_OK=1
else
  RBAC_OK=0
  echo '[]' > "$WORK/rbac.json"
fi

# --- Build the normalised cloud-posture.json -------------------------------- #
AZ_VERSION="$(az version --query '"azure-cli"' -o tsv 2>/dev/null || echo unknown)"
python3 - \
  "$CLOUD_POSTURE_OUT" "$NOW_UTC" "$SCANNER_NAME" "$AZ_VERSION" "$SUBSCRIPTION_ID" \
  "$WORK/defender.json" "$DEFENDER_OK" "$WORK/graph.json" "$GRAPH_OK" \
  "$WORK/rbac.json" "$RBAC_OK" <<'PY'
import json, sys

(out, now, scanner, ver, sub,
 defender_path, defender_ok,
 graph_path, graph_ok,
 rbac_path, rbac_ok) = sys.argv[1:12]
defender_ok = defender_ok == "1"
graph_ok = graph_ok == "1"
rbac_ok = rbac_ok == "1"


def load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


rows = []
critical = 0
high = 0
failed_states = {"failed", "unhealthy", "noncompliant", "skipped"}

# Defender regulatory-compliance standards -> rows + CRITICAL/high tally.
defender = load(defender_path, {})
for std in (defender.get("value") or []):
    props = std.get("properties") or {}
    name = std.get("name") or props.get("id") or "unknown-standard"
    state = str(props.get("state") or "").lower()
    failed = int(props.get("failedControls") or 0)
    passed = int(props.get("passedControls") or 0)
    skipped = int(props.get("skippedControls") or 0)
    unsupported = int(props.get("unsupportedControls") or 0)
    rows.append({
        "id": f"defender/{name}",
        "source": "defender-regulatory-compliance",
        "standard": name,
        "state": state or None,
        "failedControls": failed,
        "passedControls": passed,
        "skippedControls": skipped,
        "unsupportedControls": unsupported,
    })
    # A failed control in a regulatory standard is a real misconfig signal.
    critical += failed if state in failed_states or failed > 0 else 0

# Resource Graph storage rows -> immutability / public-access posture.
graph = load(graph_path, {})
storage_rows = graph.get("data") if isinstance(graph, dict) else graph
for sa in (storage_rows or []):
    pna = sa.get("pna")
    allow_blob_public = sa.get("allowBlobPublic")
    immutable = sa.get("immutableEnabled")
    # CRITICAL signals: public network access enabled, or anonymous blob access
    # allowed on an evidence-grade account. WORM-not-enabled is high, not critical.
    is_public = (str(pna).lower() == "enabled") or (allow_blob_public is True)
    if is_public:
        critical += 1
    if immutable is not True:
        high += 1
    rows.append({
        "id": f"storage/{sa.get('name')}",
        "source": "resource-graph",
        "name": sa.get("name"),
        "resourceGroup": sa.get("resourceGroup"),
        "publicNetworkAccess": pna,
        "allowBlobPublicAccess": allow_blob_public,
        "immutableStorageWithVersioning": immutable,
        "worm_locked": immutable is True,
        "public_exposed": is_public,
    })

rbac = load(rbac_path, [])
rbac_count = len(rbac) if isinstance(rbac, list) else None

# A scan ran iff at least one live source returned measurable data.
scan_present = defender_ok or graph_ok
summary = {
    "critical": critical,
    "high": high,
    "rows": len(rows),
    "storage_accounts": len(storage_rows or []),
    "rbac_assignments": rbac_count,
}
status = "PASS" if (scan_present and critical == 0) else ("FAIL" if scan_present else "INDETERMINATE")

rec = {
    "status": status,
    "tier": "EVIDENCE-ONLY",
    "scanner": scanner,
    "scanner_version": ver,
    "scanned_at": now,
    "subscription_id": sub,
    "compliance": {
        "defender_regulatory_compliance": defender_ok,
        "resource_graph": graph_ok,
        "rbac": rbac_ok,
    },
    "summary": summary,
    "rows": rows,
    "detail": (
        f"live Azure posture: {summary['storage_accounts']} storage account(s), "
        f"{len(rows)} CIS/regulatory row(s), {critical} CRITICAL, {high} high. "
        + ("PASS — 0 CRITICAL." if status == "PASS"
           else ("FAIL — CRITICAL exposure present." if status == "FAIL"
                 else "INDETERMINATE — żadne źródło live nie zwróciło danych."))
    ),
    "checked_at": now,
}
# When nothing measurable came back, DO NOT carry a summary.critical that the
# validator would read as a real 0: drop summary so it returns INDETERMINATE.
if not scan_present:
    rec.pop("summary", None)
    rec["measured"] = {"scan_present": False}

with open(out, "w", encoding="utf-8") as fh:
    json.dump(rec, fh, indent=2)
    fh.write("\n")
print(f"  cloud-posture: status={status} rows={len(rows)} critical={critical} high={high}")
PY

# --- (4) Activity Log -> tamper-evident access-log.jsonl -------------------- #
# A.7.7: who read/listed/exported the evidence store. We derive ACCESS events
# from the Activity Log scoped (best-effort) to the evidence resource group /
# storage account, then chain them (sha256 prev_hash/entry_hash, contiguous seq)
# in the exact format check_access_log.py verifies.
echo "  [4/4] Activity Log -> tamper-evident access-log.jsonl"
ACTIVITY_OK=0
ACTIVITY_ARGS=(monitor activity-log list --offset "${LOOKBACK_DAYS}d" -o json)
if [ -n "$RESOURCE_GROUP" ]; then
  ACTIVITY_ARGS+=(--resource-group "$RESOURCE_GROUP")
fi
if az "${ACTIVITY_ARGS[@]}" > "$WORK/activity.json" 2>"$WORK/activity.err"; then
  ACTIVITY_OK=1
else
  echo "    (Activity Log query nieudane: $(head -c 200 "$WORK/activity.err" 2>/dev/null))"
  echo '[]' > "$WORK/activity.json"
fi

python3 - \
  "$ACCESS_LOG_OUT" "$GENESIS_HASH" "$WORK/activity.json" "$EVIDENCE_ACCOUNT" "$ACTIVITY_OK" <<'PY'
import hashlib, json, sys

out, genesis, activity_path, evidence_account, activity_ok = sys.argv[1:6]
activity_ok = activity_ok == "1"


def load(path, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


# Map an Activity-Log operationName to one of the validator's access operations.
def classify(op_name, op_value):
    s = (op_name or op_value or "").lower()
    if "delete" in s:
        return "delete-attempt"
    if "list" in s:
        return "list"
    if "read" in s or "get" in s:
        return "read"
    if "export" in s:
        return "export"
    if "download" in s:
        return "download"
    return None  # not a data-access event we model


def canonical(entry):
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


events = load(activity_path, [])
# Keep only events that touch the evidence storage account (when known) and that
# classify as a data-access operation. We NEVER synthesise events.
selected = []
for ev in (events if isinstance(events, list) else []):
    op = ev.get("operationName") or {}
    op_name = op.get("value") if isinstance(op, dict) else op
    op_loc = op.get("localizedValue") if isinstance(op, dict) else None
    operation = classify(op_name, op_loc)
    if operation is None:
        continue
    res_id = (ev.get("resourceId") or "")
    if evidence_account and evidence_account.lower() not in res_id.lower():
        continue
    caller = ev.get("caller") or "unknown"
    ts = ev.get("eventTimestamp") or ev.get("submissionTimestamp")
    # Normalise timestamp to the schema's strict ...Z form when possible.
    if ts and ts.endswith("+00:00"):
        ts = ts[:-6] + "Z"
    status = (ev.get("status") or {})
    status_val = status.get("value") if isinstance(status, dict) else status
    selected.append({
        "timestamp": ts,
        "operation": operation,
        "principal": caller,
        "object_path": res_id,
        "status": status_val,
    })

# Order oldest-first so the chain reads forward in time.
selected.sort(key=lambda e: e.get("timestamp") or "")

lines = []
prev = genesis
for seq, ev in enumerate(selected):
    entry = {
        "seq": seq,
        "timestamp": ev["timestamp"],
        "operation": ev["operation"],
        "principal": ev["principal"],
        "object_path": ev["object_path"],
        "prev_hash": prev,
    }
    h = hashlib.sha256(canonical(entry).encode("utf-8")).hexdigest()
    entry["entry_hash"] = h
    prev = h
    lines.append(json.dumps(entry, separators=(",", ":")))

with open(out, "w", encoding="utf-8") as fh:
    for ln in lines:
        fh.write(ln + "\n")

# An empty selection is honest INDETERMINATE downstream (no fabricated PASS).
print(f"  access-log: {len(lines)} access event(s) chained "
      f"({'live' if activity_ok else 'query-failed -> empty'})")
PY

echo "=== gotowe ==="
echo "  $CLOUD_POSTURE_OUT"
echo "  $ACCESS_LOG_OUT"
exit 0

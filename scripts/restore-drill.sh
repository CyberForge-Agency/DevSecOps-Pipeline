#!/usr/bin/env bash
#
# restore-drill.sh — automated restore test (EP-09).
#
# Ports the AWS Backup "restore testing" model to Azure: restore the LATEST sealed
# evidence pack/backup into an EPHEMERAL location, verify its integrity by re-running
# the Merkle/manifest verification on the restored copy, measure the Recovery Time
# Objective (RTO), TEAR DOWN the ephemeral copy, and emit a signed-able result at
# evidence/restore-test.json carrying:
#     last_successful_test_date, rto (target/actual), outcome.
#
# The emitted JSON matches the shape scripts/validators/check-restore-test.py reads
# (measured.last_successful_test_date, measured.rto_*, threshold) so a genuine,
# in-window, RTO-met drill can flip the A.10 restore-test control to PASS.
#
# HONEST DEGRADE CONTRACT (runs inside the always-green evidence-pack job):
#   * No cloud creds / az not authenticated AND no local pack to restore -> emit a
#     status:INDETERMINATE record (cannot measure the drill) and exit 0. NEVER fake
#     a successful drill.
#   * A drill that ran but FAILED integrity verification -> outcome:fail, recorded
#     honestly (still exit 0 — enforcement is the verifier's job).
#
# SAFETY: read-only against source data. It only DOWNLOADS a copy into a fresh
# mktemp -d and removes THAT temp dir on teardown. It never deletes the source
# blob/container or any real evidence. Idempotent.
#
# Usage:
#   restore-drill.sh [--source-dir DIR] [--account ACC] [--container NAME]
#                    [--prefix PFX] [--rto-target-min N] [--out FILE]
#                    [--subscription SUB] [--help] [--selftest]
#
#   --source-dir   restore from a local sealed-pack directory (offline drill).
#   --account/--container  restore the latest blob "pack" from Azure Storage.
#   --rto-target-min  RTO target in minutes (default 60).
#
# Exit status: 0 always (degrade-honest producer).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
VERIFY_SH="$SCRIPT_DIR/verify-evidence-pack.sh"

# --------------------------------------------------------------------------- #
# Defaults / arguments                                                         #
# --------------------------------------------------------------------------- #
SOURCE_DIR=""
ACCOUNT=""
CONTAINER="evidence"
PREFIX=""
RTO_TARGET_MIN="60"
OUT="evidence/restore-test.json"
SUBSCRIPTION_ID=""
SCENARIO="evidence-pack restore drill (Azure Blob WORM -> ephemeral verify)"

usage() { sed -n '2,40p' "$0"; }

have() { command -v "$1" >/dev/null 2>&1; }

az_authenticated() {
  [ "${CF_FORCE_NO_AZ:-0}" = "1" ] && return 1
  have az || return 1
  az account show >/dev/null 2>&1
}

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
today_utc() { date -u +%Y-%m-%d; }

# epoch_ms — portable millisecond clock for RTO measurement.
epoch_ms() { date -u +%s%3N; }

# write_record <status> <outcome> <rto_actual_min|null> <detail> [evidence_path]
# Emits the restore-test result JSON (always-green producer; never throws).
write_record() {
  local status="$1" outcome="$2" rto_actual="$3" detail="$4" evidence_path="${5:-}"
  python3 - "$OUT" "$status" "$outcome" "$rto_actual" "$RTO_TARGET_MIN" \
    "$(today_utc)" "$(now_utc)" "$SCENARIO" "$detail" "$evidence_path" <<'PY'
import json, sys
(out, status, outcome, rto_actual, rto_target, today, now,
 scenario, detail, evidence_path) = sys.argv[1:11]


def num(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


rto_actual_n = num(rto_actual)
rto_target_n = num(rto_target)
success = (outcome == "success")
measured = {
    # Only a genuine success stamps a real last_successful_test_date; otherwise null
    # so the A.10 validator cannot read a fabricated success date.
    "last_successful_test_date": today if success else None,
    "test_date": today,
    "scenario": scenario,
    "rto_target": rto_target_n,        # minutes
    "rto_actual": rto_actual_n,        # minutes (null when the drill could not run)
    "rto_unit": "minutes",
    "outcome": outcome,                # success | fail | not-run
    "successful_in_window": 1 if success else 0,
    "evidence": evidence_path or None,
    "verification": "re-ran Merkle/manifest verification (verify-evidence-pack.sh) on the restored copy",
}
rec = {
    "status": status,                  # PASS | FAIL | INDETERMINATE
    "tier": "BLOCKING",
    "measured": measured,
    "threshold": {
        "max_age_days": 365,
        "rto": "rto_actual<=rto_target",
        "outcome": "success",
        "min_successful_in_window": 1,
    },
    "detail": detail,
    "tool_version": None,
    "validator": "restore-drill",
    "checked_at": now,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(rec, fh, indent=2)
    fh.write("\n")
PY
}

# --------------------------------------------------------------------------- #
# Self-test: offline, drives the degrade path AND a real local-restore drill   #
# against the committed sample pack when present.                              #
# --------------------------------------------------------------------------- #
run_selftest() {
  local tmp st rc
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  echo "[selftest] (a) degrade path: no source, az forced absent"
  CF_FORCE_NO_AZ=1 "$0" --out "$tmp/no-source.json" >/dev/null 2>&1 || true
  st="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$tmp/no-source.json")"
  echo "[selftest]   status=$st"
  if [ "$st" != "INDETERMINATE" ]; then
    echo "[selftest] FAIL: no-source/unauth drill must be INDETERMINATE, got $st"; return 1
  fi
  # Honest-no-fake: the success date must be null when no drill ran.
  local lsd
  lsd="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measured"]["last_successful_test_date"])' "$tmp/no-source.json")"
  if [ "$lsd" != "None" ]; then
    echo "[selftest] FAIL: degrade drill fabricated a success date: $lsd"; return 1
  fi

  echo "[selftest] (b) real local restore drill against sample pack (if present)"
  local sample="$SCRIPT_DIR/../sample-evidence-pack"
  if [ -d "$sample" ]; then
    CF_FORCE_NO_AZ=1 "$0" --source-dir "$sample" --out "$tmp/local.json" >/dev/null 2>&1 || true
    st="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$tmp/local.json")"
    local outcome
    outcome="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measured"]["outcome"])' "$tmp/local.json")"
    echo "[selftest]   status=$st outcome=$outcome"
    # A real drill must resolve to PASS(success) or FAIL(fail) — never fabricate.
    case "$st" in PASS|FAIL) : ;; *) echo "[selftest] FAIL: local drill yielded $st"; return 1 ;; esac
  else
    echo "[selftest]   (sample pack absent — skipping real-restore leg)"
  fi
  echo "[selftest] PASS"
  return 0
}

# --------------------------------------------------------------------------- #
# Parse args                                                                   #
# --------------------------------------------------------------------------- #
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-dir) SOURCE_DIR="${2:?}"; shift 2 ;;
    --account) ACCOUNT="${2:?}"; shift 2 ;;
    --container) CONTAINER="${2:?}"; shift 2 ;;
    --prefix) PREFIX="${2:?}"; shift 2 ;;
    --rto-target-min) RTO_TARGET_MIN="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    --subscription) SUBSCRIPTION_ID="${2:?}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --selftest) run_selftest; exit $? ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

mkdir -p "$(dirname "$OUT")"
echo "=== restore-drill.sh (EP-09) ==="

# Ephemeral restore target. ALWAYS removed on exit (teardown), even on error.
RESTORE_DIR="$(mktemp -d -t cf-restore-drill.XXXXXX)"
cleanup() { rm -rf "$RESTORE_DIR"; }
trap cleanup EXIT
echo "  ephemeral restore target: $RESTORE_DIR"

START_MS="$(epoch_ms)"
RESTORE_OK=0
RESTORE_DETAIL=""
EVIDENCE_PATH=""

# --------------------------------------------------------------------------- #
# 1. Restore the latest sealed pack into the ephemeral dir.                    #
# --------------------------------------------------------------------------- #
if [ -n "$SOURCE_DIR" ]; then
  # Offline local restore: copy a sealed-pack directory into the ephemeral target.
  if [ -d "$SOURCE_DIR" ]; then
    cp -a "$SOURCE_DIR/." "$RESTORE_DIR/" 2>/dev/null && RESTORE_OK=1
    EVIDENCE_PATH="$SOURCE_DIR"
    RESTORE_DETAIL="przywrócono lokalny pakiet z $SOURCE_DIR"
  else
    RESTORE_DETAIL="podany --source-dir nie istnieje: $SOURCE_DIR"
  fi
elif az_authenticated && [ -n "$ACCOUNT" ]; then
  # Cloud restore: find the newest blob under the (optional) prefix and download it.
  SUBSCRIPTION_ID="${SUBSCRIPTION_ID:-$(az account show --query id -o tsv 2>/dev/null || true)}"
  echo "  restoring latest blob from account=$ACCOUNT container=$CONTAINER prefix='${PREFIX}'"
  LATEST_BLOB="$(az storage blob list \
      --account-name "$ACCOUNT" --container-name "$CONTAINER" \
      ${PREFIX:+--prefix "$PREFIX"} --auth-mode login \
      --query "sort_by([], &properties.lastModified)[-1].name" -o tsv 2>/dev/null || true)"
  if [ -n "$LATEST_BLOB" ]; then
    DEST="$RESTORE_DIR/$(basename "$LATEST_BLOB")"
    if az storage blob download \
        --account-name "$ACCOUNT" --container-name "$CONTAINER" \
        --name "$LATEST_BLOB" --file "$DEST" --auth-mode login \
        --only-show-errors >/dev/null 2>&1; then
      # If the restored object is an archive, unpack it so verify can see the pack.
      case "$LATEST_BLOB" in
        *.tar.gz|*.tgz) tar -xzf "$DEST" -C "$RESTORE_DIR" 2>/dev/null && RESTORE_OK=1 || RESTORE_OK=1 ;;
        *.zip) have unzip && unzip -q "$DEST" -d "$RESTORE_DIR" 2>/dev/null && RESTORE_OK=1 || RESTORE_OK=1 ;;
        *) RESTORE_OK=1 ;;
      esac
      EVIDENCE_PATH="az://$ACCOUNT/$CONTAINER/$LATEST_BLOB"
      RESTORE_DETAIL="przywrócono najnowszy blob $LATEST_BLOB"
    else
      RESTORE_DETAIL="pobranie bloba $LATEST_BLOB nie powiodło się"
    fi
  else
    RESTORE_DETAIL="brak blobów do przywrócenia w $ACCOUNT/$CONTAINER (prefix='$PREFIX')"
  fi
fi

# --------------------------------------------------------------------------- #
# 2. Degrade-honest: nothing to restore -> INDETERMINATE, exit 0.             #
# --------------------------------------------------------------------------- #
if [ "$RESTORE_OK" != "1" ]; then
  DETAIL="INDETERMINATE: nie wykonano próby odtworzenia — \
${RESTORE_DETAIL:-brak źródła (przekaż --source-dir lub uwierzytelnione --account/--container)}. \
Drill odtworzeniowy wymaga dostępu do magazynu kopii (Azure Blob WORM) lub lokalnego pakietu. \
Zapisano INDETERMINATE — NIE sfabrykowano udanego odtworzenia."
  write_record "INDETERMINATE" "not-run" "null" "$DETAIL" ""
  echo "  -> $DETAIL"
  echo "  $OUT"
  exit 0
fi

# --------------------------------------------------------------------------- #
# 3. Verify integrity of the RESTORED copy (Merkle + manifest + sealing).      #
# --------------------------------------------------------------------------- #
# A restored pack is only credible recoverability evidence if its integrity still
# verifies. We re-run the shipped verifier in degrade mode (a locally-restored
# copy may legitimately lack the live cosign bundle; sha256 + Merkle MUST hold).
echo "  verifying restored pack integrity (Merkle/manifest)..."
VERIFY_OUT="$RESTORE_DIR/.verify.out"
VERIFY_RC=0
if [ -x "$VERIFY_SH" ] || [ -f "$VERIFY_SH" ]; then
  # Point the verifier at the directory that actually contains manifest.json.
  TARGET="$RESTORE_DIR"
  if [ ! -f "$RESTORE_DIR/manifest.json" ]; then
    FOUND="$(find "$RESTORE_DIR" -maxdepth 3 -name manifest.json -print -quit 2>/dev/null || true)"
    [ -n "$FOUND" ] && TARGET="$(dirname "$FOUND")"
  fi
  EVIDENCE_ALLOW_DEGRADE=1 bash "$VERIFY_SH" "$TARGET" >"$VERIFY_OUT" 2>&1 || VERIFY_RC=$?
else
  VERIFY_RC=127
  echo "verify-evidence-pack.sh not found at $VERIFY_SH" > "$VERIFY_OUT"
fi

END_MS="$(epoch_ms)"
RTO_ACTUAL_MIN="$(python3 -c "print(round((${END_MS}-${START_MS})/60000.0, 4))")"
echo "  RTO actual: ${RTO_ACTUAL_MIN} min (target ${RTO_TARGET_MIN} min)"

# --------------------------------------------------------------------------- #
# 4. Decide outcome and emit. Teardown happens via the EXIT trap.             #
# --------------------------------------------------------------------------- #
# grep -c prints 0 and exits 1 when there are no matches; capture the count
# without the `|| echo 0` trap that would otherwise yield a doubled "0\n0".
FAILS="$(grep -c '^FAIL' "$VERIFY_OUT" 2>/dev/null)" || FAILS=0
RTO_MET="$(python3 -c "print('1' if ${RTO_ACTUAL_MIN} <= ${RTO_TARGET_MIN} else '0')")"

if [ "$VERIFY_RC" = "0" ] && [ "$FAILS" = "0" ] && [ "$RTO_MET" = "1" ]; then
  STATUS="PASS"; OUTCOME="success"
  DETAIL="PASS: odtworzono i zweryfikowano integralność pakietu (${RESTORE_DETAIL}); \
Merkle/manifest OK; RTO ${RTO_ACTUAL_MIN} min <= ${RTO_TARGET_MIN} min."
elif [ "$VERIFY_RC" = "0" ] && [ "$FAILS" = "0" ] && [ "$RTO_MET" != "1" ]; then
  STATUS="FAIL"; OUTCOME="fail"
  DETAIL="FAIL: integralność OK, ale przekroczono RTO — ${RTO_ACTUAL_MIN} min > ${RTO_TARGET_MIN} min."
else
  STATUS="FAIL"; OUTCOME="fail"
  DETAIL="FAIL: weryfikacja integralności odtworzonego pakietu nie powiodła się \
(verify rc=${VERIFY_RC}, FAIL-linii=${FAILS}). Szczegóły: $(tr '\n' ' ' < "$VERIFY_OUT" | head -c 400)"
fi

write_record "$STATUS" "$OUTCOME" "$RTO_ACTUAL_MIN" "$DETAIL" "$EVIDENCE_PATH"
echo "  -> status=$STATUS outcome=$OUTCOME"
echo "  $OUT"
echo "=== teardown (usuwanie kopii efemerycznej) ==="
exit 0

#!/usr/bin/env bash
#
# run-authenticated-dast.sh — authenticated OWASP ZAP full scan wrapper (EP-10).
#
# The "continuous proof-trail" probe between formal TLPT exercises. It runs an
# AUTHENTICATED ZAP full scan (zap-full-scan.py) against a target URL using either
# an auth header (ZAP_AUTH_HEADER / ZAP_AUTH_HEADER_VALUE) or a ZAP automation /
# login hook, parses HIGH/CRITICAL (riskcode >= 3) FAIL-CLOSED, and emits a
# signed-able result JSON.
#
# EXPLICITLY NOT A TLPT. DORA RTS on TLPT requires an externally-attested,
# threat-led penetration test on a cadence; this automated authenticated scan only
# MAINTAINS the proof-trail between those formal exercises. The emitted record sets
# "is_tlpt": false and labels itself a continuous-assurance probe.
#
# HONEST FAIL-CLOSED SEMANTICS (mirror dast.yml):
#   report_status: ok | missing | unparseable | no-site
#   * Anything other than 'ok' is a DEGRADED scan. A degraded scan is NOT a clean
#     scan: on a non-PR run it FAILs (outcome:fail). On a PR it is advisory only.
#   * A genuinely clean scan (report ok, 0 HIGH/CRITICAL) is the only PASS.
#   * It NEVER reports 0 findings from a missing/empty/unparseable report.
#
# It does not crash the producing job: it writes the result JSON and exits 0 in
# evidence-pack mode (--evidence-pack), so it stays always-green by policy while
# recording FAIL honestly. In gate mode (default) it exits non-zero on FAIL so it
# can be wired as a blocking CI step too.
#
# Usage:
#   run-authenticated-dast.sh --target URL [options]
#     --target URL            target to scan (http(s)://...) [required unless --selftest]
#     --auth-header NAME       auth header name (default: Authorization)
#     --auth-value VALUE       auth header value (e.g. "Bearer eyJ...") — sets ZAP_AUTH_HEADER*
#     --af-plan FILE           ZAP Automation Framework plan (YAML) for login-script auth
#     --hook FILE              ZAP python hook (alternative auth customisation)
#     --report FILE            ZAP JSON report path (default: zap-auth-report.json)
#     --out FILE               result JSON (default: evidence/authenticated-dast.json)
#     --pr                     treat as a PR run (degraded = advisory, not fail)
#     --evidence-pack          always-green producer mode (exit 0 even on FAIL)
#     --zap-image IMG          docker image (default: ghcr.io/zaproxy/zaproxy:stable)
#     --no-run                 do NOT invoke ZAP; only parse an existing --report
#     --help / --selftest
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Defaults / arguments                                                         #
# --------------------------------------------------------------------------- #
TARGET=""
AUTH_HEADER="Authorization"
AUTH_VALUE=""
AF_PLAN=""
HOOK=""
REPORT="zap-auth-report.json"
OUT="evidence/authenticated-dast.json"
IS_PR=0
EVIDENCE_PACK=0
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy:stable"
NO_RUN=0

usage() { sed -n '2,46p' "$0"; }
have() { command -v "$1" >/dev/null 2>&1; }
now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# parse_report <report_path> <out_json> <target> <is_pr> <ran> <run_detail>
# Single source of truth for fail-closed parsing + result emission. Pure python
# (mirrors dast.yml report_status semantics). Prints the chosen outcome to stdout.
parse_report() {
  python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$(now_utc)" <<'PY'
import json, sys
from pathlib import Path

report_path, out, target, is_pr, ran, run_detail, now = sys.argv[1:8]
is_pr = is_pr == "1"
ran = ran == "1"

# Mirror dast.yml: distinguish a clean scan from a degraded one.
report_status = "ok"
count = 0
high = med = low = info = 0
rp = Path(report_path)

if not rp.exists():
    report_status = "missing"
elif rp.stat().st_size == 0:
    report_status = "unparseable"
else:
    try:
        report = json.loads(rp.read_text(encoding="utf-8"))
    except Exception:
        report_status = "unparseable"
        report = None
    if report is not None:
        if "site" not in report:
            report_status = "no-site"
        else:
            alerts = []
            for site in report.get("site", []):
                alerts += site.get("alerts", [])
            for a in alerts:
                rc = int(a.get("riskcode", 0))
                if rc >= 3:
                    high += 1
                elif rc == 2:
                    med += 1
                elif rc == 1:
                    low += 1
                else:
                    info += 1
            count = high

# Decide status/outcome with honest fail-closed rules.
if report_status != "ok":
    # Degraded scan: never looks like a clean 0-findings pass.
    if is_pr:
        status, outcome = "INDETERMINATE", "degraded-advisory"
        detail = (f"skan DAST zdegradowany (report_status={report_status}) — "
                  f"doradczo na PR; zdegradowany skan to NIE czysty skan")
    else:
        status, outcome = "FAIL", "fail"
        detail = (f"skan DAST zdegradowany (report_status={report_status}) — "
                  f"fail-closed na non-PR; brakujący/niepar­sowalny raport != 0 podatności")
elif count > 0:
    status, outcome = "FAIL", "fail"
    detail = f"OWASP ZAP znalazł {count} podatność(i) HIGH/CRITICAL (authenticated full scan)"
else:
    status, outcome = "PASS", "success"
    detail = "authenticated full scan: 0 podatności HIGH/CRITICAL"

rec = {
    "status": status,                 # PASS | FAIL | INDETERMINATE
    "tier": "BLOCKING",
    "is_tlpt": False,                 # NOT a TLPT — continuous proof-trail probe only
    "probe": "authenticated-zap-full-scan",
    "purpose": "continuous-assurance proof-trail between formal DORA TLPT exercises",
    "measured": {
        "target": target,
        "report_status": report_status,
        "scan_ran": ran,
        "high_critical": high,
        "medium": med,
        "low": low,
        "informational": info,
        "outcome": outcome,
    },
    "threshold": {
        "high_critical": 0,
        "report_status": "ok",
        "fail_closed": "degraded report (missing/unparseable/no-site) FAILs on non-PR",
    },
    "detail": detail + (f"; {run_detail}" if run_detail else ""),
    "tool_version": None,
    "validator": "run-authenticated-dast",
    "checked_at": now,
}
Path(out).parent.mkdir(parents=True, exist_ok=True)
with open(out, "w", encoding="utf-8") as fh:
    json.dump(rec, fh, indent=2)
    fh.write("\n")
print(outcome)
PY
}

# --------------------------------------------------------------------------- #
# Self-test: offline, no docker/ZAP. Drives the parser over synthetic reports  #
# to prove fail-closed + honest no-fabricated-zero behaviour.                  #
# --------------------------------------------------------------------------- #
run_selftest() {
  local tmp rc
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  local fail=0

  # (1) Missing report on non-PR -> FAIL (degraded != clean).
  parse_report "$tmp/nope.json" "$tmp/r1.json" "https://x" 0 0 "no scan" >/dev/null
  local s1; s1="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$tmp/r1.json")"
  echo "[selftest] missing-report/non-PR -> $s1 (want FAIL)"
  [ "$s1" = "FAIL" ] || fail=1

  # (2) Missing report on PR -> INDETERMINATE (advisory).
  parse_report "$tmp/nope.json" "$tmp/r2.json" "https://x" 1 0 "no scan" >/dev/null
  local s2; s2="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$tmp/r2.json")"
  echo "[selftest] missing-report/PR -> $s2 (want INDETERMINATE)"
  [ "$s2" = "INDETERMINATE" ] || fail=1

  # (3) Empty (zero-byte) report -> unparseable -> FAIL non-PR.
  : > "$tmp/empty.json"
  parse_report "$tmp/empty.json" "$tmp/r3.json" "https://x" 0 1 "" >/dev/null
  local s3; s3="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["measured"]["report_status"])' "$tmp/r3.json")"
  echo "[selftest] empty-report report_status -> $s3 (want unparseable)"
  [ "$s3" = "unparseable" ] || fail=1

  # (4) Clean report, 0 HIGH -> PASS.
  printf '{"site":[{"alerts":[{"riskcode":"1"},{"riskcode":"2"}]}]}' > "$tmp/clean.json"
  parse_report "$tmp/clean.json" "$tmp/r4.json" "https://x" 0 1 "" >/dev/null
  local s4; s4="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$tmp/r4.json")"
  echo "[selftest] clean-report -> $s4 (want PASS)"
  [ "$s4" = "PASS" ] || fail=1

  # (5) HIGH finding -> FAIL.
  printf '{"site":[{"alerts":[{"riskcode":"3"}]}]}' > "$tmp/high.json"
  parse_report "$tmp/high.json" "$tmp/r5.json" "https://x" 0 1 "" >/dev/null
  local s5 tlpt; s5="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' "$tmp/r5.json")"
  tlpt="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["is_tlpt"])' "$tmp/r5.json")"
  echo "[selftest] high-finding -> $s5 (want FAIL), is_tlpt=$tlpt (want False)"
  [ "$s5" = "FAIL" ] || fail=1
  [ "$tlpt" = "False" ] || fail=1

  if [ "$fail" = "0" ]; then echo "[selftest] PASS"; return 0; else echo "[selftest] FAIL"; return 1; fi
}

# --------------------------------------------------------------------------- #
# Parse args                                                                   #
# --------------------------------------------------------------------------- #
while [ "$#" -gt 0 ]; do
  case "$1" in
    --target) TARGET="${2:?}"; shift 2 ;;
    --auth-header) AUTH_HEADER="${2:?}"; shift 2 ;;
    --auth-value) AUTH_VALUE="${2:?}"; shift 2 ;;
    --af-plan) AF_PLAN="${2:?}"; shift 2 ;;
    --hook) HOOK="${2:?}"; shift 2 ;;
    --report) REPORT="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    --pr) IS_PR=1; shift ;;
    --evidence-pack) EVIDENCE_PACK=1; shift ;;
    --zap-image) ZAP_IMAGE="${2:?}"; shift 2 ;;
    --no-run) NO_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    --selftest) run_selftest; exit $? ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

echo "=== run-authenticated-dast.sh (EP-10) — continuous proof-trail, NOT a TLPT ==="

# Validate the (untrusted) target URL (A06-2), as dast.yml does.
if [ -z "$TARGET" ]; then
  echo "::error:: --target jest wymagany (odmawiam uruchomienia pustego skanu)" >&2
  RAN=0; RUN_DETAIL="brak target_url"
  OUTCOME="$(parse_report "/nonexistent-$$.json" "$OUT" "" "$IS_PR" "$RAN" "$RUN_DETAIL")"
  echo "  outcome=$OUTCOME -> $OUT"
  if [ "$EVIDENCE_PACK" = "1" ] || [ "$OUTCOME" = "success" ] || [ "$OUTCOME" = "degraded-advisory" ]; then exit 0; else exit 1; fi
fi
case "$TARGET" in
  https://*|http://*) : ;;
  *) echo "::error:: --target musi zaczynać się od http:// lub https:// (otrzymano: $TARGET)" >&2; exit 64 ;;
esac

RAN=0
RUN_DETAIL=""

if [ "$NO_RUN" = "1" ]; then
  RUN_DETAIL="--no-run: pominięto uruchomienie ZAP, parsowanie istniejącego raportu $REPORT"
  echo "  $RUN_DETAIL"
else
  # We need a container runtime to run ZAP. If absent, degrade honestly: do not
  # fabricate a report; the parser will mark report_status accordingly.
  RUNTIME=""
  if have docker; then RUNTIME="docker"; elif have podman; then RUNTIME="podman"; fi

  if [ -z "$RUNTIME" ]; then
    RUN_DETAIL="brak środowiska kontenerowego (docker/podman) — nie uruchomiono ZAP"
    echo "  $RUN_DETAIL"
  else
    echo "  scanning (authenticated full scan) target=$TARGET via $RUNTIME image=$ZAP_IMAGE"
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    # Build the zap-full-scan command. Auth is injected via the ZAP_AUTH_HEADER*
    # env vars (added to every proxied request) and/or an AF plan / hook.
    ZAP_ENV=()
    if [ -n "$AUTH_VALUE" ]; then
      ZAP_ENV+=(-e "ZAP_AUTH_HEADER=${AUTH_HEADER}" -e "ZAP_AUTH_HEADER_VALUE=${AUTH_VALUE}")
    fi
    ZAP_CMD=(zap-full-scan.py -t "$TARGET" -J "$(basename "$REPORT")" -I)
    MOUNTS=(-v "$WORK:/zap/wrk:rw")
    if [ -n "$AF_PLAN" ] && [ -f "$AF_PLAN" ]; then
      cp "$AF_PLAN" "$WORK/af-plan.yaml"
      ZAP_CMD=(zap.sh -cmd -autorun /zap/wrk/af-plan.yaml)
      RUN_DETAIL="auth via AF plan $(basename "$AF_PLAN")"
    elif [ -n "$HOOK" ] && [ -f "$HOOK" ]; then
      cp "$HOOK" "$WORK/hook.py"
      ZAP_CMD+=(--hook /zap/wrk/hook.py)
      RUN_DETAIL="auth via hook $(basename "$HOOK")"
    elif [ -n "$AUTH_VALUE" ]; then
      RUN_DETAIL="auth via header ${AUTH_HEADER}"
    else
      RUN_DETAIL="UWAGA: brak parametrów auth — skan nieuwierzytelniony"
    fi

    # fail_action semantics live in OUR parser, so we ignore ZAP's exit code here.
    "$RUNTIME" run --rm "${ZAP_ENV[@]}" "${MOUNTS[@]}" "$ZAP_IMAGE" "${ZAP_CMD[@]}" \
      >"$WORK/zap.log" 2>&1 || true
    # Recover the report from the mounted work dir.
    if [ -f "$WORK/$(basename "$REPORT")" ]; then
      mkdir -p "$(dirname "$REPORT")" 2>/dev/null || true
      cp "$WORK/$(basename "$REPORT")" "$REPORT" 2>/dev/null || true
      RAN=1
    else
      RUN_DETAIL="$RUN_DETAIL; ZAP nie wytworzył raportu (log: $(tail -c 200 "$WORK/zap.log" 2>/dev/null | tr '\n' ' '))"
    fi
  fi
fi

# --------------------------------------------------------------------------- #
# Parse + emit (fail-closed). Then exit per mode.                             #
# --------------------------------------------------------------------------- #
OUTCOME="$(parse_report "$REPORT" "$OUT" "$TARGET" "$IS_PR" "$RAN" "$RUN_DETAIL")"
echo "  outcome=$OUTCOME -> $OUT"

if [ "$EVIDENCE_PACK" = "1" ]; then
  # Always-green producer mode: record honestly, never crash the pack job.
  exit 0
fi
# Gate mode: PASS / advisory -> 0; FAIL -> non-zero so it can block CI.
case "$OUTCOME" in
  success|degraded-advisory) exit 0 ;;
  *) exit 1 ;;
esac

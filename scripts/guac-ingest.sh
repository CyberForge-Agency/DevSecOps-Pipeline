#!/usr/bin/env bash
#
# guac-ingest.sh — EP-12 GUAC evidence-graph ingestion + query scaffold.
#
# WHAT THIS IS (be honest)
#   GUAC (Graph for Understanding Artifact Composition, https://guac.sh) is an
#   EXTERNAL piece of infrastructure: it runs as a set of services (a GraphQL
#   server + a backing store, usually started via docker compose). This script
#   is the *integration scaffold* that wires the CyberForge evidence pack INTO a
#   GUAC instance — it is NOT a hosted service and it does not stand GUAC up for
#   you. It detects whether the GUAC CLIs are installed and, if so, ingests the
#   pack's signed attestations so a buyer can query the evidence graph. If GUAC
#   is not installed it prints the exact install + run instructions and degrades
#   honestly (exit 0), per the repo's "always-green producer" contract.
#
# WHY GUAC
#   The pack already emits the artifacts GUAC is designed to aggregate:
#     - SBOM (CycloneDX)            evidence/sbom.cyclonedx.json
#     - SLSA provenance (in-toto)   evidence/provenance.intoto.jsonl  (or *.intoto.json)
#     - VEX (OpenVEX)               evidence/vex.openvex.json
#     - cosign keyless bundles      evidence/*.bundle / *.sig
#     - EP-07 control attestations  evidence/*.attestation.json  (custom in-toto predicate)
#   GUAC ingests in-toto/SLSA/SBOM/VEX documents and exposes a single GraphQL
#   graph linking artifacts -> what produced them -> their SBOM -> their VEX
#   status -> the controls attested over them. That graph is the substrate for a
#   buyer-verifiable evidence portal.
#
# DEGRADE / HONESTY MODEL (repo convention)
#   This is a producer-side step: it NEVER crashes the calling job and it never
#   fabricates a result. If GUAC is absent, or if there are no attestations to
#   ingest, it reports that honestly and exits 0. Enforcement (e.g. "the graph
#   MUST contain a signed attestation for control X") is the verifier's job, not
#   this script's.
#
# USAGE
#   scripts/guac-ingest.sh [EVIDENCE_DIR]
#     EVIDENCE_DIR  directory holding the pack's attestation files.
#                   Default: <repo>/evidence  (repo root inferred from scripts/..).
#   scripts/guac-ingest.sh --selftest
#                   Offline self-test: exercises file discovery + guidance path
#                   with a synthetic evidence dir; requires no GUAC, no network.
#   scripts/guac-ingest.sh --queries
#                   Print the example GraphQL queries and exit 0.
#
# ENVIRONMENT
#   GUAC_GQL_ADDR   GraphQL endpoint guacone ingests against.
#                   Default: http://localhost:8080/query  (GUAC default).
#   GUAC_CSUB_ADDR  CollectSub endpoint. Default: localhost:2782 (GUAC default).
#
# EXIT CODES
#   0  always on the normal/degraded producer path (GUAC absent, nothing to
#      ingest, or ingest attempted) and on --selftest success.
#   2  usage error (evidence dir missing/not a directory on the real run path).
#   Non-zero only escapes from --selftest if the self-test itself fails.
#
# SOURCES (verified 2026-06-22):
#   GUAC docs — install/start ........... https://docs.guac.sh/guac/setup-install/
#   GUAC docs — ingest data ............. https://docs.guac.sh/setup-ingest-data/
#   guaccollect/guacone CLI ............. https://docs.guac.sh/guac/cli-guaccollect/
#   GraphQL interface + endpoint ........ https://docs.guac.sh/guac/guac-graphql/
#   querying via CLI .................... https://docs.guac.sh/guac/querying-via-cli/
#
set -euo pipefail

# --- locate repo + defaults ----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

GUAC_GQL_ADDR="${GUAC_GQL_ADDR:-http://localhost:8080/query}"
GUAC_CSUB_ADDR="${GUAC_CSUB_ADDR:-localhost:2782}"

# GUAC release the documented CLI surface below was confirmed against.
GUAC_MIN_VERSION="v0.8.9"

# --- example GraphQL queries (kept in one place; reused by --queries and docs) --------
print_example_queries() {
  cat <<'GRAPHQL'
# =====================================================================
# Przykładowe zapytania GraphQL do grafu dowodowego GUAC
# Endpoint:  http://localhost:8080/query     (GraphQL Playground: http://localhost:8080/)
# =====================================================================

# --- Q1: "pokaż wszystkie kontrole z podpisaną atestacją" -----------------------------
# Atestacje kontroli (predykat EP-07) trafiają do GUAC jako CertifyBad/CertifyGood
# lub jako ogólne atestacje in-toto powiązane z artefaktem. Poniżej: wszystkie
# atestacje "dobre" (spełnione kontrole) wraz z autorem (justifier) i artefaktem.
{
  CertifyGood(certifyGoodSpec: {}) {
    id
    justification          # np. identyfikator kontroli + werdykt (PASS/INDETERMINATE)
    origin                 # kolektor, który wprowadził atestację
    collector
    subject {
      __typename
      ... on Artifact { algorithm digest }
    }
  }
}

# --- Q2: "co wyprodukowało artefakt X" (proweniencja SLSA) ----------------------------
# HasSLSA łączy podpisany artefakt (subject) z materiałami wejściowymi i tożsamością
# buildera (builtBy). Podstaw cyfrowy skrót obrazu w pole `digest`.
{
  HasSLSA(
    hasSLSASpec: {
      subject: { algorithm: "sha256", digest: "<WSTAW_DIGEST_ARTEFAKTU>" }
    }
  ) {
    subject { algorithm digest }
    slsa {
      builtBy { uri }              # tożsamość buildera (np. ref-pinned workflow URI)
      buildType
      slsaVersion
      builtFrom { algorithm digest }   # materiały wejściowe
      origin
      collector
    }
  }
}

# --- Q3: status VEX dla pakietu (czy podatność jest wykorzystywalna) -------------------
{
  CertifyVEXStatement(certifyVEXStatementSpec: {}) {
    vulnerability { vulnerabilityIDs { vulnerabilityID } }
    status                 # AFFECTED / NOT_AFFECTED / FIXED / UNDER_INVESTIGATION
    justification
    statement
    origin
  }
}

# --- Q4: zależności pakietu (z SBOM) --------------------------------------------------
{
  IsDependency(
    isDependencySpec: {
      package: { type: "oci", namespace: "<NAMESPACE>", name: "<NAZWA_OBRAZU>" }
    }
  ) {
    dependencyPackage {
      type
      namespaces { namespace names { name } }
    }
  }
}
GRAPHQL
}

# --- honest guidance when GUAC is not installed ---------------------------------------
print_install_guidance() {
  cat <<EOF
[guac-ingest] GUAC CLI nie jest zainstalowane — pomijam ingest (degradacja uczciwa, exit 0).

GUAC to ZEWNĘTRZNA infrastruktura (serwer GraphQL + magazyn danych). Ten skrypt jest
łącznikiem (scaffold): nie uruchamia GUAC za Ciebie. Aby wprowadzić dowody do grafu:

  1) Pobierz binarkę 'guacone' z wydań (min. ${GUAC_MIN_VERSION}):
       https://github.com/guacsec/guac/releases
       # Linux x86_64:
       curl -fsSL -o guacone https://github.com/guacsec/guac/releases/latest/download/guacone-linux-amd64
       # ZWERYFIKUJ skrót sha256 z pliku checksums z tego samego wydania przed użyciem:
       sha256sum guacone     # porównaj z wartością z release checksums.txt
       chmod +x guacone && sudo mv guacone /usr/local/bin/guacone

  2) Uruchom usługi GUAC (compose z repozytorium guacsec/guac):
       curl -fsSLO https://raw.githubusercontent.com/guacsec/guac/main/guac-demo-compose.yaml
       docker compose -f guac-demo-compose.yaml -p guac up --force-recreate -d
       docker compose ls --filter "name=guac"     # weryfikacja, że działa
       # GraphQL: http://localhost:8080/query   (Playground: http://localhost:8080/)

  3) Wprowadź dowody i odpytaj graf:
       scripts/guac-ingest.sh ${1:-${REPO_ROOT}/evidence}
       scripts/guac-ingest.sh --queries        # przykładowe zapytania GraphQL

Dokumentacja: https://docs.guac.sh/guac/setup-install/  oraz  https://docs.guac.sh/setup-ingest-data/
EOF
}

# --- discover ingestible attestation files in an evidence dir -------------------------
# Echoes one path per line. GUAC's `collect files` ingests SBOM/SLSA/VEX/in-toto
# documents; cosign .bundle/.sig live alongside and are listed for operator context.
discover_attestations() {
  local dir="$1"
  find "${dir}" -maxdepth 1 -type f \( \
       -iname '*.cyclonedx.json' \
    -o -iname '*sbom*.json' \
    -o -iname '*.intoto.jsonl' \
    -o -iname '*.intoto.json' \
    -o -iname '*provenance*.json*' \
    -o -iname '*.openvex.json' \
    -o -iname '*vex*.json' \
    -o -iname '*.attestation.json' \
    -o -iname '*.att.json' \
    \) 2>/dev/null | sort -u
}

discover_signatures() {
  local dir="$1"
  find "${dir}" -maxdepth 1 -type f \( -iname '*.bundle' -o -iname '*.sig' \) \
    2>/dev/null | sort -u
}

# --- main ingest path -----------------------------------------------------------------
run_ingest() {
  local evidence_dir="$1"

  if [ ! -d "${evidence_dir}" ]; then
    echo "::error::evidence dir not found: ${evidence_dir}" >&2
    exit 2
  fi

  echo "[guac-ingest] katalog dowodów : ${evidence_dir}"
  echo "[guac-ingest] GraphQL endpoint : ${GUAC_GQL_ADDR}"
  echo "[guac-ingest] CollectSub addr  : ${GUAC_CSUB_ADDR}"

  # Detect the GUAC CLI. 'guacone' is the all-in-one binary; 'guacgql' is the
  # server. We need at least guacone to ingest.
  local guac_bin=""
  if command -v guacone >/dev/null 2>&1; then
    guac_bin="guacone"
  elif command -v guaccollect >/dev/null 2>&1; then
    guac_bin="guaccollect"
  fi

  if [ -z "${guac_bin}" ]; then
    print_install_guidance "${evidence_dir}"
    exit 0
  fi

  echo "[guac-ingest] wykryto GUAC CLI : ${guac_bin} ($(command -v "${guac_bin}"))"

  # Collect the attestation files.
  local files=()
  while IFS= read -r f; do [ -n "$f" ] && files+=("$f"); done < <(discover_attestations "${evidence_dir}")

  local sigs=()
  while IFS= read -r f; do [ -n "$f" ] && sigs+=("$f"); done < <(discover_signatures "${evidence_dir}")

  if [ "${#sigs[@]}" -gt 0 ]; then
    echo "[guac-ingest] cosign artefakty (kontekst, nie ingest bezpośredni): ${#sigs[@]}"
    printf '  - %s\n' "${sigs[@]}"
  fi

  if [ "${#files[@]}" -eq 0 ]; then
    echo "[guac-ingest] INDETERMINATE: brak plików atestacji do wprowadzenia w ${evidence_dir} — pomijam (exit 0)."
    echo "[guac-ingest] (oczekiwane: *.cyclonedx.json, *.intoto.json(l), *.openvex.json, *.attestation.json)"
    exit 0
  fi

  echo "[guac-ingest] plików do wprowadzenia: ${#files[@]}"
  printf '  - %s\n' "${files[@]}"

  # GUAC's `collect files` ingests a folder of files (shell globs / directories
  # supported). We point it at the evidence dir so SBOM/SLSA/VEX/in-toto docs are
  # all picked up in one pass, against the configured GraphQL endpoint.
  echo "[guac-ingest] uruchamiam: ${guac_bin} collect files --gql-addr ${GUAC_GQL_ADDR} ${evidence_dir}"
  if "${guac_bin}" collect files --gql-addr "${GUAC_GQL_ADDR}" "${evidence_dir}"; then
    echo "[guac-ingest] OK — dowody wprowadzone do grafu GUAC."
    echo "[guac-ingest] Odpytaj graf: scripts/guac-ingest.sh --queries  (lub Playground: ${GUAC_GQL_ADDR%/query}/)"
  else
    # Honest producer contract: a failed external ingest is reported, not fatal
    # to the calling job. The verifier decides whether an empty graph is a FAIL.
    echo "[guac-ingest] OSTRZEŻENIE: ingest GUAC zwrócił błąd — zgłaszam i nie przerywam joba (degradacja uczciwa, exit 0)." >&2
  fi
  exit 0
}

# --- offline self-test ---------------------------------------------------------------
run_selftest() {
  echo "[guac-ingest:selftest] start"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN

  # Synthetic attestation files (content irrelevant — only discovery is tested).
  : > "${tmp}/sbom.cyclonedx.json"
  : > "${tmp}/provenance.intoto.jsonl"
  : > "${tmp}/vex.openvex.json"
  : > "${tmp}/nis2-21-2-d.attestation.json"
  : > "${tmp}/readme.txt"                 # must NOT be discovered
  : > "${tmp}/app.bundle"                 # cosign bundle (context only)

  local found
  found="$(discover_attestations "${tmp}" | wc -l | tr -d ' ')"
  if [ "${found}" -ne 4 ]; then
    echo "[guac-ingest:selftest] FAIL: discover_attestations zwróciło ${found}, oczekiwano 4" >&2
    return 1
  fi
  echo "[guac-ingest:selftest] discovery OK (4 atestacje, txt pominięty)"

  local sigs
  sigs="$(discover_signatures "${tmp}" | wc -l | tr -d ' ')"
  if [ "${sigs}" -ne 1 ]; then
    echo "[guac-ingest:selftest] FAIL: discover_signatures zwróciło ${sigs}, oczekiwano 1" >&2
    return 1
  fi
  echo "[guac-ingest:selftest] sygnatury OK (1 bundle)"

  # Guidance path must produce non-empty output (install instructions).
  if [ -z "$(print_install_guidance "${tmp}")" ]; then
    echo "[guac-ingest:selftest] FAIL: pusta instrukcja instalacji" >&2
    return 1
  fi
  echo "[guac-ingest:selftest] instrukcja instalacji OK"

  # Query helper must mention the documented endpoint + the two required queries.
  local q; q="$(print_example_queries)"
  case "${q}" in
    *"localhost:8080/query"*) : ;;
    *) echo "[guac-ingest:selftest] FAIL: brak endpointu w przykładowych zapytaniach" >&2; return 1 ;;
  esac
  case "${q}" in
    *"HasSLSA"*) : ;;
    *) echo "[guac-ingest:selftest] FAIL: brak zapytania proweniencji (HasSLSA)" >&2; return 1 ;;
  esac
  echo "[guac-ingest:selftest] przykładowe zapytania OK"

  echo "[guac-ingest:selftest] PASS"
  return 0
}

# --- arg dispatch --------------------------------------------------------------------
case "${1:-}" in
  --selftest) run_selftest ;;
  --queries)  print_example_queries ;;
  -h|--help)
    sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
  *)
    run_ingest "${1:-${REPO_ROOT}/evidence}"
    ;;
esac

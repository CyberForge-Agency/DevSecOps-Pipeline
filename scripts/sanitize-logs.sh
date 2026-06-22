#!/usr/bin/env bash
set -euo pipefail

# Sanitize PII from log files in evidence directory.
# Deleguje redakcję do scripts/lib_pii_redact.py (warstwowa detekcja w stylu
# Microsoft Presidio: format + walidacja sumy kontrolnej PESEL + allowlista
# kluczy JSON). Czysty Python — GNU sed nie wspiera lookaheadów PCRE.
#
# EP-01: poprzedni "zachłanny" regex PESEL redagował po samym formacie daty,
# przez co GitHub run_id (11 cyfr) w pipeline-run.json stawał się
# "[REDACTED_PESEL]". Teraz PESEL jest redagowany TYLKO gdy przechodzi
# oficjalną sumę kontrolną (wagi 1,3,7,9,1,3,7,9,1,3), a strukturalnie
# bezpieczne klucze (run_id, run_number, *_digest, image_digest, merkle_root,
# logIndex, sha, git_sha, *_sha256) są na allowliście i nigdy nie redagowane.
#
# A07-4: rekursja po podkatalogach (evidence/codeql, evidence/coverage,
# evidence/source-control-export, evidence/provenance, ...) i pokrycie więcej
# typów artefaktów tekstowych (.sarif, .jsonl). Uruchamiać PO wygenerowaniu
# całości dowodów (tuż przed manifestem/Merkle), nie wcześniej.
EVIDENCE_DIR="${1:-.}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${SCRIPT_DIR}/lib_pii_redact.py"

# --selftest: deleguj do biblioteki (dowodzi: run_id przetrwa, ważny PESEL
# zredagowany, nie-PESEL ze złym checksumem przetrwa).
if [ "${1:-}" = "--selftest" ]; then
  exec python3 "${LIB}" --selftest
fi

if [ ! -f "${LIB}" ]; then
  echo "BŁĄD: brak biblioteki redakcji: ${LIB}" >&2
  exit 1
fi

count=0
while IFS= read -r -d '' f; do
  [ -f "$f" ] || continue
  case "$f" in
    *.json)
      # Redakcja świadoma struktury JSON (honoruje allowlistę kluczy).
      python3 "${LIB}" --json "$f"
      ;;
    *.jsonl)
      # JSON Lines: każdy wiersz redagowany jako osobny obiekt JSON.
      python3 "${LIB}" --jsonl "$f"
      ;;
    *)
      # .log, .sarif i inne traktowane jako surowy tekst.
      python3 "${LIB}" "$f"
      ;;
  esac
  count=$((count + 1))
done < <(find "${EVIDENCE_DIR}" -type f \( -name '*.json' -o -name '*.log' -o -name '*.sarif' -o -name '*.jsonl' \) -print0)

echo "Sanityzacja logów zakończona (${count} plików)."

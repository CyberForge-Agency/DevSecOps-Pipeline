#!/usr/bin/env python3
"""lib_pii_redact — warstwowa redakcja PII (styl Microsoft Presidio), wyłącznie stdlib.

EP-01: poprzedni "zachłanny" regex PESEL fałszywie redagował GitHub run_id
(pipeline-run.json: run_id stawał się "[REDACTED_PESEL]"). Tu wdrażamy
warstwowe podejście wzorowane na Presidio (format + walidacja kontekstu/sumy
kontrolnej + allowlista), aby redagować tylko realne PII:

  (a) PESEL — TYLKO gdy 11-cyfrowa liczba przechodzi OFICJALNĄ sumę kontrolną
      (wagi 1,3,7,9,1,3,7,9,1,3), a nie sam format daty.
  (b) E-mail — z zachowaniem istniejącej allowlisty github.com / noreply.
  (c) Allowlista strukturalnie bezpiecznych kluczy JSON, które NIGDY nie są
      redagowane (run_id, run_number, *_digest, image_digest, merkle_root,
      logIndex, sha, git_sha, *_sha256).

Model honest-degrade: ta biblioteka jest deterministycznym transformatorem
tekstu — nie zgłasza PASS/FAIL i nie crashuje przy braku trafień; po prostu
zwraca tekst z zredagowanym PII (lub niezmieniony, gdy PII nie wykryto).

Źródła (potwierdzone WebSearch 2026-06-22):
  - PESEL suma kontrolna: wagi [1,3,7,9,1,3,7,9,1,3];
    checksum = (10 - (sum % 10)) % 10  (https://en.wikipedia.org/wiki/PESEL)
  - Microsoft Presidio: warstwowa detekcja (PatternRecognizer + validate_result
    z walidacją sumy kontrolnej + allow_list); kontekst i checksum podnoszą
    pewność ponad samo dopasowanie wzorca.
    (https://microsoft.github.io/presidio/analyzer/adding_recognizers/)
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

# --- Stałe redakcji ---------------------------------------------------------

REDACTED_EMAIL = "[REDACTED_EMAIL]"
REDACTED_PESEL = "[REDACTED_PESEL]"

# Oficjalne wagi sumy kontrolnej PESEL dla pierwszych 10 cyfr.
PESEL_WEIGHTS = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)

# Allowlista strukturalnie bezpiecznych kluczy JSON — NIGDY nie redagujemy ich
# wartości. Dopasowanie: dokładne nazwy (case-insensitive) ORAZ sufiksowe
# wzorce (*_digest, *_sha256) dla rodzin pól integralności.
ALLOWLIST_EXACT = frozenset(
    k.lower()
    for k in (
        "run_id",
        "run_number",
        "image_digest",
        "merkle_root",
        "logIndex",
        "sha",
        "git_sha",
    )
)
ALLOWLIST_SUFFIXES = ("_digest", "_sha256")

# E-mail z zachowaniem allowlisty: pomijamy adresy w domenach github.com /
# noreply (np. boty CI / commit authors w GitHub noreply).
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@(?![^@\s]*(?:github\.com|noreply)\b)"
    r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Kandydat PESEL: dokładnie 11 cyfr z granicami słowa. Walidacja formatu daty
# ORAZ sumy kontrolnej odbywa się w validate_pesel() — regex jest tylko
# pierwszą (tanią) warstwą, jak recognizer.PATTERN w Presidio.
_PESEL_CANDIDATE_RE = re.compile(r"\b\d{11}\b")


# --- Allowlista kluczy ------------------------------------------------------


def is_allowlisted_key(key: str) -> bool:
    """Czy klucz JSON jest strukturalnie bezpieczny (nie redagujemy wartości)."""
    if not isinstance(key, str):
        return False
    low = key.lower()
    if low in ALLOWLIST_EXACT:
        return True
    return any(low.endswith(suf) for suf in ALLOWLIST_SUFFIXES)


# --- PESEL: walidacja daty + sumy kontrolnej --------------------------------


def _valid_pesel_date(digits: str) -> bool:
    """Sprawdza, czy pola RRMMDD kodują poprawną datę (z offsetem stulecia).

    Kodowanie miesiąca PESEL niesie stulecie:
      1800-1899 -> +80, 1900-1999 -> +00, 2000-2099 -> +20,
      2100-2199 -> +40, 2200-2299 -> +60.
    """
    year = int(digits[0:2])
    month_raw = int(digits[2:4])
    day = int(digits[4:6])

    # month_raw = miesiąc(1..12) + offset stulecia (0/20/40/60/80).
    century_offsets = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}
    offset = (month_raw // 20) * 20
    if offset not in century_offsets:
        return False
    month = month_raw - offset
    if not (1 <= month <= 12):
        return False
    full_year = century_offsets[offset] + year

    if not (1 <= day <= 31):
        return False
    # Dni w miesiącu (luty bez precyzji przestępności — granica górna 29).
    days_in_month = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    if day > days_in_month[month - 1]:
        return False
    if full_year < 1800 or full_year > 2299:
        return False
    return True


def pesel_checksum_ok(digits: str) -> bool:
    """Czy 11-cyfrowy ciąg ma poprawną OFICJALNĄ sumę kontrolną PESEL.

    sum = Σ (cyfra_i * waga_i) dla i=0..9; checksum = (10 - (sum % 10)) % 10;
    porównanie z 11. cyfrą. (Σ pełnych iloczynów ma to samo sum % 10 co
    "ostatnia cyfra iloczynu", więc wynik jest identyczny.)
    """
    if len(digits) != 11 or not digits.isdigit():
        return False
    total = sum(int(digits[i]) * PESEL_WEIGHTS[i] for i in range(10))
    expected = (10 - (total % 10)) % 10
    return expected == int(digits[10])


def validate_pesel(digits: str) -> bool:
    """Warstwa walidacji (jak Presidio validate_result): format daty + suma.

    Zwraca True tylko, gdy ciąg jest realnym PESEL-em (poprawna data ORAZ
    poprawna suma kontrolna). To eliminuje fałszywe trafienia na 11-cyfrowych
    identyfikatorach (GitHub run_id), które przypadkiem mają format.
    """
    if len(digits) != 11 or not digits.isdigit():
        return False
    if not _valid_pesel_date(digits):
        return False
    return pesel_checksum_ok(digits)


# --- Redakcja w surowym tekście --------------------------------------------


def redact_emails(text: str) -> str:
    """Redaguje adresy e-mail poza allowlistą github.com / noreply."""
    return _EMAIL_RE.sub(REDACTED_EMAIL, text)


def redact_pesel_in_text(text: str) -> str:
    """Redaguje TYLKO realne PESEL-e (walidacja formatu + sumy kontrolnej)."""

    def _repl(m: "re.Match[str]") -> str:
        candidate = m.group(0)
        return REDACTED_PESEL if validate_pesel(candidate) else candidate

    return _PESEL_CANDIDATE_RE.sub(_repl, text)


def redact_text(text: str) -> str:
    """Pełna redakcja surowego tekstu (e-mail + PESEL). Bez świadomości kluczy.

    Używana dla artefaktów nie-JSON (.log, .sarif jako tekst, .jsonl wiersz po
    wierszu po stronie wywołującego). Dla JSON używaj redact_json_text(), aby
    uszanować allowlistę kluczy.
    """
    return redact_pesel_in_text(redact_emails(text))


# --- Redakcja świadoma struktury JSON --------------------------------------


def _redact_value(value: Any, key_is_allowlisted: bool) -> Any:
    """Rekurencyjnie redaguje wartość JSON; pomija allowlistowane liście."""
    if isinstance(value, dict):
        return {k: _redact_value(v, is_allowlisted_key(k)) for k, v in value.items()}
    if isinstance(value, list):
        # Elementy listy dziedziczą status allowlisty po kluczu rodzica
        # (np. lista digestów pod kluczem *_sha256 nie jest redagowana).
        return [_redact_value(v, key_is_allowlisted) for v in value]
    if isinstance(value, str):
        if key_is_allowlisted:
            return value
        return redact_text(value)
    # int/float/bool/None: brak redakcji (run_id bywa liczbą — i tak bezpieczny).
    return value


def redact_json_obj(obj: Any) -> Any:
    """Redaguje obiekt JSON, honorując allowlistę kluczy. Czysta funkcja."""
    return _redact_value(obj, key_is_allowlisted=False)


def redact_json_text(text: str) -> str:
    """Redaguje treść pliku JSON z poszanowaniem allowlisty kluczy.

    Gdy treść nie jest poprawnym JSON-em, degraduje do redakcji tekstowej
    (redact_text) — honest-degrade, bez crasha.
    """
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return redact_text(text)
    redacted = redact_json_obj(obj)
    return json.dumps(redacted, ensure_ascii=False, indent=2)


# --- Selftest ---------------------------------------------------------------


def _gen_valid_pesel(prefix10: str) -> str:
    """Pomocnik testowy: dolicza poprawną cyfrę kontrolną do 10 cyfr."""
    total = sum(int(prefix10[i]) * PESEL_WEIGHTS[i] for i in range(10))
    check = (10 - (total % 10)) % 10
    return prefix10 + str(check)


def _selftest() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool) -> None:
        status = "OK" if cond else "FAIL"
        print(f"[{status}] {name}")
        if not cond:
            failures.append(name)

    # DoD 1: realny GitHub run_id (11 cyfr) PRZETRWA.
    # Przykład run_id ze złym checksumem / nie-PESEL formatem daty.
    run_id = "15847362094"  # 11 cyfr, typowy GitHub Actions run_id
    payload = json.dumps({"run_id": run_id, "note": f"build {run_id}"})
    out = redact_json_text(payload)
    check(
        "run_id pod allowlistowanym kluczem przetrwa",
        run_id in out,
    )
    # Nawet w polu nie-allowlistowanym run_id przetrwa, jeśli to nie PESEL.
    check(
        "run_id w tekście (zły checksum) przetrwa",
        run_id in redact_text(f"build {run_id}") or not validate_pesel(run_id),
    )

    # DoD 2: PESEL z POPRAWNĄ sumą kontrolną zostaje zredagowany.
    # Data 1990-05-15 -> "900515", przykładowy seryjny "0010".
    valid_pesel = _gen_valid_pesel("9005150010")
    check("wygenerowany PESEL ma poprawny checksum", validate_pesel(valid_pesel))
    out2 = redact_text(f"obywatel PESEL {valid_pesel} zgloszony")
    check("ważny PESEL zredagowany w tekście", REDACTED_PESEL in out2)
    check("ważny PESEL nie pozostaje w tekście", valid_pesel not in out2)
    # PESEL w polu nie-allowlistowanym JSON też redagowany.
    j = json.dumps({"customer_pesel": valid_pesel})
    out3 = redact_json_text(j)
    check("ważny PESEL zredagowany w JSON", REDACTED_PESEL in out3)

    # DoD 3: 11-cyfrowa nie-PESEL (zły checksum) PRZETRWA.
    # Weź ważny PESEL i zmień ostatnią cyfrę -> zły checksum.
    bad_checksum = valid_pesel[:-1] + str((int(valid_pesel[-1]) + 1) % 10)
    check("zmodyfikowany ma ZŁY checksum", not validate_pesel(bad_checksum))
    out4 = redact_text(f"id {bad_checksum} koniec")
    check("11-cyfra ze złym checksumem przetrwa", bad_checksum in out4)

    # Allowlista sufiksowa: *_digest / *_sha256 / image_digest / merkle_root.
    # Wstaw wartość, która FORMATEM mogłaby zostać uznana — ale klucz chroni.
    digest_like = valid_pesel  # ważny PESEL jako wartość pola integralności
    jd = json.dumps(
        {
            "image_digest": digest_like,
            "foo_sha256": digest_like,
            "bar_digest": digest_like,
            "merkle_root": digest_like,
            "logIndex": int(run_id),
        }
    )
    outd = redact_json_text(jd)
    check("image_digest nie redagowany", digest_like in outd)
    check("*_sha256 nie redagowany", outd.count(digest_like) >= 4)
    check("REDACTED_PESEL nie pojawia się w polach integralności",
          REDACTED_PESEL not in outd)

    # E-mail: allowlista github.com / noreply zachowana.
    em = "user@example.com kontakt; bot@users.noreply.github.com pomija"
    oute = redact_text(em)
    check("zewnętrzny e-mail zredagowany", REDACTED_EMAIL in oute)
    check("noreply.github.com zachowany", "noreply.github.com" in oute)

    # JSON nie-parsowalny -> degrade do redakcji tekstowej (bez crasha).
    broken = f'{{"x": "{valid_pesel}" '  # brak zamknięcia
    outb = redact_json_text(broken)
    check("uszkodzony JSON degraduje bez crasha", REDACTED_PESEL in outb)

    print()
    if failures:
        print(f"SELFTEST FAIL: {len(failures)} przypadków: {failures}")
        return 1
    print("SELFTEST OK: wszystkie przypadki przeszły")
    return 0


# --- CLI --------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == "--selftest":
        return _selftest()

    import argparse

    parser = argparse.ArgumentParser(
        description="Warstwowa redakcja PII (PESEL z sumą kontrolną, e-mail)."
    )
    parser.add_argument("path", help="Plik do redakcji (in-place).")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Traktuj jako JSON (honoruj allowlistę kluczy).",
    )
    parser.add_argument(
        "--jsonl",
        action="store_true",
        help="Traktuj jako JSON Lines (redaguj każdy wiersz jako JSON).",
    )
    args = parser.parse_args(argv[1:])

    import pathlib

    p = pathlib.Path(args.path)
    text = p.read_text(encoding="utf-8")

    if args.jsonl:
        lines = text.split("\n")
        out_lines = []
        for line in lines:
            if line.strip():
                out_lines.append(redact_json_text(line))
            else:
                out_lines.append(line)
        result = "\n".join(out_lines)
    elif args.json:
        result = redact_json_text(text)
    else:
        result = redact_text(text)

    p.write_text(result, encoding="utf-8")
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(_main(sys.argv))

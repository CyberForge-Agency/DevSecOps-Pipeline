# Graf dowodowy (GUAC) — EP-12

Status: **scaffold integracyjny** (nie hostowana usługa). GUAC jest infrastrukturą
zewnętrzną; ten komponent łączy podpisane atestacje paczki dowodowej CyberForge
z grafem GUAC, aby kupujący mógł je niezależnie odpytać i zweryfikować.

- Skrypt: [`scripts/guac-ingest.sh`](../scripts/guac-ingest.sh)
- Konwencja: krok produkujący jest „zawsze zielony” — brak GUAC lub brak atestacji
  jest raportowany uczciwie i kończy się `exit 0`; egzekwowanie należy do weryfikatora.

---

## 1. Po co graf dowodowy

Paczka dowodowa emituje już artefakty, które GUAC jest zaprojektowany do agregacji:

| Artefakt paczki                        | Plik (typowo)                          | Typ dla GUAC          |
|----------------------------------------|----------------------------------------|-----------------------|
| SBOM (CycloneDX)                       | `evidence/sbom.cyclonedx.json`         | SBOM                  |
| Proweniencja SLSA (in-toto Statement)  | `evidence/provenance.intoto.jsonl`     | SLSA / in-toto        |
| VEX (OpenVEX)                          | `evidence/vex.openvex.json`            | VEX                   |
| Atestacje kontroli (EP-07)             | `evidence/*.attestation.json`          | in-toto (custom pred.)|
| Bundle cosign (keyless)                | `evidence/*.bundle` / `*.sig`          | sygnatura (kontekst)  |

GUAC (Graph for Understanding Artifact Composition) wprowadza te dokumenty do
jednego grafu GraphQL, który łączy: **artefakt → co go wyprodukowało (proweniencja
SLSA) → jego SBOM → status VEX podatności → kontrole zaatestowane nad nim**. Ten graf
jest podstawą kupująco-weryfikowalnego portalu dowodowego (Q1–Q4 poniżej).

Atestacje kontroli z EP-07 to in-toto Statements z własnym `predicateType` (zgodnie
z in-toto Attestation Framework / ITE-6). Werdykt kontroli, której nie da się zmierzyć,
to **INDETERMINATE**, nigdy sfabrykowany PASS — graf odzwierciedla ten model uczciwie.

---

## 2. Architektura

```
  paczka dowodowa (evidence/)                GUAC (infrastruktura zewnętrzna)
  ┌───────────────────────────┐             ┌───────────────────────────────────┐
  │ sbom.cyclonedx.json        │             │  guacgql  (serwer GraphQL :8080)   │
  │ provenance.intoto.jsonl    │  guacone    │            ↕                       │
  │ vex.openvex.json           │  collect    │  magazyn grafu (in-memory / DB)    │
  │ *.attestation.json (EP-07) │  files ───▶ │            ↕                       │
  │ *.bundle / *.sig (cosign)  │   ─────────▶│  guacone query / GraphQL Playground│
  └───────────────────────────┘             └───────────────────────────────────┘
        (producent — ten repo)                    (uruchamiane osobno: compose)
```

- **Wprowadzanie**: `guacone collect files <katalog>` przyjmuje folder plików
  (obsługuje globy/katalogi) i wprowadza SBOM/SLSA/VEX/in-toto przeciw endpointowi
  GraphQL (`--gql-addr`, domyślnie `http://localhost:8080/query`).
- **Odpytywanie**: `guacone query …` (CLI) lub GraphQL Playground na
  `http://localhost:8080/`.
- **Domyślne porty**: `8080` (GraphQL), `2782` (CollectSub).

Granica honest-degrade: jeśli `guacone`/`guaccollect` nie są zainstalowane, skrypt
drukuje dokładne instrukcje instalacji i kończy `exit 0`. Jeśli nie ma plików
atestacji — raportuje INDETERMINATE i kończy `exit 0`. Nieudany ingest zewnętrzny
jest zgłaszany, ale nie przerywa joba.

---

## 3. Koncepcja portalu weryfikacji dla kupującego

Cel: kupujący (lub jego audytor) potwierdza dowody **bez zaufania do nas** —
weryfikuje podpisy lokalnie i przegląda powiązania w grafie.

1. Kupujący pobiera zapieczętowaną paczkę dowodową (manifest + Merkle root + tokeny
   RFC-3161 + bundle cosign) i weryfikuje ją niezależnie:
   [`scripts/verify-evidence-pack.sh`](../scripts/verify-evidence-pack.sh)
   (sha256 manifestu, RFC-6962 Merkle root, `cosign verify-blob` z przypiętą
   tożsamością + dowód inkluzji Rekor, `openssl ts -verify`).
2. Kupujący stawia lokalną instancję GUAC (compose) i wprowadza tę samą paczkę
   przez `guac-ingest.sh`.
3. Kupujący odpytuje graf (Q1–Q4) i konfrontuje: czy każda deklarowana kontrola ma
   **podpisaną** atestację, co wyprodukowało dany artefakt, jaki jest status VEX.

GUAC pełni rolę warstwy zapytań/korelacji nad atestacjami in-toto/SLSA/VEX/SBOM
(jak opisano w guac.sh). Dla zespołów chcących trwałego portalu: ta sama instancja
GUAC może być wystawiona za uwierzytelnionym proxy jako read-only Playground —
to jednak hosting (poza zakresem tego scaffoldu).

---

## 4. Dokładne kroki reprodukcji / weryfikacji

Wymagania: `docker compose`, dostęp sieciowy do wydań GitHub (jednorazowo na pobranie).

```bash
# 0) (jeśli GUAC niezainstalowany) skrypt sam wydrukuje te kroki i zakończy exit 0:
scripts/guac-ingest.sh evidence/

# 1) Zainstaluj binarkę guacone (min. v0.8.9). Linux x86_64:
curl -fsSL -o guacone \
  https://github.com/guacsec/guac/releases/latest/download/guacone-linux-amd64
# ZWERYFIKUJ sha256 względem checksums.txt z tego samego wydania PRZED uruchomieniem:
sha256sum guacone        # porównaj z release checksums.txt
chmod +x guacone && sudo mv guacone /usr/local/bin/guacone

# 2) Uruchom usługi GUAC (compose z guacsec/guac):
curl -fsSLO https://raw.githubusercontent.com/guacsec/guac/main/guac-demo-compose.yaml
docker compose -f guac-demo-compose.yaml -p guac up --force-recreate -d
docker compose ls --filter "name=guac"          # potwierdź, że działa
# GraphQL: http://localhost:8080/query   (Playground: http://localhost:8080/)

# 3) Wprowadź atestacje paczki do grafu:
scripts/guac-ingest.sh evidence/

# 4) Odpytaj graf — przykładowe zapytania GraphQL:
scripts/guac-ingest.sh --queries
#   wklej je w Playground na http://localhost:8080/  albo użyj CLI, np.:
guacone query vuln purl "pkg:guac/cyclonedx/<...>"     # podatności po pURL

# Self-test scaffoldu (offline, bez GUAC i bez sieci):
scripts/guac-ingest.sh --selftest
```

### Przykładowe zapytania (Q1–Q4)

Pełne zapytania w skrypcie: `scripts/guac-ingest.sh --queries`. Skrót:

- **Q1 — „pokaż wszystkie kontrole z podpisaną atestacją”**: `CertifyGood(...)`
  (atestacje kontroli EP-07 powiązane z artefaktem, z polem `justification`
  zawierającym ID kontroli + werdykt, oraz `collector`/`origin`).
- **Q2 — „co wyprodukowało artefakt X”**: `HasSLSA(hasSLSASpec: { subject: {
  algorithm: "sha256", digest: "<DIGEST>" } })` → `slsa.builtBy.uri`,
  `buildType`, `builtFrom` (materiały wejściowe).
- **Q3 — status VEX podatności**: `CertifyVEXStatement(...)` →
  `status` (AFFECTED / NOT_AFFECTED / FIXED / UNDER_INVESTIGATION).
- **Q4 — zależności pakietu**: `IsDependency(...)` (z SBOM).

---

## 5. Ograniczenia (uczciwie)

- To **scaffold**, nie hostowana usługa. GUAC trzeba uruchomić osobno (compose).
- GUAC mapuje atestacje na własny model grafu; dokładny węzeł dla niestandardowego
  predykatu EP-07 zależy od wersji GUAC i sposobu opakowania atestacji (CertifyGood/
  CertifyBad vs. ogólny węzeł in-toto). Powyższe Q1 zakłada mapowanie na `CertifyGood`
  i należy je dostosować do faktycznej wersji GUAC.
- Bundle cosign (`.bundle`/`.sig`) są wymieniane jako kontekst weryfikacji podpisu;
  weryfikacja podpisu odbywa się przez `cosign`/`verify-evidence-pack.sh`, nie w GUAC.
- Składnia CLI/GraphQL potwierdzona dla GUAC **v0.8.9+** (patrz źródła) — starsze
  wersje używają innego `guacone query vuln`.

---

## 6. Źródła (zweryfikowane 2026-06-22)

- GUAC — projekt i koncepcja grafu: <https://guac.sh>
- GUAC docs — instalacja i start: <https://docs.guac.sh/guac/setup-install/>
- GUAC docs — wprowadzanie danych (`collect files`): <https://docs.guac.sh/setup-ingest-data/>
- GUAC docs — `guaccollect`/`guacone` CLI i flagi (`--gql-addr`, `--csub-addr`):
  <https://docs.guac.sh/guac/cli-guaccollect/>
- GUAC docs — interfejs GraphQL i endpoint `:8080/query`:
  <https://docs.guac.sh/guac/guac-graphql/>
- GUAC docs — odpytywanie przez CLI (wymaga v0.8.9+):
  <https://docs.guac.sh/guac/querying-via-cli/>
- in-toto Attestation Framework (ITE-6, predicateType): <https://github.com/in-toto/attestation>
- SLSA provenance: <https://slsa.dev/spec/v1.0/provenance>
- OpenVEX: <https://github.com/openvex/spec>

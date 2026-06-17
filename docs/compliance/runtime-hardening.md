# Runtime Hardening — Least-Privilege Container/Runtime Posture (Azure Container Apps)

| Field          | Value                                                                 |
|----------------|-----------------------------------------------------------------------|
| Document Owner | Security Lead                                                          |
| Approved By    | CyberForge Management                                                  |
| Version        | 1.0                                                                    |
| Effective Date | 2026-06-16                                                            |
| Review Cycle   | Annually, or after significant runtime/base-image change              |
| Compliance     | NIS2 Art.21(2)(i); DORA Art.9; CIS Kubernetes Benchmark v1.10 (PSS `restricted`); CIS Docker Benchmark v1.7; ISO/IEC 27001:2022 A.8.9 |
| Spec mapping   | evidence-pack-specification.md:150 (Part C.15 "Runtime hardening"); §4 stage "Runtime / cloud posture" (evidence-pack-specification.md:198) |

---

## 1. Purpose and honesty boundary

The master spec requires a **Runtime hardening** row (Part C.15): *"Least-privilege runtime · K8s
Pod Security Admission · PSS profile config · NIS2 21(2)(i); CIS K8s · `restricted` (or justified
`baseline`) enforced; PSP-removal handled · sign; 2y"* (evidence-pack-specification.md:150). Spec §4
maps this to the "Runtime / cloud posture" stage and **rejects** a *"Point-in-time screenshot from
audit week"* (evidence-pack-specification.md:198).

This document maps the **declared** container and runtime configuration — the application image
(`Pipeline/app/Dockerfile`) and the Azure Container Apps deployment (`Pipeline/infra/**`, Terraform)
— to the **Kubernetes Pod Security Standards (PSS) `restricted` profile** controls and to ISO/IEC
27001:2022 Annex A 8.9 (Configuration management). It is the design-stage runtime-hardening baseline.

> **STATUS — honest scope (not Kubernetes; no continuous runtime control).** The deployed workload
> is an **Azure Container App**, *not* a Kubernetes pod. There is therefore **no Pod Security
> Admission controller, no `securityContext`, no PSS label, and no PSP** to enforce or remove —
> those primitives do not exist on the Azure Container Apps platform. The honest artifact is a
> **least-privilege container/runtime posture statement**, mapped *control-for-control* against the
> PSS `restricted` requirements, **not a fabricated `restricted` PSS profile config** that the
> platform cannot consume. Per the spec's honesty constraints (§7/§8), the audit-document Part C.15
> wording MUST describe the actual Azure-Container-Apps posture and MUST NOT claim a Kubernetes PSS
> `restricted` enforcement that is not in force.
>
> The hardening assertions below are **derived statically from the Dockerfile and Terraform source**
> (read-only), not from a runtime scan of the live workload. **Continuous runtime hardening — an
> admission/policy controller, runtime drift detection, and a periodically-signed
> `evidence/runtime-hardening.json` — is TARGET-STATE** (see §6).

---

## 2. Why "runtime hardening" is distinct from the existing image scan and IaC scan

The pipeline already performs **container image scanning** (Trivy over the built image, mapping to
the spec's separate "Container/image" row, evidence-pack-specification.md and §4 "Container/image"
stage) and **IaC scanning** (Checkov over `infra/**`, the "IaC scan" row). Those prove the image is
*free of known CVEs* and the *intended* infrastructure is secure **before** apply.

Runtime hardening (Part C.15) is a **different control**: it asserts the **least-privilege execution
posture** of the workload as it actually runs — *who* the process runs as, *what* it can write, and
*which* Linux privileges and ingress it is granted. A clean CVE scan says nothing about whether the
container runs as root; runtime hardening is the control that does.

| Aspect            | Image scan (existing)              | IaC scan (existing)                | Runtime hardening (this doc, C.15)           |
|-------------------|-----------------------------------|------------------------------------|----------------------------------------------|
| Target            | Built image layers                | Terraform source                   | The running container's privilege posture    |
| Proves            | No known CVEs                     | Secure intended infra              | Non-root, least-privilege, restricted ingress|
| Timing            | Build / pre-push                  | Pre-merge / pre-apply              | Runtime (continuous = TARGET)                 |
| Maps to PSS?      | No                                | No                                 | Yes — `restricted` control-by-control        |

---

## 3. Scope — the runtime boundary

Derived (read-only) from:

- `Pipeline/app/Dockerfile` — the application image build and final-stage runtime configuration.
- `Pipeline/infra/modules/container-apps/main.tf` — the Azure Container App, environment, ingress,
  identity, and resource limits.
- `Pipeline/infra/modules/acr/main.tf` — the registry the image is pulled from.

The workload is a single Azure Container App (`azurerm_container_app`,
`infra/modules/container-apps/main.tf:18-71`) running one container (`name = "app"`,
`:36-54`) inside a Container Apps Environment (`:10-16`) in resource group
`${project}-${environment}-rg` (`infra/main.tf:13-17`). Image and deployment are applied by the CI
deploy workflow via `az containerapp update` (`infra/modules/container-apps/main.tf:29-30, 68-70`).

---

## 4. PSS `restricted` → declared container/runtime posture mapping

Each row maps a **Pod Security Standards `restricted`** requirement to the **declared** posture, with
the source citation (read-only). PSS `restricted` (the spec's named target) requires, at minimum:
run as non-root, no privilege escalation, drop **all** capabilities, a `RuntimeDefault` seccomp
profile, no host namespaces/host path, and (as a hardening goal) a read-only root filesystem.

| # | PSS `restricted` control | Declared posture | Evidence (read-only) | Status |
|---|--------------------------|------------------|----------------------|--------|
| 1 | **Run as non-root** (`runAsNonRoot: true`, non-zero UID) | Final stage runs as **UID 65532** (Chainguard nonroot); set explicitly via `USER 65532` | `app/Dockerfile:48` (base), `:58-59` (`USER 65532`) | **MET** |
| 2 | **No privilege escalation** (`allowPrivilegeEscalation: false`) | No `setuid`/`setcap` binaries added; no escalation path declared; Azure Container Apps does not grant `CAP_SYS_ADMIN` or privileged mode to app containers | `app/Dockerfile:40-63`; `infra/modules/container-apps/main.tf:36-54` (no privileged/securityContext escalation) | MET (platform-bounded) |
| 3 | **Privileged container = false** | No privileged mode requested; Azure Container Apps **does not support** privileged containers for customer workloads | `infra/modules/container-apps/main.tf:36-54` (no privileged flag exists/possible) | **MET** |
| 4 | **Drop ALL Linux capabilities; add back only required** | Base is a minimal Wolfi/Chainguard image with no added capabilities; the Node process needs none beyond bind-to-3000 (>1024, no `NET_BIND_SERVICE` needed) | `app/Dockerfile:48-55` (port 3000 > 1024) | MET (no caps added) |
| 5 | **Seccomp `RuntimeDefault`** | Not independently settable on Azure Container Apps; the platform applies its managed runtime sandbox to all app containers | platform-managed (no `securityContext` surface) | **N/A on ACA** — see honesty note |
| 6 | **No host namespaces** (`hostNetwork/PID/IPC` = false) | Azure Container Apps never shares host namespaces with customer containers (multi-tenant managed runtime) | platform invariant | **MET** (platform) |
| 7 | **No `hostPath` volumes** | No host-path mount declared; no `volume_mounts` in the container block | `infra/modules/container-apps/main.tf:36-54` (no volumes) | **MET** |
| 8 | **Read-only root filesystem** (hardening goal) | Not declared; Azure Container Apps does not expose a `readOnlyRootFilesystem` knob today. The image is immutable and the app does not write to the rootfs at runtime, but this is **not enforced** by the platform | `app/Dockerfile` (no writable-state writes after build); platform lacks the knob | **PARTIAL / TARGET** |
| 9 | **Resource limits set** (DoS containment) | CPU `0.25`, memory `0.5Gi`, `max_replicas = 3` bound the blast radius | `infra/modules/container-apps/main.tf:39-40, 34` | **MET** |
| 10 | **Least-privilege ingress** | External ingress on a **single** target port `3000`; no admin/management port exposed; transport `auto` (HTTP/2 upgrade); single traffic target | `infra/modules/container-apps/main.tf:57-66` | **MET** (single app port; see gap on `external_enabled`) |
| 11 | **Least-privilege identity** (no admin creds) | Container App uses a **SystemAssigned** managed identity scoped to **AcrPull** only; ACR `admin_enabled = false` | `infra/modules/container-apps/main.tf:25-27, 74-78`; `infra/modules/acr/main.tf:6` | **MET** |

### 4.1 Honesty note on rows 5–8

Azure Container Apps deliberately does **not** surface the Kubernetes `securityContext`
(`runAsNonRoot`, `seccompProfile`, `capabilities`, `readOnlyRootFilesystem`) to customer workloads —
this is a documented platform limitation, not an omission in our configuration. Non-root execution
(row 1) is therefore enforced **at the image layer** (`USER 65532`), which is the strongest control
available on the platform; the remaining `restricted` knobs (rows 5, 8) are **platform-managed or
not exposed** and are honestly reported as N/A-on-ACA or PARTIAL/TARGET rather than claimed as
enforced. Should the workload migrate to AKS, these rows become directly enforceable via a PSS
`restricted` namespace label + `securityContext`, and the artifact MUST be re-asserted accordingly.

---

## 5. CIS Kubernetes Benchmark applicability

The spec's clause text names **CIS K8s** alongside PSS. Because the deployed workload is Azure
Container Apps (a managed, serverless container runtime — **not** a customer-managed Kubernetes
cluster), the CIS Kubernetes Benchmark's **control-plane / kubelet / etcd** sections (CIS K8s §1–§4)
are **NOT APPLICABLE** — there is no API server, kubelet, or etcd under our control. The only CIS
K8s section with an analogue here is **§5 Policies / Pod Security Standards**, mapped control-by-
control in §4 above. The honest CIS posture is:

| CIS Kubernetes Benchmark section | Applicability to Azure Container Apps | Mapped where |
|----------------------------------|---------------------------------------|--------------|
| §1 Control Plane Components       | N/A (managed by Azure; not customer-controlled) | — |
| §2 etcd                           | N/A (managed)                         | — |
| §3 Control Plane Configuration    | N/A (managed)                         | — |
| §4 Worker Nodes / kubelet         | N/A (serverless; no node access)      | — |
| §5 Policies / Pod Security        | **Applicable** (PSS `restricted` controls) | §4 rows 1–11 |

For the container image itself, the **CIS Docker Benchmark v1.7** §4 (Container Images) is the
applicable supplement: §4.1 non-root user (MET, `app/Dockerfile:58-59`), §4.6 HEALTHCHECK (covered by
the Container App `liveness_probe`, `infra/modules/container-apps/main.tf:47-53`), §4.9 minimal base
image (MET, Chainguard/Wolfi, `app/Dockerfile:48`).

---

## 6. TARGET-STATE — continuous runtime hardening (not yet wired)

The items below satisfy the spec's *"sign; 2y"* and the §4 *"Continuous, drift-alerted"* expectation.
They are **NOT in force today** and are reported as target-state.

### 6.1 `evidence/runtime-hardening.json` (TARGET-STATE)

A validator (target: `scripts/validators/runtime_hardening.py`, owned by the validators stream — not
created by this doc) would parse `app/Dockerfile` and the Container App container block and emit the
shared T-33 envelope (`scripts/validators/libcompliance.py:17-30`):

```json
{
  "schema_version": 1,
  "validator": "runtime_hardening",
  "status": "PASS",
  "tier": "EVIDENCE-ONLY",
  "measured": { "runs_as_non_root": true, "user": "65532", "privileged": false,
                "read_only_rootfs": "platform-managed", "ingress_ports": [3000] },
  "threshold": { "runs_as_non_root": true },
  "detail": "Dockerfile USER 65532 (non-root); ACA single-port ingress; AcrPull-only identity",
  "checked_at": "<UTC ISO-8601>"
}
```

Tiering follows `libcompliance.py:30-43`: the **"runs as non-root"** sub-check is **BLOCKING** (a
Dockerfile with no non-root `USER`, or `USER 0`/`root`, FAILs and stops seal/deploy); the remaining
posture facts are **EVIDENCE-ONLY** (recorded as measured values). `status` is PASS only when the
Dockerfile is actually parsed and the non-root assertion holds; absence is INDETERMINATE, never a
silent PASS (`libcompliance.py:9-11`).

### 6.2 Signing and Merkle inclusion (TARGET-STATE)

When produced, `runtime-hardening.json` is written into the evidence directory **before** the seal
step so it is hashed into the manifest, committed-to by the Merkle root, and cosign-signed alongside
the other artifacts (handled by the integrity-chain stream, not this doc).

### 6.3 Continuous enforcement / drift detection (TARGET-STATE)

Part C.15's *"sign; 2y"* + §4 *"Continuous, drift-alerted"* expectation requires the posture to be
re-asserted on a schedule and to alert on drift (e.g. a base-image bump that drops the non-root
`USER`, or an ingress change exposing a new port). On Azure Container Apps there is **no admission
controller**; the equivalent enforcement is: (a) the BLOCKING non-root sub-check in CI (§6.1) gating
every build, and (b) an Azure activity-log alert on `Microsoft.App/containerApps` ingress/config
changes (a target addition to the monitoring module, `infra/modules/monitoring/main.tf`). If the
workload migrates to AKS, a **Kyverno/Gatekeeper** policy enforcing `restricted` + a Pod Security
Admission `restricted` namespace label become the in-cluster admission controls. Until one of these
exists, **continuous runtime enforcement and drift alerting remain TARGET-STATE** — this doc and the
audit-document must not claim them.

---

## 7. Gap register (design-stage → target)

| # | Gap                                                                          | Severity | Closure action                                                                          |
|---|------------------------------------------------------------------------------|----------|-----------------------------------------------------------------------------------------|
| 1 | No `evidence/runtime-hardening.json` produced or signed                       | HIGH     | Add `scripts/validators/runtime_hardening.py` (T-33 envelope) + seal/sign (§6.1–6.2)     |
| 2 | No continuous runtime enforcement / admission controller on ACA              | HIGH     | BLOCKING non-root CI sub-check + ingress-change activity-log alert; Kyverno PSS on AKS    |
| 3 | Read-only root filesystem not enforced (platform lacks the knob)             | MEDIUM   | Document as platform-bounded; enforce `readOnlyRootFilesystem: true` on AKS migration     |
| 4 | Seccomp `RuntimeDefault` not independently settable on ACA                    | LOW      | Platform-managed; assert explicitly on AKS migration                                      |
| 5 | Ingress is `external_enabled = true` (publicly reachable)                     | MEDIUM   | Confirm public exposure is intended; otherwise internal ingress + front door / WAF        |
| 6 | No drift alert on Container App ingress/config changes                        | MEDIUM   | Add `Microsoft.App/containerApps` activity-log alert to the monitoring module             |

---

## 8. Regulatory mapping

| Regime / standard           | Clause                          | How this posture maps                                                            |
|-----------------------------|---------------------------------|---------------------------------------------------------------------------------|
| NIS2                        | Art.21(2)(i)                    | Basic cyber hygiene + secure configuration; least-privilege runtime              |
| DORA                        | Art.9 (Protection & prevention) | Minimised attack surface; non-root, least-privilege execution; resource bounds    |
| ISO/IEC 27001:2022 Annex A  | A.8.9 Configuration management  | Runtime config established/documented (image + IaC); monitored/reviewed (target)  |
| CIS Kubernetes Benchmark    | v1.10 §5 / PSS `restricted`     | §5 mapped control-by-control (§4); §1–§4 N/A on managed serverless runtime        |
| CIS Docker Benchmark        | v1.7 §4 Container Images        | §4.1 non-root MET; §4.6 healthcheck via liveness probe; §4.9 minimal base image MET |

ISO 27001:2022 A.8.9 control text: *"Configurations, including security configurations, of hardware,
software, services and networks should be established, documented, implemented, monitored and
reviewed."* The **established/documented/implemented** half is satisfied by the image + IaC posture
above; the **monitored and reviewed** half is satisfied only when the continuous assertion (§6) is
operating — until then it is design-stage.

---

## 9. References

- evidence-pack-specification.md:150 (Part C.15 "Runtime hardening"); :198 (§4 "Runtime / cloud posture")
- `Pipeline/app/Dockerfile` (read-only) — final-stage `USER 65532`, Chainguard nonroot base (see §4)
- `Pipeline/infra/modules/container-apps/main.tf` (read-only) — Container App, ingress, identity, limits
- `Pipeline/infra/modules/acr/main.tf:6` (read-only) — `admin_enabled = false`, AcrPull-only identity
- `Pipeline/scripts/validators/libcompliance.py` (shared T-33 validator envelope, read-only)
- Kubernetes Pod Security Standards — `restricted` profile — https://kubernetes.io/docs/concepts/security/pod-security-standards/
- CIS Kubernetes Benchmark — https://www.cisecurity.org/benchmark/kubernetes
- CIS Docker Benchmark — https://www.cisecurity.org/benchmark/docker
- Azure Container Apps — securityContext / non-root limitations (platform): https://github.com/microsoft/azure-container-apps/issues/1001
- Chainguard nonroot Node image (uid 65532) — https://images.chainguard.dev/directory/image/node/overview

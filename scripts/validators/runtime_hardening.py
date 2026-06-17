#!/usr/bin/env python3
"""runtime_hardening.py — emit/validate the runtime-hardening posture (T-118).

Spec mapping
------------
Evidence Pack master spec Part C.15 "Runtime hardening" (``evidence-pack-specification
.md:150``) and §4 stage "Runtime / cloud posture" (``evidence-pack-specification.md:198``,
which REJECTS a point-in-time audit-week screenshot). The honest scope and the exact
envelope shape are pre-described in ``docs/compliance/runtime-hardening.md`` §6.1 — this
validator implements that contract.

What it does
------------
The deployed workload is an **Azure Container App, not a Kubernetes pod** — there is no
Pod Security Admission, no ``securityContext``, no PSS label, no PSP. The honest artifact
is a **least-privilege container/runtime posture statement** derived STATICALLY (read-only)
from the IaC + image:

  * ``app/Dockerfile`` (or ``--dockerfile``)               — non-root ``USER`` (the only
    control enforceable on ACA at the image layer);
  * ``infra/modules/container-apps/main.tf`` (or ``--tf``) — ingress ports,
    privileged/host/volume surface, resource limits, managed identity.

It then ASSERTS the declared posture matches the IaC and emits the T-33 envelope.

Tiering (the runtime-hardening.md §6.1 contract; libcompliance.py:30-43)
------------------------------------------------------------------------
* The **"runs as non-root"** sub-check is **BLOCKING**: a Dockerfile with no non-root
  ``USER`` (or ``USER 0`` / ``USER root``) FAILs and stops seal/deploy. ``status`` is
  PASS only when the Dockerfile is actually parsed AND the non-root assertion holds;
  absence of the Dockerfile -> INDETERMINATE, never a silent PASS.
* The remaining posture facts (privileged=false, ingress ports, host-namespace/volume
  surface, resource limits, identity) are recorded as **measured values**. Controls the
  ACA platform does not express in IaC (seccomp ``RuntimeDefault``, read-only rootfs) are
  reported honestly as **INDETERMINATE / platform-managed** in the per-control map —
  NEVER fabricated as enforced (mirrors runtime-hardening.md §4 rows 5,8 and §4.1).

What it does NOT claim (honesty)
--------------------------------
It does not claim a Kubernetes PSS ``restricted`` enforcement (the platform cannot consume
one). It does not perform a *runtime* scan of the live workload — that, plus continuous
drift alerting, is TARGET-STATE (runtime-hardening.md §6). It proves the **declared**
least-privilege posture is consistent with the IaC, with the non-root invariant gated.

Usage:
    runtime_hardening.py [--dockerfile PATH] [--tf PATH] [--out FILE]
    Defaults: app/Dockerfile, infra/modules/container-apps/main.tf
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Make ``scripts.validators.libcompliance`` importable regardless of cwd.
PIPELINE_ROOT = Path(__file__).resolve().parents[2]
if str(PIPELINE_ROOT) not in sys.path:
    sys.path.insert(0, str(PIPELINE_ROOT))

from scripts.validators import libcompliance as lc  # noqa: E402

VALIDATOR_NAME = "runtime_hardening"
DEFAULT_DOCKERFILE = "app/Dockerfile"
DEFAULT_TF = "infra/modules/container-apps/main.tf"
DEFAULT_OUT = "runtime-hardening.json"

# Controls the Azure Container Apps platform does not surface in IaC; honestly reported
# as INDETERMINATE (not-expressible) rather than fabricated as enforced. (See
# runtime-hardening.md §4 rows 5,8 and the §4.1 honesty note.)
PLATFORM_NOT_EXPRESSIBLE = {
    "seccomp_runtime_default": "Not settable on Azure Container Apps; platform-managed sandbox.",
    "read_only_rootfs": "No readOnlyRootFilesystem knob on Azure Container Apps today.",
}

# Tokens that, as a Dockerfile USER value, mean the container would run as root.
_ROOT_USER_TOKENS = frozenset({"0", "root", "0:0", "root:root"})


def _resolve(path_str: str) -> Path:
    """Resolve a path arg: use as-is if it exists, else relative to the Pipeline root."""
    p = Path(path_str)
    if p.is_file():
        return p
    candidate = PIPELINE_ROOT / path_str
    return candidate if candidate.is_file() else p


def _tool_version() -> str | None:
    """Parsed (not hardcoded) Python version for traceability (pure-stdlib parser)."""
    return f"python {sys.version.split()[0]}"


def _last_user_directive(dockerfile_text: str) -> str | None:
    """Return the value of the LAST ``USER`` directive in the Dockerfile, or None.

    The last USER wins at runtime, so a multi-stage Dockerfile that ends with a non-root
    USER in the final stage is correctly read as non-root.
    """
    last: str | None = None
    for raw in dockerfile_text.splitlines():
        line = raw.strip()
        m = re.match(r"^USER\s+(\S+)", line, flags=re.IGNORECASE)
        if m:
            last = m.group(1).strip()
    return last


def _parse_dockerfile(path: Path) -> tuple[dict[str, Any], str | None]:
    """Parse the non-root posture from the Dockerfile. Returns (facts, error)."""
    if not path.is_file():
        return {}, f"{path}: Dockerfile not found"
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}, f"{path}: Dockerfile is empty"
    user = _last_user_directive(text)
    if user is None:
        return {"user": None, "runs_as_non_root": False}, None
    runs_as_non_root = user.lower() not in _ROOT_USER_TOKENS
    return {"user": user, "runs_as_non_root": runs_as_non_root}, None


def _container_block(tf_text: str) -> str:
    """Best-effort slice of the ``container { ... }`` block (for privileged/volume checks)."""
    m = re.search(r"\bcontainer\s*\{", tf_text)
    if not m:
        return ""
    # Walk braces from the opening brace to find the matching close.
    start = m.end() - 1
    depth = 0
    for i in range(start, len(tf_text)):
        c = tf_text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return tf_text[start : i + 1]
    return tf_text[start:]


def _parse_terraform(path: Path) -> tuple[dict[str, Any], str | None]:
    """Parse the ACA runtime posture from the container-apps Terraform. (facts, error)."""
    if not path.is_file():
        return {}, f"{path}: Terraform not found"
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return {}, f"{path}: Terraform is empty"

    facts: dict[str, Any] = {}

    # Ingress target_port(s) — least-privilege ingress (single app port expected).
    ports = sorted({int(p) for p in re.findall(r"target_port\s*=\s*(\d+)", text)})
    facts["ingress_ports"] = ports

    # external_enabled (publicly reachable?) — recorded, not failed (see md gap #5).
    m_ext = re.search(r"external_enabled\s*=\s*(true|false)", text)
    facts["ingress_external"] = (m_ext.group(1) == "true") if m_ext else None

    # Privileged / host-namespace / hostPath surface: ACA has no such knobs. We assert
    # NONE are present in the IaC (their presence would be the anomaly to flag).
    facts["privileged"] = bool(re.search(r"\bprivileged\s*=\s*true", text))
    facts["host_network"] = bool(re.search(r"\bhost_network\s*=\s*true", text))
    container = _container_block(text)
    facts["host_path_volume"] = bool(re.search(r"\bhost_path\b", container))
    facts["volume_mounts"] = bool(re.search(r"\bvolume_mounts?\b", container))

    # Resource limits (DoS containment) — cpu/memory + max_replicas.
    m_cpu = re.search(r"\bcpu\s*=\s*([\d.]+)", container or text)
    m_mem = re.search(r'\bmemory\s*=\s*"([^"]+)"', container or text)
    m_max = re.search(r"\bmax_replicas\s*=\s*(\d+)", text)
    facts["cpu"] = m_cpu.group(1) if m_cpu else None
    facts["memory"] = m_mem.group(1) if m_mem else None
    facts["max_replicas"] = int(m_max.group(1)) if m_max else None
    facts["resource_limits_set"] = bool(m_cpu and m_mem and m_max)

    # Managed identity (least-privilege identity; no admin creds).
    m_id = re.search(r"identity\s*\{[^}]*type\s*=\s*\"([^\"]+)\"", text, flags=re.DOTALL)
    facts["managed_identity"] = m_id.group(1) if m_id else None

    return facts, None


def validate(dockerfile: Path, tf_path: Path) -> dict[str, Any]:
    """Run the T-118 check and return a ready T-33 envelope (no exit).

    The envelope ``tier`` is BLOCKING because the non-root invariant is BLOCKING.
    Posture facts ride along in ``measured``; not-expressible platform controls are
    reported INDETERMINATE in the per-control map (never fabricated).
    """
    tier = lc.Tier.BLOCKING
    tv = _tool_version()
    threshold = {"runs_as_non_root": True, "non_root_user": "non-zero/non-root UID"}

    # 1) Dockerfile is the BLOCKING input: absent -> INDETERMINATE (cannot measure).
    df_facts, df_err = _parse_dockerfile(dockerfile)
    if df_err is not None:
        return lc.envelope(
            lc.Status.INDETERMINATE, tier, measured=None, threshold=threshold,
            detail=f"runtime hardening indeterminate: {df_err}", tool_version=tv,
            validator=VALIDATOR_NAME,
        )

    # 2) Terraform posture (advisory facts). Absence does not break the non-root gate
    #    but is recorded honestly so the posture map shows what could not be measured.
    tf_facts, tf_err = _parse_terraform(tf_path)

    # 3) Per-control posture map — MET / INDETERMINATE(platform) per the md mapping.
    controls: dict[str, str] = {}
    user = df_facts.get("user")
    runs_as_non_root = bool(df_facts.get("runs_as_non_root"))
    controls["run_as_non_root"] = "MET" if runs_as_non_root else "FAIL"
    # Platform-managed / not-IaC-expressible controls — honest INDETERMINATE.
    for key in PLATFORM_NOT_EXPRESSIBLE:
        controls[key] = "INDETERMINATE"
    if tf_err is None:
        controls["privileged_false"] = "MET" if not tf_facts.get("privileged") else "FAIL"
        controls["no_host_namespaces"] = "MET" if not tf_facts.get("host_network") else "FAIL"
        controls["no_host_path_volume"] = "MET" if not tf_facts.get("host_path_volume") else "FAIL"
        controls["resource_limits_set"] = "MET" if tf_facts.get("resource_limits_set") else "INDETERMINATE"
        controls["least_privilege_ingress"] = (
            "MET" if (tf_facts.get("ingress_ports") and len(tf_facts["ingress_ports"]) == 1) else "INDETERMINATE"
        )
        controls["managed_identity"] = "MET" if tf_facts.get("managed_identity") else "INDETERMINATE"
    else:
        # IaC not measurable: report the IaC-dependent controls as INDETERMINATE.
        for key in (
            "privileged_false", "no_host_namespaces", "no_host_path_volume",
            "resource_limits_set", "least_privilege_ingress", "managed_identity",
        ):
            controls[key] = "INDETERMINATE"

    measured: dict[str, Any] = {
        "runs_as_non_root": runs_as_non_root,
        "user": user,
        "privileged": tf_facts.get("privileged"),
        "ingress_ports": tf_facts.get("ingress_ports"),
        "ingress_external": tf_facts.get("ingress_external"),
        "resource_limits": {
            "cpu": tf_facts.get("cpu"),
            "memory": tf_facts.get("memory"),
            "max_replicas": tf_facts.get("max_replicas"),
        },
        "managed_identity": tf_facts.get("managed_identity"),
        "read_only_rootfs": "platform-managed",
        "seccomp_runtime_default": "platform-managed",
        "controls": controls,
        "iac_parse_error": tf_err,
        "platform": "Azure Container Apps (not Kubernetes; no PSS/securityContext)",
    }

    # 4) BLOCKING gate: the non-root invariant. A FAIL here stops seal/deploy.
    if not runs_as_non_root:
        bad = f"USER {user!r}" if user is not None else "no USER directive"
        return lc.envelope(
            lc.Status.FAIL, tier, measured=measured, threshold=threshold,
            detail=(
                f"runtime hardening FAIL: container would run as root ({bad}); "
                f"a non-root final-stage USER is the BLOCKING least-privilege invariant "
                f"on Azure Container Apps (runtime-hardening.md §6.1)"
            ),
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    # 5) Any IaC-derived hard FAIL (privileged/host surface present) is also BLOCKING.
    iac_fails = [k for k, v in controls.items() if v == "FAIL"]
    if iac_fails:
        return lc.envelope(
            lc.Status.FAIL, tier, measured=measured, threshold=threshold,
            detail=(
                f"runtime hardening FAIL: privileged/host surface declared in IaC "
                f"({', '.join(iac_fails)}) contradicts the least-privilege posture"
            ),
            tool_version=tv, validator=VALIDATOR_NAME,
        )

    indeterminate = sorted(k for k, v in controls.items() if v == "INDETERMINATE")
    return lc.envelope(
        lc.Status.PASS, tier, measured=measured, threshold=threshold,
        detail=(
            f"runtime hardening posture consistent with IaC: non-root USER {user} "
            f"(BLOCKING invariant MET); ingress ports {tf_facts.get('ingress_ports')}; "
            f"identity {tf_facts.get('managed_identity')}; "
            f"platform-managed/not-IaC-expressible (INDETERMINATE, NOT fabricated): "
            f"{indeterminate}. NOTE: declared posture only — a live runtime scan + "
            f"continuous drift alerting are TARGET-STATE (runtime-hardening.md §6)."
        ),
        tool_version=tv, validator=VALIDATOR_NAME,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit/validate the Azure Container Apps runtime-hardening posture (T-118)."
    )
    parser.add_argument("--dockerfile", default=DEFAULT_DOCKERFILE, help="path to app Dockerfile")
    parser.add_argument("--tf", default=DEFAULT_TF, help="path to container-apps Terraform")
    parser.add_argument("--out", default=DEFAULT_OUT, help="output envelope JSON path")
    args = parser.parse_args(argv)

    env = validate(_resolve(args.dockerfile), _resolve(args.tf))
    try:
        Path(args.out).write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not write {args.out}: {exc}", file=sys.stderr)

    print(json.dumps(env))
    return lc.exit_code_for(env["status"], env["tier"])


if __name__ == "__main__":
    sys.exit(main())

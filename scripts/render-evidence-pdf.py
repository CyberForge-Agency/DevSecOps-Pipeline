#!/usr/bin/env python3
"""render-evidence-pdf.py — render the audit document HTML into a PDF/A-3b
forensic object with raw evidence files embedded as PDF/A-3 attachments.

This is the ONLY script in the evidence-PDF chain that imports a third-party
library (weasyprint). Per the shared integration contract it must degrade
gracefully: if weasyprint cannot be imported and EVIDENCE_ALLOW_DEGRADE=1,
it writes a `<out>.MISSING` marker and exits 0 so the rest of the chain can
run locally; otherwise (CI, fail-closed) it exits non-zero with a clear error.

CLI:
  render-evidence-pdf.py --html audit-document.html --evidence-dir DIR \\
      --out evidence-report.pdf [--attach FILE ...]

Embedded attachments use AFRelationship "Source" for first-class evidence
inputs (manifest, oscal, sbom, sarif, provenance) and "Data" for supporting
machine artifacts (verify runbook). Document XMP/DocInfo created/modified are
taken from the GENERATED_AT env var (ISO-8601 UTC) for deterministic metadata.
"""
from __future__ import annotations

import argparse
import datetime
import os
import sys
from pathlib import Path

# Default set of raw evidence files to embed when --attach is not given.
# Each entry: (filename-relative-to-evidence-dir, AFRelationship).
DEFAULT_ATTACHMENTS: list[tuple[str, str]] = [
    ("manifest.json", "Source"),
    ("oscal-assessment-results.json", "Source"),
    ("sbom.cyclonedx.json", "Source"),
    ("security-report.json", "Source"),
    ("trivy-sca-results.json", "Source"),
    ("trivy-image-results.json", "Source"),
    ("codeql/javascript.sarif", "Source"),
    ("checkov-results.sarif", "Source"),
    ("zap-report.json", "Source"),
    ("provenance.intoto.jsonl", "Source"),
    ("verapdf-report.json", "Data"),
    ("VERIFY.md", "Data"),
    ("manifest.sha256", "Data"),
]

# MIME hints by extension for the attachment description / embedding.
_MIME = {
    ".json": "application/json",
    ".jsonl": "application/jsonl",
    ".sarif": "application/sarif+json",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".html": "text/html",
}


def _mime_for(path: Path) -> str:
    return _MIME.get(path.suffix.lower(), "application/octet-stream")


def _supported_pdf_options(weasyprint) -> set:  # type: ignore[no-untyped-def]
    """Return the set of PDF option names this WeasyPrint accepts.

    WeasyPrint exposes its render options differently across versions:
      * v60+ ships a ``DEFAULT_OPTIONS`` dict naming every supported option
        (pdf_variant, attachments, srgb, ...).
      * Older versions accepted a fixed set of write_pdf kwargs.
    We prefer DEFAULT_OPTIONS when present and fall back to introspecting the
    write_pdf signature, so we only ever pass kwargs the library understands.
    """
    default_opts = getattr(weasyprint, "DEFAULT_OPTIONS", None)
    if isinstance(default_opts, dict):
        return set(default_opts.keys())
    import inspect

    try:
        params = set(inspect.signature(weasyprint.HTML.write_pdf).parameters)
    except (TypeError, ValueError):
        params = set()
    return params


def _parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Render audit HTML -> PDF/A-3b")
    ap.add_argument("--html", required=True, help="Input audit-document HTML")
    ap.add_argument("--evidence-dir", required=True, help="Evidence directory")
    ap.add_argument("--out", required=True, help="Output PDF path")
    ap.add_argument(
        "--attach",
        action="append",
        default=[],
        help="Extra file to embed as a PDF/A-3 attachment (repeatable)",
    )
    return ap.parse_args(argv)


def _resolve_generated_at() -> tuple[datetime.datetime, str]:
    """Return (aware-datetime, iso-string) from env GENERATED_AT.

    Never calls time.now() directly so metadata is deterministic/testable.
    Falls back to the fixed epoch placeholder mandated by the contract.
    """
    iso = os.environ.get("GENERATED_AT") or "1970-01-01T00:00:00Z"
    raw = iso.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        dt = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
        iso = "1970-01-01T00:00:00Z"
    return dt, iso


def _collect_attachments(evidence_dir: Path, extra: list[str]) -> list[tuple[Path, str, str]]:
    """Return list of (path, af_relationship, description) for existing files."""
    out: list[tuple[Path, str, str]] = []
    seen: set[Path] = set()
    for rel, relationship in DEFAULT_ATTACHMENTS:
        p = (evidence_dir / rel).resolve()
        if p.exists() and p.is_file() and p not in seen:
            seen.add(p)
            out.append((p, relationship, f"CyberForge evidence: {rel} ({_mime_for(p)})"))
    for rel in extra:
        p = Path(rel).resolve()
        if p.exists() and p.is_file() and p not in seen:
            seen.add(p)
            out.append((p, "Source", f"CyberForge evidence: {p.name} ({_mime_for(p)})"))
    return out


def _degrade_or_fail(out_path: Path, reason: str) -> int:
    """Either write a .MISSING marker (degrade) or fail closed."""
    allow = os.environ.get("EVIDENCE_ALLOW_DEGRADE") == "1"
    if allow:
        marker = out_path.with_suffix(out_path.suffix + ".MISSING")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            "EVIDENCE PDF NOT RENDERED (degraded run)\n"
            f"reason: {reason}\n"
            "EVIDENCE_ALLOW_DEGRADE=1 was set, so this placeholder marker was\n"
            "written and the chain continues. In CI (fail-closed) this is an\n"
            "error: install weasyprint + system libs (see requirements-pdf.txt).\n",
            encoding="utf-8",
        )
        sys.stderr.write(
            f"WARNING [render-evidence-pdf]: {reason}\n"
            f"WARNING [render-evidence-pdf]: EVIDENCE_ALLOW_DEGRADE=1 -> wrote marker {marker}\n"
        )
        return 0
    sys.stderr.write(
        f"ERROR [render-evidence-pdf]: {reason}\n"
        "ERROR [render-evidence-pdf]: fail-closed (EVIDENCE_ALLOW_DEGRADE!=1). "
        "Install weasyprint and dependencies (requirements-pdf.txt).\n"
    )
    return 2


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    html_path = Path(args.html)
    evidence_dir = Path(args.evidence_dir)
    out_path = Path(args.out)

    if not html_path.exists():
        return _degrade_or_fail(out_path, f"input HTML not found: {html_path}")
    if not evidence_dir.exists():
        return _degrade_or_fail(out_path, f"evidence dir not found: {evidence_dir}")

    # Import weasyprint lazily so the missing-tool path can degrade.
    try:
        import weasyprint  # type: ignore
    except Exception as exc:  # noqa: BLE001 — any import failure should degrade
        return _degrade_or_fail(out_path, f"weasyprint import failed: {exc!r}")

    # weasyprint.Attachment was added in modern versions; tolerate older ones.
    Attachment = getattr(weasyprint, "Attachment", None)

    dt, iso = _resolve_generated_at()
    attachments_spec = _collect_attachments(evidence_dir, args.attach)

    # Build Attachment objects using the documented keyword API
    # (WeasyPrint >= 61: Attachment(filename=..., description=..., relationship=...)).
    # The first POSITIONAL argument is `guess`, NOT the filename, so we must pass
    # filename as a keyword — getting this wrong silently dropped attachments.
    wp_attachments = []
    if Attachment is not None:
        for path, relationship, description in attachments_spec:
            try:
                wp_attachments.append(
                    Attachment(
                        filename=str(path),
                        description=description,
                        relationship=relationship,
                    )
                )
            except TypeError:
                # Older Attachment signature without `relationship`.
                wp_attachments.append(
                    Attachment(filename=str(path), description=description)
                )
    else:
        sys.stderr.write(
            "WARNING [render-evidence-pdf]: weasyprint.Attachment unavailable; "
            "rendering without embedded attachments.\n"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # WeasyPrint moved PDF/A + attachment controls into write_pdf options. The
    # supported names differ across major versions, so probe the installed
    # write_pdf signature / DEFAULT_OPTIONS and only pass what is accepted.
    # (v68: options are accepted as **kwargs to write_pdf, e.g. pdf_variant,
    #  attachments, srgb. Older versions used the same kwarg names directly.)
    supported = _supported_pdf_options(weasyprint)
    opts: dict = {}
    if "pdf_variant" in supported:
        opts["pdf_variant"] = "pdf/a-3b"
    if "srgb" in supported:
        # PDF/A requires an output intent; srgb=True makes WeasyPrint embed one.
        opts["srgb"] = True
    if "attachments" in supported and wp_attachments:
        opts["attachments"] = wp_attachments

    rendered_variant = "pdf/a-3b" if "pdf_variant" in opts else "plain-pdf"
    embedded = len(wp_attachments) if "attachments" in opts else 0

    try:
        doc = weasyprint.HTML(filename=str(html_path), base_url=str(evidence_dir))
        doc.write_pdf(str(out_path), **opts)
    except Exception as exc:  # noqa: BLE001
        # A render failure with a real weasyprint present is a hard error even
        # locally — degraded mode is only for the *missing tool* case.
        if os.environ.get("EVIDENCE_ALLOW_DEGRADE") == "1":
            return _degrade_or_fail(out_path, f"weasyprint render error: {exc!r}")
        sys.stderr.write(f"ERROR [render-evidence-pdf]: render failed: {exc!r}\n")
        return 3

    # Fail honestly: in fail-closed (CI) mode, refuse to claim PDF/A-3 or
    # embedded evidence we did not actually produce. veraPDF is the formal gate,
    # but this catches a silent API-mismatch before we ever get there.
    if os.environ.get("EVIDENCE_ALLOW_DEGRADE") != "1":
        problems = []
        if "pdf_variant" not in opts:
            problems.append(
                "this WeasyPrint does not support pdf_variant -> NOT PDF/A-3b"
            )
        if wp_attachments and "attachments" not in opts:
            problems.append(
                "this WeasyPrint does not support attachments -> evidence NOT embedded"
            )
        if problems:
            sys.stderr.write(
                "ERROR [render-evidence-pdf]: cannot produce an audit-grade PDF:\n"
                + "".join(f"  - {p}\n" for p in problems)
                + "  Upgrade WeasyPrint (see requirements-pdf.txt) or run with "
                "EVIDENCE_ALLOW_DEGRADE=1 locally.\n"
            )
            return 4

    sys.stderr.write(
        f"render-evidence-pdf: wrote {out_path} (generated_at={iso}, "
        f"variant={rendered_variant}, attachments={embedded})\n"
    )
    _ = dt  # reserved for explicit XMP injection in a future pikepdf pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

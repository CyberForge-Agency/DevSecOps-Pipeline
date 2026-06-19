# Security Policy

CyberForge builds DevSecOps assurance pipelines, so we hold this repository to
the same disclosure standard we deliver to clients.

## Reporting a Vulnerability

**Please do not open public issues for security vulnerabilities.**

Report privately through GitHub's
[**"Report a vulnerability"**](https://github.com/CyberForge-Agency/DevSecOps-Pipeline/security/advisories/new)
button (repository **Security → Advisories**). This opens a private advisory
visible only to you and the maintainers.

If you cannot use GitHub advisories, reach the maintainers via the contact
listed on the [CyberForge-Agency organization profile](https://github.com/CyberForge-Agency).

Please include:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- the affected version / commit SHA,
- any suggested remediation.

## Response Targets

| Stage | Target |
|-------|--------|
| Acknowledgement | within 3 business days |
| Triage + severity (CVSS) | within 7 business days |
| Fix or mitigation for High/Critical | within 30 days |
| Coordinated disclosure | by mutual agreement, default 90 days |

We support coordinated disclosure and will credit reporters who wish to be named.

## Supported Versions

Security fixes land on `main`. They are not back-ported to historical commits,
tags, or forks unless separately agreed.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ |
| older commits / tags / forks | ❌ |

## Scope

**In scope:** the pipeline workflows (`.github/workflows/`), policies
(`policies/`), evidence and automation scripts (`scripts/`), the demo
application (`app/`), and infrastructure templates (`infra/`).

**Out of scope:** findings that require an already-compromised CI runner or
maintainer account; vulnerabilities in third-party actions or base images
pinned by this repo (report those to their upstream projects); and the contents
of `sample-evidence-pack/` (illustrative demo data, not a deployed surface).

## Our Own Controls

This repository dogfoods its controls: signed commits and required status
checks on `main`, SBOM + dependency scanning (Trivy), SAST (CodeQL), IaC
scanning (Checkov), secret scanning (TruffleHog), DAST (OWASP ZAP), and a
sealed, RFC-6962 Merkle-rooted evidence pack produced on every run.

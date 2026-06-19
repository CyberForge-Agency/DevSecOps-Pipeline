# ICT Risk-Management Framework

**Document Owner:** Security Lead (CyberForge)
**Approved By:** _pending initial management review_
**Last Reviewed:** pending initial management review
**Review Cadence:** Annually (DORA Art. 6(5) requires at least annual review of the ICT risk-management framework)
**Version:** 0.1 (initial seed — not yet ratified by a management review)
**Regulatory Reference:** DORA (Reg. (EU) 2022/2554) Art. 5–6 / NIS2 (Dir. (EU) 2022/2555) Art. 21(2)(a) / ISO/IEC 27001 Cl. 6.1, 8.2

---

## 1. Purpose and Honest Status

This document is the single, top-level **ICT risk-management framework** required by
DORA Art. 6 and NIS2 Art. 21(2)(a). It does **not** duplicate the underlying
methodology, treatment, register, or applicability artifacts — it **references** them
(Section 5) and binds them into one governed framework with a defined owner, risk
appetite, control-framework reference, and review cadence.

**Honesty note (HONESTY IS THE SPEC).** No senior-management review of this framework
has occurred yet. The `Last Reviewed:` field is therefore deliberately recorded as
`pending initial management review` rather than a founder-typed date. The automated
validator (`scripts/validators/check_ict_risk_framework.py`) will consequently report
this control as **not fresh / not yet attested** until a genuine management review is
held and the date is recorded here. This is intentional: the framework content exists
and is real, but the *attested annual review* is a human event that has not yet
happened, and the pipeline must not fake a PASS on a date nobody actually reviewed.

---

## 2. Governance and Ownership

| Aspect | Assignment |
|---|---|
| **Framework owner (accountable)** | Security Lead, CyberForge |
| **Management body (approving)** | CyberForge management (founder/management team) — per NIS2 Art. 20(1), the management body approves and oversees ICT risk measures |
| **Operational responsibility** | Security Lead + engineering on-call |
| **Review/approval forum** | ISMS Management Review (see [management-review-template.md](management-review-template.md), ISO 27001 Cl. 9.3) |

The management body retains overall accountability for ICT risk management (DORA Art.
5(2)). The Security Lead maintains this framework and the referenced artifacts and
presents them at each management review.

---

## 3. Risk Appetite and Tolerance

CyberForge operates a **low risk appetite** for confidentiality and integrity of
customer and pipeline data, and a **moderate** appetite for availability commensurate
with its current stage. Quantified tolerances:

| Dimension | Tolerance statement |
|---|---|
| **Confidentiality / Integrity** | No acceptance of risks scoring "High" or above on the inherent-risk scale without a documented, time-bound risk acceptance (see [risk-acceptance-process.md](risk-acceptance-process.md)). |
| **Availability** | Target platform RTO ≤ 60 min, RPO ≤ 15 min for the core pipeline (see BCDR runbooks). |
| **Vulnerabilities** | Zero tolerance for unremediated CRITICAL CVEs in shipped images at release gate. |
| **Residual risk** | Residual risk above tolerance requires explicit management-body sign-off. |

Risk appetite is reviewed and, if necessary, recalibrated at each annual framework
review.

---

## 4. Risk-Management Methodology (Reference)

The framework adopts the qualitative, asset-based methodology defined in
[risk-assessment-methodology.md](risk-assessment-methodology.md) (ISO 27001 Cl.
6.1.2, 8.2). That document defines the identify → analyse → evaluate → treat cycle,
the likelihood/impact scales, and the risk scoring matrix. This framework does not
restate that methodology; it incorporates it by reference.

---

## 5. Control Framework and Bound Artifacts (Reference)

This framework binds the following existing governance artifacts. They are the
authoritative sources; this document references them rather than duplicating them.

| Component | Reference artifact | Standard hook |
|---|---|---|
| **Risk methodology** | [risk-assessment-methodology.md](risk-assessment-methodology.md) | ISO 27001 Cl. 6.1.2, 8.2 |
| **Risk treatment** | [risk-treatment-plan.md](risk-treatment-plan.md) | ISO 27001 Cl. 6.1.3, 8.3 |
| **Risk register** | [risk-register.md](risk-register.md) | DORA Art. 6 / ISO 27001 Cl. 8.2 |
| **Control framework (applicability)** | [statement-of-applicability.md](statement-of-applicability.md) | ISO 27001 Cl. 6.1.3(d) |

The control framework of record is the ISO/IEC 27001 Annex A set as scoped in the
Statement of Applicability, supplemented by DORA Chapter II and NIS2 Art. 21(2)
measures.

---

## 6. Review Cadence and Record

DORA Art. 6(5) requires the ICT risk-management framework to be reviewed **at least
once a year** (and after major ICT-related incidents). The review is conducted as part
of, or alongside, the ISMS management review.

| Review # | Date | Reviewed by | Outcome | Evidence |
|---|---|---|---|---|
| 1 | pending initial management review | _pending_ | _pending_ | _pending_ |

When the first genuine management review occurs, record its date in the
`**Last Reviewed:**` header field (top of this document) and add the row above. Until
then the freshness validator honestly flags this control as not-yet-reviewed.

---

## 7. Maintenance

- This framework is version-controlled in the governance repository.
- Changes to risk appetite, the bound control framework, or the referenced
  methodology require management-body approval at a review.
- The automated validator asserts presence of Sections 2–6 and the freshness of the
  `Last Reviewed:` date (≤ 365 days) as a BLOCKING gate; the human attestation that a
  review genuinely occurred is recorded here and treated as EVIDENCE-ONLY.

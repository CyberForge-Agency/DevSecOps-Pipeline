# Incident Response Runbook -- DORA/NIS2 Compliance

**Document Owner:** CISO / Security Lead
**Last Updated:** 2026-04-13
**Review Cadence:** Annually or after any major incident
**Regulatory References:** DORA Art. 17-19, NIS2 Art. 23, ISO 27001 A.5.24-A.5.28

---

## 1. Purpose

This runbook defines the incident response process for CyberForge, ensuring compliance with DORA (Digital Operational Resilience Act) and NIS2 (Network and Information Security Directive) reporting obligations. It covers incident classification, response timelines, reporting requirements, and escalation procedures.

---

## 2. DORA Article 19 Reporting Timelines

DORA Article 19 requires financial entities (and their ICT third-party service providers, including CyberForge) to report **major ICT-related incidents** to their competent authority using a three-phase notification structure:

| Report Type | Deadline | Content |
|---|---|---|
| **Initial Notification** | Within **4 hours** of classifying the incident as major (and no later than 24 hours after detection) | Basic facts: what happened, when, initial impact assessment, whether services are affected |
| **Intermediate Report** | Within **72 hours** of the initial notification | Updated impact analysis, root cause (if known), remediation actions taken, containment status, affected clients/services |
| **Final Report** | Within **1 month** of the intermediate report | Complete root cause analysis, total impact quantification, remediation completed, lessons learned, preventive measures implemented |

### NIS2 Article 23 Parallel Obligations

If CyberForge or its clients fall under NIS2 scope (essential or important entities), the following parallel obligations apply:

| Report Type | Deadline | Recipient |
|---|---|---|
| Early Warning | Within **24 hours** of becoming aware | National CSIRT or competent authority |
| Incident Notification | Within **72 hours** | National CSIRT or competent authority |
| Final Report | Within **1 month** | National CSIRT or competent authority |

---

## 3. Incident Classification

### 3.1 What Qualifies as a "Major" ICT-Related Incident (DORA Art. 18)

An incident is classified as **major** if it meets **two or more** of the following criteria:

| Criterion | Threshold |
|---|---|
| **Affected clients** | >10% of clients or any client in a critical sector (banking, insurance, market infrastructure) |
| **Duration** | Service degradation lasting >2 hours or outage lasting >1 hour |
| **Geographic spread** | Affects clients in >2 EU member states |
| **Data integrity/confidentiality** | Any confirmed data breach, unauthorized access, or data loss |
| **Economic impact** | Direct costs exceeding EUR 100,000 or 5% of quarterly revenue (whichever is lower) |
| **Reputational impact** | Media coverage, regulatory inquiry, or client escalation to supervisory authority |
| **Critical functions affected** | Core service delivery impaired (pipeline execution, evidence generation, deployment) |

### 3.2 Severity Levels

| Severity | Description | Response SLA | Examples |
|---|---|---|---|
| **SEV-1 (Critical)** | Service outage affecting production clients; data breach; supply chain compromise | Immediate response, all-hands | Compromised signing keys, ACR breach, client data exposure |
| **SEV-2 (High)** | Major feature degradation; security vulnerability actively exploited; failed security gates bypassed | Response within 1 hour | DAST finds critical vulns in production, pipeline security gate bypass |
| **SEV-3 (Medium)** | Non-critical service degradation; security vulnerability not yet exploited | Response within 4 hours | Build failures, non-critical CVE in dependency, monitoring gaps |
| **SEV-4 (Low)** | Minor issue; informational security event | Response within 24 hours | Minor UI bug, low-severity CVE, documentation gap |

### 3.3 Decision Tree

```
Is there confirmed data breach or unauthorized access?
  YES -> SEV-1 (Major incident -- initiate DORA reporting)
  NO  -> Continue

Is production service unavailable or critically degraded?
  YES -> Duration > 1 hour?
    YES -> SEV-1 (Major incident -- initiate DORA reporting)
    NO  -> SEV-2 (escalate to SEV-1 if not resolved within 1 hour)
  NO  -> Continue

Are security controls bypassed or compromised?
  YES -> SEV-2 (evaluate for major incident classification)
  NO  -> Continue

Is a known vulnerability being actively exploited?
  YES -> SEV-2 (evaluate for major incident classification)
  NO  -> SEV-3 or SEV-4 based on impact
```

---

## 4. Required Content for Each Report Type

### 4.1 Initial Notification (4 hours)

| Field | Description |
|---|---|
| Incident ID | Unique identifier (GitHub issue number) |
| Detection time | When the incident was first detected (UTC) |
| Classification time | When it was classified as major (UTC) |
| Incident type | Data breach / Service disruption / Cyber attack / Supply chain / Other |
| Affected services | Which CyberForge services are impacted |
| Affected clients | Number and type of affected clients (if known) |
| Initial impact assessment | Brief description of business impact |
| Current status | Ongoing / Contained / Resolved |
| Initial actions taken | What has been done so far |
| Point of contact | Name and contact details of incident lead |

### 4.2 Intermediate Report (72 hours)

| Field | Description |
|---|---|
| All fields from Initial Notification | Updated as needed |
| Root cause (preliminary) | Best current understanding of what caused the incident |
| Attack vector | How the incident occurred (if applicable) |
| Containment actions | Specific technical measures taken to contain |
| Affected data types | Categories of data affected (if data breach) |
| Cross-border impact | Whether incident affects services in other EU member states |
| Client notifications sent | Whether and when clients were notified |
| Regulatory notifications | Other regulators notified (e.g., DPA for GDPR breach) |
| Timeline of events | Chronological log of incident response actions |
| Ongoing remediation | Actions still in progress |

### 4.3 Final Report (1 month)

| Field | Description |
|---|---|
| All fields from Intermediate Report | Finalized |
| Root cause analysis (complete) | Full technical and organizational root cause |
| Total duration | From detection to full resolution |
| Total impact quantification | Number of affected clients, data records, financial cost |
| Remediation completed | All technical fixes applied |
| Lessons learned | What went well, what failed, what was missing |
| Preventive measures | Specific changes to prevent recurrence |
| Process improvements | Changes to incident response process |
| Evidence references | Links to evidence pack, logs, forensics |

---

## 5. Communication Tree and Escalation

### 5.1 Escalation Matrix

| Time Since Detection | Action | Responsible |
|---|---|---|
| T+0 min | Incident detected (alert, DAST, manual report) | On-call engineer |
| T+15 min | Initial triage and severity classification | On-call engineer |
| T+30 min | Incident lead assigned; response team assembled | CTO / Security Lead |
| T+1 hour | Containment actions initiated | Incident lead |
| T+4 hours | Initial notification to competent authority (if major) | CISO / CTO |
| T+4 hours | Client notification (if service impact) | CTO |
| T+24 hours | NIS2 early warning (if applicable) | CISO / CTO |
| T+72 hours | Intermediate report submitted | CISO / CTO |
| T+72 hours | NIS2 incident notification (if applicable) | CISO / CTO |
| T+1 month | Final report submitted | CISO / CTO |

### 5.2 Communication Channels

| Channel | Use For |
|---|---|
| GitHub Issues | Incident tracking, evidence, timeline logging (use `ict-incident-report` template) |
| Email | Client notifications, regulatory reports |
| Phone/Signal | Urgent escalation for SEV-1 incidents |
| Status page (if deployed) | Public-facing service status |

### 5.3 External Contacts

| Entity | When to Contact | Deadline |
|---|---|---|
| KNF (Polish Financial Supervision) | DORA major incidents affecting financial clients | 4h initial / 72h intermediate / 1mo final |
| CSIRT NASK | NIS2 incidents | 24h early warning / 72h notification / 1mo final |
| UODO (Polish DPA) | GDPR personal data breaches | 72 hours |
| Affected clients | Any service impact or data breach | As soon as reasonably possible |

---

## 6. Integration with Automated Incident Detection

### 6.1 DAST Auto-Incident Workflow

The DAST workflow (`.github/workflows/dast.yml`) automatically creates a GitHub issue when OWASP ZAP finds HIGH/CRITICAL vulnerabilities. This issue includes:

- Finding details and severity
- Link to the pipeline run
- Commit SHA and scan target URL
- Triage SLA (4 hours), fix SLA (48 hours), deploy SLA (72 hours)
- Required action checklist

These auto-created issues should be triaged according to the classification criteria in Section 3 to determine if they constitute a major incident requiring DORA/NIS2 reporting.

### 6.2 Monitoring Alerts

Alert rules defined in `infra/modules/monitoring/main.tf` detect:
- Container App deployment failures
- Application error spikes (>10 errors in 10 minutes)
- Image pull failures

When these alerts fire, follow the operational procedures in `docs/runbooks/monitoring-setup.md` and classify per Section 3.

---

## 7. Post-Incident Activities

### 7.1 Post-Incident Review (Blameless)

Conduct a post-incident review within **5 business days** of incident resolution:

1. **Timeline reconstruction:** Build a complete timeline from detection to resolution
2. **Root cause analysis:** Use the "5 Whys" method
3. **Contributing factors:** Identify systemic issues (process gaps, tooling limitations, training needs)
4. **Action items:** Assign specific, time-bound corrective actions
5. **Evidence preservation:** Archive all incident artifacts to the evidence storage (WORM)
6. **Update runbooks:** If this runbook or any procedure was found lacking, update it

### 7.2 Corrective Actions

All corrective actions from post-incident reviews must be:
- Logged in `docs/governance/corrective-actions-log.md`
- Assigned to a named owner
- Given a target completion date
- Tracked to completion
- Verified effective in preventing recurrence

### 7.3 Evidence Retention

All incident evidence (logs, reports, communications, forensic data) must be retained in the evidence storage account for the WORM retention period (5 years) per DORA Art. 17(3) and the data retention policy.

# Crisis Management Plan

| Field          | Value                                                  |
|----------------|--------------------------------------------------------|
| Document Owner | CTO                                                    |
| Approved By    | CyberForge Management                                  |
| Version        | 1.0                                                    |
| Effective Date | 2026-03-15                                             |
| Review Cycle   | Annually, after any crisis event, or after crisis drill |
| Compliance     | NIS2 Art.21.2.c, DORA Art.11-12, ISO 27001 A.5.29-A.5.30, SOC 2 CC7 |

---

## 1. Purpose

This document establishes the crisis management framework for CyberForge. It defines what constitutes a crisis, assigns roles and responsibilities, specifies communication procedures, and outlines the response phases for events that exceed normal incident response capabilities.

A crisis is distinct from a routine incident. Routine incidents are handled through operational incident response procedures (planned, Task 24, `docs/runbooks/`). This plan activates when an event threatens CyberForge's ability to deliver services, protect client data, or maintain regulatory compliance, and cannot be resolved through normal incident response.

---

## 2. Crisis Definition

A **crisis** is an event or series of events that meets one or more of the following criteria:

- Threatens CyberForge's ability to deliver pipeline services to clients.
- Involves confirmed unauthorized access to client code, secrets, or sensitive data.
- Causes or risks causing regulatory non-compliance or enforcement action.
- Results in significant reputational damage to CyberForge.
- Cannot be contained or resolved through standard incident response procedures within established SLAs.
- Requires coordination with external parties (regulators, law enforcement, clients, media).

---

## 3. Crisis Categories

| Category    | Description                                                                      | Examples                                                              |
|-------------|----------------------------------------------------------------------------------|-----------------------------------------------------------------------|
| Security Breach | Unauthorized access to systems, data exfiltration, or supply chain compromise | Compromised GitHub org owner account, malicious code in pipeline workflows, leaked client secrets |
| Service Outage  | Prolonged outage affecting pipeline availability beyond SLA targets           | GitHub or Azure extended outage (>4 hours), cascading infrastructure failure |
| Data Loss       | Loss or corruption of critical data that cannot be recovered through normal backup | Evidence pack corruption, Terraform state loss, repository data loss  |
| Regulatory      | Enforcement action, audit failure, or regulatory notification deadline pressure | NIS2 enforcement action, failed compliance audit, GDPR breach notification deadline |
| Personnel       | Loss of key team member or insider threat                                      | Departure of sole knowledge holder, detected insider malicious activity |

---

## 4. Crisis Team

### 4.1 Roles and Responsibilities

| Role                 | Primary        | Backup          | Responsibilities                                                |
|----------------------|----------------|-----------------|------------------------------------------------------------------|
| Crisis Commander     | CTO            | Security Lead   | Overall decision authority, external communication authorization, resource allocation |
| Technical Lead       | Security Lead  | CTO             | Technical assessment, containment actions, recovery coordination, evidence preservation |
| Communications Lead  | CTO            | External PR advisor | Client notification, regulator communication, media statements (if required) |
| Legal Advisor        | External counsel | -              | Regulatory obligation assessment, liability analysis, notification review |

### 4.2 Crisis Team Activation

The crisis team is activated when:

- Any team member identifies a potential crisis condition (Section 2 criteria).
- An incident escalation from routine incident response determines the event exceeds normal handling capacity.
- An external party (client, regulator, law enforcement) reports a significant security event involving CyberForge.

Either the Crisis Commander or the Technical Lead may activate the crisis team. Activation does not require consensus -- it is better to activate and stand down than to delay response.

---

## 5. Communication Tree

### 5.1 Internal Escalation

```
Event Detected
    |
    v
Technical Lead assesses severity (within 15 minutes)
    |
    +-- NOT a crisis --> Handle via standard incident response
    |
    +-- CRISIS CONFIRMED
            |
            v
        Crisis Commander notified immediately (phone call, not message-only)
            |
            v
        Crisis team activated (within 30 minutes of confirmation)
            |
            v
        Initial situation assessment completed (within 1 hour of activation)
            |
            v
        Stakeholder notifications initiated (see Section 5.2)
```

### 5.2 Stakeholder Notification Timelines

| Stakeholder          | Channel                              | Timeline                          | Content                                             |
|----------------------|--------------------------------------|-----------------------------------|-----------------------------------------------------|
| Internal team        | Slack (primary), phone (backup)      | Immediate upon crisis activation  | Situation summary, assigned actions, communication restrictions |
| Affected clients     | Email + phone for critical impact    | Within 4 hours of confirmation    | What happened, what CyberForge is doing, what clients should do, next update timeline |
| Regulators (DORA)    | Designated reporting channel         | 4 hours (initial), 72 hours (intermediate), 1 month (final) | Per DORA Art.19 notification templates |
| Regulators (NIS2)    | National CSIRT (Poland: NASK CSIRT)  | 24 hours (early warning), 72 hours (notification), 1 month (final report) | Per NIS2 Art.23 notification templates |
| Regulators (GDPR)    | UODO (Polish DPA)                    | 72 hours from awareness of personal data breach | Per GDPR Art.33 breach notification format |
| Public/media         | Written statement only               | Only if required, via Communications Lead + Legal | Approved statement only; no ad-hoc media responses  |

### 5.3 Communication Rules During Crisis

- All external communications must be approved by the Crisis Commander before release.
- No team member may discuss the crisis on social media, public forums, or with unauthorized parties.
- A single point of contact (Communications Lead) handles all inbound media inquiries.
- Client communications are factual and avoid speculation about root cause until confirmed.
- All communications are logged and timestamped for the post-crisis review.

---

## 6. Decision Authority Matrix

| Decision                        | Authority                              | Condition                                 |
|---------------------------------|----------------------------------------|-------------------------------------------|
| Activate crisis team            | Crisis Commander or Technical Lead     | Any suspected crisis meeting Section 2 criteria |
| Shut down pipeline              | Technical Lead                         | Active compromise of CI/CD workflows or infrastructure |
| Revoke all external access      | Technical Lead                         | Suspected unauthorized access via external accounts |
| Rotate all credentials          | Technical Lead                         | Confirmed or suspected credential compromise |
| Notify clients                  | Crisis Commander                       | Confirmed data exposure or service impact affecting clients |
| Notify regulators               | Crisis Commander + Legal Advisor       | Per regulatory timelines (Section 5.2)    |
| Issue public statement          | Crisis Commander + Legal Advisor       | Only when required by regulation or when silence causes greater harm |
| Resume operations               | Crisis Commander + Technical Lead      | After containment verified and recovery validated |
| Stand down crisis team          | Crisis Commander                       | After recovery confirmed and post-crisis review scheduled |

---

## 7. Crisis Response Phases

### Phase 1: Detection and Assessment (0-1 hour)

**Objective:** Confirm whether the event is a crisis and establish initial scope.

Actions:
1. Technical Lead receives alert or report and performs initial assessment.
2. Assess against crisis criteria (Section 2). Document the assessment.
3. If crisis confirmed, notify Crisis Commander immediately.
4. Crisis Commander activates crisis team.
5. Conduct initial situation assessment: what is known, what is not known, what is the potential impact.
6. Assign initial containment actions.
7. Begin crisis log (timestamp all actions and decisions).

### Phase 2: Containment (1-4 hours)

**Objective:** Prevent the crisis from spreading and preserve evidence.

Actions:
1. Isolate affected systems (disable compromised accounts, revoke tokens, restrict network access).
2. Preserve forensic evidence (do not delete logs, take snapshots of affected systems).
3. Assess blast radius: which assets, services, and clients are affected.
4. Implement emergency access controls if required.
5. Issue initial client notification if client impact is confirmed.
6. Determine regulatory notification obligations and timelines.
7. Activate external support if needed (legal counsel, forensics, vendor support).

### Phase 3: Eradication (4-24 hours)

**Objective:** Remove the root cause and close the attack vector.

Actions:
1. Identify and confirm the root cause.
2. Remove malicious code, unauthorized access, or compromised components.
3. Patch vulnerabilities that were exploited.
4. Rotate all potentially compromised credentials (OIDC federation configs, SSH keys, API tokens).
5. Verify eradication through scanning and manual review.
6. Submit regulatory notifications per required timelines.
7. Update crisis log with all actions taken.

### Phase 4: Recovery (24-72 hours)

**Objective:** Restore normal operations with verified integrity.

Actions:
1. Restore services from known-good backups or verified clean state.
2. Verify system integrity before resuming operations (re-run security scans, verify signatures).
3. Implement additional monitoring for indicators of recurrence.
4. Gradually restore access and services (do not restore everything simultaneously).
5. Confirm with clients that service has been restored and provide status update.
6. Crisis Commander and Technical Lead jointly approve resumption of normal operations.

### Phase 5: Post-Crisis Review (within 2 weeks)

**Objective:** Learn from the crisis and improve future response.

Actions:
1. Conduct post-crisis review meeting with all crisis team members.
2. Complete the Post-Crisis Review Template (Section 9.3).
3. Identify root causes and contributing factors.
4. Document lessons learned and recommended improvements.
5. Assign corrective actions with owners and deadlines.
6. Update this crisis management plan if procedures need revision.
7. Submit final regulatory report if required (1-month report for NIS2/DORA).
8. Archive all crisis documentation in the evidence pack.

---

## 8. Category-Specific Guidance

### 8.1 Security Breach Response

In addition to the general response phases:
- Immediately disable compromised accounts and rotate associated credentials.
- Assess whether client data was accessed or exfiltrated.
- Engage external forensics if the breach involves sophisticated threat actors.
- Consider law enforcement notification if criminal activity is suspected.
- Review GitHub Audit Log and Azure Activity Log for scope of unauthorized actions.

### 8.2 Service Outage Response

In addition to the general response phases:
- Contact the affected vendor's enterprise support channel.
- Assess whether the outage is vendor-side (GitHub/Azure status page) or CyberForge-side.
- Communicate expected recovery time to affected clients.
- If prolonged (>8 hours), assess whether manual workarounds are feasible.
- Document the outage duration for SLA compliance reporting.

### 8.3 Data Loss Response

In addition to the general response phases:
- Identify the scope of data loss (which assets, which time period).
- Attempt recovery from backups (Git clones, Azure GRS, WORM storage).
- For Terraform state loss, use `terraform import` to reconstruct state from live resources.
- Assess whether the data loss constitutes a personal data breach (GDPR notification obligation).

### 8.4 Regulatory Crisis Response

In addition to the general response phases:
- Engage Legal Advisor immediately.
- Assess the specific regulatory obligation and applicable deadline.
- Prepare response documentation with supporting evidence.
- Coordinate with external counsel for formal submissions.

### 8.5 Personnel Crisis Response

In addition to the general response phases:
- Immediately revoke access for any departing or suspected insider threat personnel per the [JML Process](jml-process.md).
- Conduct knowledge transfer assessment: identify critical knowledge held solely by the departing individual.
- Review all actions taken by the individual's accounts in the preceding 90 days.
- If insider threat is confirmed, preserve evidence and engage legal counsel.

---

## 9. Templates

### 9.1 Crisis Declaration Template

```
CRISIS DECLARATION
==================
Date/Time:          [YYYY-MM-DD HH:MM UTC]
Declared By:        [Name, Role]
Crisis Category:    [Security Breach / Service Outage / Data Loss / Regulatory / Personnel]
Severity:           [Critical / High]

SITUATION SUMMARY
What happened:      [Brief factual description]
When detected:      [Date/time of initial detection]
Current status:     [Active / Contained / Under Investigation]

INITIAL ASSESSMENT
Affected systems:   [List of affected assets from asset inventory]
Affected services:  [List of affected services from service inventory]
Client impact:      [Yes/No -- if yes, which clients and how]
Data exposure:      [Confirmed / Suspected / None]
Regulatory trigger: [NIS2 / DORA / GDPR / None -- notification deadlines]

ASSIGNED ACTIONS
Crisis Commander:   [Name]
Technical Lead:     [Name]
Immediate actions:  [List of first containment steps]
Next update:        [Date/time of next scheduled update]
```

### 9.2 Client Notification Template

```
Subject: Security Notice from CyberForge -- [Brief Description]

Dear [Client Name],

We are writing to inform you of a security event affecting CyberForge services.

WHAT HAPPENED
[Factual description of the event, without speculation about root cause
if not yet confirmed.]

WHAT WE ARE DOING
[Description of containment and recovery actions CyberForge is taking.]

WHAT YOU SHOULD DO
[Specific, actionable recommendations for the client. Examples:
- Review access logs for your GitHub organization
- Rotate any credentials shared with CyberForge
- No action required at this time]

TIMELINE FOR UPDATES
We will provide our next update by [date/time]. If you have immediate
questions, please contact [contact information].

[Name]
[Role]
CyberForge
```

### 9.3 Post-Crisis Review Template

```
POST-CRISIS REVIEW
===================
Crisis ID:          [Reference number]
Crisis Category:    [Category from Section 3]
Duration:           [Start date/time to resolution date/time]
Review Date:        [Date of this review]
Participants:       [Names and roles of review attendees]

TIMELINE
[Chronological record of key events, decisions, and actions with timestamps]

ROOT CAUSE
[Description of the root cause. If multiple contributing factors,
list each with its relative contribution.]

IMPACT ASSESSMENT
Systems affected:   [List]
Services affected:  [List]
Client impact:      [Description and count of affected clients]
Data exposure:      [Scope of any data exposure]
Financial impact:   [Estimated cost, if quantifiable]
Regulatory impact:  [Notifications made, regulatory actions taken]

RESPONSE EVALUATION
What worked well:   [List]
What could improve: [List]
Response timeline:  [Were notification deadlines met? Were phases completed on schedule?]

LESSONS LEARNED
[Numbered list of key takeaways]

CORRECTIVE ACTIONS
| # | Action                        | Owner          | Deadline   | Status     |
|---|-------------------------------|----------------|------------|------------|
| 1 | [Description]                 | [Name]         | [Date]     | [Open/Done]|
| 2 | [Description]                 | [Name]         | [Date]     | [Open/Done]|

DOCUMENT UPDATES REQUIRED
[List any policies, procedures, or plans that need updating based on lessons learned]
```

---

## 10. Crisis Readiness

### 10.1 Crisis Drills

Crisis response capability must be tested to be effective. CyberForge conducts:

- **Tabletop exercise:** Annually. A simulated crisis scenario is walked through by the crisis team without actual system changes. Validates communication tree, decision authority, and notification procedures.
- **Technical drill:** Annually (may be combined with BC/DR testing, Task 25). Tests actual containment and recovery actions in a non-production environment.

Drill results are documented and any gaps identified are addressed through corrective actions.

### 10.2 Contact Information

Crisis team contact details are maintained in a separate, access-controlled document to prevent exposure of personal phone numbers and email addresses. All crisis team members must have current contact information on file and immediately notify the Crisis Commander of any changes.

Required contact information:
- Primary phone number (for immediate crisis notification)
- Backup phone number
- Personal email (for use when corporate email is unavailable)
- Physical location / time zone (for response coordination)

### 10.3 External Contacts

| Contact               | Organization                 | When to Engage                                |
|-----------------------|------------------------------|-----------------------------------------------|
| Legal Counsel         | [External law firm]          | Any crisis with regulatory or liability implications |
| NASK CSIRT            | National CSIRT (Poland)      | NIS2 incident reporting obligations           |
| UODO                  | Polish Data Protection Authority | GDPR personal data breach notification     |
| GitHub Enterprise Support | GitHub (Microsoft)       | GitHub service compromise or extended outage  |
| Azure Enterprise Support  | Microsoft                | Azure service compromise or extended outage   |
| Law Enforcement       | Local/national police        | Criminal activity or law enforcement request  |

---

## 11. Compliance Mapping

| Requirement                            | Framework Reference      | How This Plan Addresses It                                |
|----------------------------------------|--------------------------|-----------------------------------------------------------|
| Business continuity and crisis management | NIS2 Art.21.2.c       | Crisis definition, response phases, communication tree    |
| Incident management and reporting      | NIS2 Art.23             | Regulatory notification timelines (24h/72h/1mo)          |
| BC/DR and crisis management            | DORA Art.11-12          | Crisis response framework, recovery phases               |
| Major incident reporting               | DORA Art.19             | Regulatory notification timelines (4h/72h/1mo)           |
| ICT-related incident management        | DORA Art.17             | Crisis classification, escalation, response phases       |
| Business continuity planning           | ISO 27001 A.5.29-A.5.30 | Crisis preparedness, drills, post-crisis review          |
| System operations                      | SOC 2 CC7               | Crisis detection, response, recovery procedures          |

---

## 12. Related Documents

- [Asset Inventory](asset-inventory.md)
- [Service Inventory](service-inventory.md)
- [IAM Governance Policy](iam-governance.md)
- [JML Process](jml-process.md)
- [Vendor Risk Register](vendor-risk-register.md)
- [Vulnerability Management Policy](vulnerability-management-policy.md)
- [Scope and Limitations](../compliance/scope-and-limitations.md)
- [Framework Boundaries](../compliance/framework-boundaries.md)
- Incident Handling Runbooks (planned, Task 24, `docs/runbooks/`)
- BC/DR Plan (planned, Task 25)

---

## 13. Revision History

| Date       | Change             | Author                  |
|------------|--------------------|-------------------------|
| 2026-03-15 | Initial version    | CyberForge Engineering  |

# SentinelOps AI — Incident Response Policy

## Purpose

This policy governs automated and human-in-the-loop incident response executed by SentinelOps AI agents in enterprise cloud environments.

## Scope

Applies to all production services including PaymentAPI, AuthService, DatabaseCluster, IAMService, and SecurityGateway.

## Severity Classification

| Level    | Criteria                                      | Response SLA |
|----------|-----------------------------------------------|--------------|
| CRITICAL | Data loss risk, auth bypass, policy violation | 15 minutes   |
| HIGH     | Customer-facing outage, payment failures      | 30 minutes   |
| MEDIUM   | Degraded performance, partial failures        | 2 hours      |
| LOW      | Monitoring alerts without user impact         | 24 hours     |

## Prohibited Actions (Automatic Block)

The following must **never** be executed without explicit CISO approval:

- Deleting production databases or persistent volumes
- Disabling authentication, MFA, or audit logging
- Exposing customer PII or secrets in incident channels
- Privilege escalation without ticket linkage
- Bypassing compliance or guardrail systems

## Approval Requirements

High-risk remediations require two-person approval:

- Production database failover
- Mass token revocation
- Production rollbacks affecting >10% traffic
- Firewall or network segmentation changes

## Prompt Injection & Abuse

User inputs attempting to override system instructions, ignore policies, or manipulate agents must be blocked immediately. All blocks are logged to the immutable audit trail.

## Data Handling

- Logs and evidence remain in-memory during MVP processing
- No customer PII may be written to external systems without redaction
- Retention follows `compliance_rules.json` data_retention_days

## Escalation

1. On-call SRE (PagerDuty)
2. Security Operations Center
3. Compliance Officer (for policy violations)

## Audit

Every agent step, guardrail decision, and remediation recommendation is recorded with UTC timestamps for SOC 2 alignment.

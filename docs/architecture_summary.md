# SentinelOps AI — Architecture Summary

## Multi-Agent Design

SentinelOps AI implements a **hub-and-spoke orchestration pattern** with seven single-responsibility agents. Each agent returns a structured JSON dictionary consumed by downstream steps and the Streamlit UI. Separation of concerns enables independent testing, policy enforcement at dedicated checkpoints, and clear audit attribution.

### Agent Responsibilities

1. **Intake** — Normalizes unstructured incident text into intent, entities, services, and severity.
2. **Planner** — Emits a task graph and execution order (sequential vs parallel phases).
3. **Log Analysis** — Joins cloud metrics and security events from CSV fixtures.
4. **Root Cause** — Applies rule-based (or LLM) inference over evidence bundles.
5. **Compliance** — Enforces `compliance_rules.json`, guardrails, and injection heuristics.
6. **Remediation** — Produces gated action lists; skips entirely on compliance block.
7. **Auditor** — Aggregates scores, executive summary, and immutable-style audit trail.

## Orchestration Flow

```
User Input
    → IntakeAgent
    → PlannerAgent
    → [ LogAnalysisAgent || ComplianceAgent ]  (log first, then RCA uses output)
    → RootCauseAgent
    → RemediationAgent   (skipped if ComplianceAgent.blocked)
    → AuditorAgent
    → Final Report
```

**Sequential vs parallel:** Log analysis and compliance checks are logically parallelizable; the MVP runs log analysis before RCA because RCA depends on evidence. Compliance can short-circuit the pipeline before remediation—an intentional **fail-fast** security control.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Input | `check_guardrails()` phrase blocklist |
| Compliance | `blocked_actions`, injection patterns, policy JSON |
| Remediation | `requires_approval` flags on high-risk steps |
| Audit | Per-step UTC timestamps in `audit_trail` |

Blocked incidents receive elevated risk score (98) and minimal confidence (15) to signal low trust in automated handling.

## LLM Integration

`LLMClient` abstracts provider selection:

- **Groq** (preferred when `GROQ_API_KEY` set)
- **OpenAI** (fallback when Groq unavailable)
- **Mock** (deterministic keyword/rules — default for demos)

Mock mode ensures reproducible demos for interviewers and Streamlit Cloud reviewers without secrets.

## Data Layer (MVP)

All processing is **in-memory**:

- `cloud_logs.csv` — service metrics with status flags
- `security_events.csv` — auth and privilege events
- `compliance_rules.json` — machine-readable policy
- `incident_policy.md` — human-readable policy reference

No external databases or cloud APIs are required.

## Scalability Path (Future Azure Production)

| MVP Component | Production Target |
|---------------|-------------------|
| CSV fixtures | Azure Monitor / Log Analytics queries |
| In-memory orchestrator | Azure Functions + Durable Functions or Container Apps |
| Streamlit UI | React ops portal + API gateway |
| Mock LLM | Azure OpenAI with private endpoints |
| Audit trail | Azure Table Storage / immutable blob audit log |
| Guardrails | Azure AI Content Safety + custom policy engine |

### Recommended Production Topology

```
Azure Front Door
    → API Management
        → Incident Orchestrator (Container Apps)
            → Agent microservices (scale per agent)
            → Azure OpenAI (private VNet)
            → Log Analytics / Sentinel connectors
            → Key Vault (secrets, no env files)
```

## Why Custom Orchestration (Not LangGraph) for MVP

LangGraph adds dependency weight and deployment complexity for a screening MVP. The custom `SentinelOrchestrator` class mirrors the same DAG semantics and can be migrated to LangGraph later by wrapping each agent `run()` as a graph node—preserving agent interfaces.

## Observability

The Streamlit **System Metrics** page surfaces anomaly counts from mock telemetry. Production would export OpenTelemetry spans per agent with correlation IDs tied to incident tickets.

---

*Document version: 1.0 — SentinelOps AI MVP*

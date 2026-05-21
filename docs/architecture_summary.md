# SentinelOps AI — Architecture Summary

## Multi-Agent Design

SentinelOps AI implements a **shared-context orchestration pattern** with eight single-responsibility agents. Each agent returns a structured JSON dictionary; the orchestrator stores outputs in a shared `context` object so downstream agents and the Streamlit UI can consume prior results without re-parsing raw text.

### Agent Responsibilities

1. **Intake** — Normalizes unstructured incident text into intent, entities, services, and severity.
2. **Planner** — Emits a task list and execution order (sequential vs parallel phases).
3. **Log Analysis** — Joins cloud metrics and security events from CSV fixtures.
4. **Root Cause** — Applies rule-based (or LLM) inference over evidence bundles.
5. **Compliance** — Enforces `compliance_rules.json`, guardrails, and injection heuristics.
6. **Remediation** — Produces gated action lists; skips entirely on compliance block.
7. **Validation** — Post-remediation scan for high-risk language (delete, disable, purge, bypass, PII, etc.); sets `requires_approval` when needed.
8. **Auditor** — Aggregates scores, executive summary, and immutable-style audit trail.

## Orchestration Flow

```
User Input
    → IntakeAgent
    → PlannerAgent
    → LogAnalysisAgent
    → ComplianceAgent
    → RootCauseAgent
    → RemediationAgent
    → ValidationAgent
    → AuditorAgent
    → Final Report
```

**Shared context:** `SentinelOrchestrator.run()` initializes `context` with `incident_text`, `audit_trail`, `workflow`, and `timings`. Each `_run_agent` step writes enriched output back into `context` before the next agent executes.

**Sequential vs parallel:** Log analysis and compliance are logically parallelizable; the MVP runs log analysis before RCA because RCA depends on evidence. Compliance can short-circuit the pipeline before remediation—an intentional **fail-fast** security control. Validation always runs after remediation when remediation is produced.

See [architecture_diagram.md](architecture_diagram.md) for a Mermaid diagram including Guardrails, Groq, and Cloud Run.

## Agent Instantiation and Termination

| Phase | Behavior |
|-------|----------|
| **Instantiation** | `SentinelOrchestrator.__init__` constructs one instance per agent class and a shared `LLMClient`. Agents are stateless per run. |
| **Execution** | `run(incident_text)` drives a single linear pass; each agent's `run()` is invoked inside `_run_agent` with timing metadata. |
| **Early termination** | Intake guardrail or compliance `blocked` halts downstream agents; remediation, validation, and RCA may be marked `skipped` or `pending`. |
| **Normal termination** | Auditor completes; orchestrator returns final dict with `workflow_status`, `audit_trail`, and `used_fallback` when LLM fallback was used. |

No background workers or persistent agent processes—the lifecycle is **per incident request** inside the Streamlit session.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Input | `check_guardrails()` phrase blocklist |
| Compliance | `blocked_actions`, injection patterns, policy JSON |
| Validation | High-risk phrase scan on remediation narrative |
| Remediation | `requires_approval` flags on high-risk steps |
| Output | `validate_llm_output()` redacts email, phone, SSN, API keys before UI |
| Audit | Per-step UTC timestamps in `audit_trail` |

Blocked incidents receive elevated risk score (98) and minimal confidence (15) to signal low trust in automated handling.

## PII and Data Handling

| Topic | MVP behavior |
|-------|----------------|
| **Training / demo data** | Synthetic CSV and JSON under `data/` only—no production customer data. |
| **Environment** | `GROQ_API_KEY`, `OPENAI_API_KEY` via `.env` locally or platform env vars on Cloud Run / Azure. |
| **Production PII pipeline** | Recommended: ingest redacted tickets, scan with DLP, store tokens not raw PII, run `validate_llm_output` on every model response before persistence. |
| **Output filtering** | Streamlit applies `validate_llm_output` to summaries and remediation text; UI shows "Output Filtered" when violations are redacted. |

## LLM Integration

`LLMClient` abstracts provider selection:

- **Groq** (preferred when `GROQ_API_KEY` set)
- **OpenAI** (fallback when Groq unavailable)
- **Mock** (deterministic keyword/rules — default for demos)

Retries: up to **2** retries with brief backoff; on failure returns mock with `used_fallback=True`. The UI warns operators when fallback mode is active (no raw stack traces).

## Data Layer (MVP)

All processing is **in-memory**:

- `cloud_logs.csv` — service metrics with status flags
- `security_events.csv` — auth and privilege events
- `compliance_rules.json` — machine-readable policy
- `incident_policy.md` — human-readable policy reference

No external databases or cloud APIs are required.

## Custom Orchestration (Not LangGraph)

LangGraph adds dependency weight and deployment complexity for a screening MVP. The custom `SentinelOrchestrator` in `orchestrator.py` mirrors DAG semantics and can be migrated later by wrapping each agent `run()` as a graph node—preserving agent interfaces.

**Why custom:** Full control over shared context, audit trail shape, guardrail short-circuiting, and Cloud Run / Streamlit packaging without an extra graph runtime.

## Parallel Execution (Future)

Today all agents run **sequentially** in one Python process. A future release could:

- Run Log Analysis and Compliance in parallel threads/async tasks, then join before RCA.
- Fan out per-service sub-agents with a merge step into `context`.
- Use LangGraph or Durable Functions for checkpointing and human-in-the-loop interrupts at Validation.

The shared `context` dict is the integration contract for any parallel scheduler.

## Scalability Path (Cloud Run / Azure Production)

| MVP Component | Production Target |
|---------------|-------------------|
| CSV fixtures | Azure Monitor / Log Analytics or GCP Logging |
| In-memory orchestrator | Cloud Run service or Container Apps with horizontal scale |
| Streamlit UI | React ops portal + API gateway |
| Mock LLM | Groq / Azure OpenAI with private endpoints |
| Audit trail | Immutable blob or Table Storage |
| Guardrails | Content Safety + custom policy engine |

### Recommended Production Topology

```
Cloud Run / Azure Front Door
    → API Management
        → Incident Orchestrator
            → Agent workers (scale per agent)
            → Groq / Azure OpenAI (private egress)
            → SIEM connectors
            → Secret Manager (no plain env files)
```

## Observability

The Streamlit **System Metrics** page surfaces anomaly counts from mock telemetry. Production would export OpenTelemetry spans per agent with correlation IDs tied to incident tickets.

---

*Document version: 1.1 — SentinelOps AI MVP (8 agents + validation + output guardrails)*

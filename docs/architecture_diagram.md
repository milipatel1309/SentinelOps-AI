# SentinelOps AI — Architecture Diagram

```mermaid
flowchart TB
    subgraph Users["Operators"]
        U[SOC Analyst / Commander / Compliance / Manager]
    end

    subgraph CloudRun["Google Cloud Run"]
        UI[Streamlit app.py]
        ORCH[SentinelOrchestrator]
        CTX[(Shared context dict)]
    end

    subgraph Agents["Agent pipeline — sequential"]
        I[IntakeAgent]
        P[PlannerAgent]
        L[LogAnalysisAgent]
        CO[ComplianceAgent]
        R[RootCauseAgent]
        RM[RemediationAgent]
        V[ValidationAgent]
        A[AuditorAgent]
    end

    subgraph Safety["Safety layers"]
        GR[check_guardrails input]
        VF[validate_llm_output display]
    end

    subgraph LLM["LLM providers"]
        GQ[Groq API]
        OAI[OpenAI API]
        MOCK[Deterministic mock fallback]
    end

    subgraph Data["Synthetic data MVP"]
        CSV[cloud_logs.csv / security_events.csv]
        POL[compliance_rules.json]
    end

    U --> UI
    UI --> GR
    GR --> ORCH
    ORCH --> CTX
    CTX --> I --> P --> L --> CO --> R --> RM --> V --> A
    I & P & L & R & RM --> GQ
    GQ -.->|retry / fail| OAI
    OAI -.->|retry / fail| MOCK
    L --> CSV
    CO --> POL
    A --> VF
    VF --> UI
    A --> UI
```

## Flow summary

1. **Input guardrails** scan operator text before agents run.
2. **Orchestrator** initializes shared `context` and runs eight agents in order.
3. **ValidationAgent** sits after Remediation and before Auditor.
4. **Output guardrails** sanitize summaries before Streamlit renders them.
5. **Groq** is preferred; **OpenAI** and **mock** provide retries and fallback.

---

*See [architecture_summary.md](architecture_summary.md) for narrative design notes.*

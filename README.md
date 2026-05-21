
Live website: https://sentinelops-ai-427637329209.us-central1.run.app/

Live Demo youtube link: https://youtu.be/G0-QVhzKzqg

Live Presentation link: https://youtu.be/Sw4fKI_cw-U

# SentinelOps AI

**Multi-Agent Cloud Incident Response & Compliance Orchestration Platform**

SentinelOps AI is an enterprise-style Streamlit MVP for Security Operations Center (SOC) workflows. Eight specialized agents analyze cloud incidents using **synthetic** mock telemetry, enforce compliance guardrails, validate remediation plans, and produce auditable reports—without requiring API keys for local demos.

**Live deployment (Cloud Run):** `https://your-cloud-run-url` — replace after `gcloud run deploy` or set your service URL in CI.

![Dashboard Placeholder](assets/ui_mockups/.gitkeep)

---

## Overview

Operators describe a cloud incident in natural language. The platform routes the request through intake, planning, log analysis, compliance, root cause, remediation, **validation**, and final audit—producing severity classification, evidence, root cause, compliance status, remediation steps, risk/confidence scores, and a full audit trail.

**Key capabilities:**

- **8-agent** orchestrated workflow (`orchestrator.py` + shared context)
- Role-based access (SOC Analyst, Incident Commander, Compliance Reviewer, SOC Manager, Observer)
- Deterministic mock AI when no LLM keys are configured
- Optional **Groq** / **OpenAI** with retries and graceful fallback
- Input guardrails + **output filtering** (`validate_llm_output`) before UI display
- **ValidationAgent** between Remediation and Auditor
- Dark enterprise UI with workflow pipeline and trust badges

---

## Architecture

```
User Input → Intake → Planner → Log Analysis → Compliance → Root Cause
    → Remediation → Validation → Auditor → Final Report
```

| Document | Description |
|----------|-------------|
| [docs/architecture_summary.md](docs/architecture_summary.md) | Design, PII, instantiation, custom vs parallel orchestration |
| [docs/architecture_diagram.md](docs/architecture_diagram.md) | Mermaid flowchart (Validation, Guardrails, Groq, Cloud Run) |
| [docs/testing_summary.md](docs/testing_summary.md) | Manual test matrix |
| [docs/azure_deployment_guide.md](docs/azure_deployment_guide.md) | Azure App Service steps |

---

## Agents

| Agent | Responsibility |
|-------|----------------|
| **IntakeAgent** | Intent, entities, affected services, severity |
| **PlannerAgent** | Task list and execution order |
| **LogAnalysisAgent** | CSV log analysis, anomalies, evidence |
| **RootCauseAgent** | RCA from correlated evidence |
| **ComplianceAgent** | Policy checks, prompt injection detection |
| **RemediationAgent** | Safe actions with approval flags |
| **ValidationAgent** | Post-remediation high-risk phrase scan, approval flags |
| **AuditorAgent** | Risk/confidence scores, executive summary |

Agents communicate through a **shared `context` dict** managed by `SentinelOrchestrator` (see `orchestrator.py` docstring).

---

## Guardrails & Output Filtering

**Input** (`check_guardrails`): blocks unsafe instructions (prompt injection, policy bypass, destructive actions).

**Output** (`validate_llm_output`): redacts emails, phone numbers, SSNs, and API-key-like tokens before summaries appear in the UI. The app shows:

- Note: *LLM output validated before display.*
- Badge: **Output Filtered** (when redactions occur)
- Badge: **Synthetic data only** — no real PII processed

---

## PII & Synthetic Data

| Area | MVP |
|------|-----|
| Telemetry | Mock CSV/JSON under `data/` only |
| Customer PII | Not collected; demo accounts are fictional |
| Env vars | `GROQ_API_KEY`, `OPENAI_API_KEY` in `.env` or platform settings |
| Production | Use DLP on ingest, tokenize identifiers, run `validate_llm_output` on every model response before storage |

---

## LLM Client

`utils/llm_client.py`:

- Priority: **Groq → OpenAI → deterministic mock**
- Up to **2 retries** with short backoff on provider errors
- Returns `used_fallback=True` when mock is used; UI shows a friendly warning (not raw exceptions)

---

## Orchestration

| Topic | Implementation |
|-------|----------------|
| Entry point | `orchestrator.py` — `SentinelOrchestrator.run(incident_text)` |
| Backward import | `from agents import SentinelOrchestrator` still works |
| Instantiation | One agent instance per class per orchestrator; stateless per run |
| Termination | Early exit on guardrail/compliance block; otherwise Auditor completes |
| Future parallel | Log + Compliance in parallel; join before RCA (see architecture_summary) |

**Custom orchestration** avoids LangGraph weight for the MVP while preserving a clear migration path to graph-based checkpointing later.

---

## Tech Stack

- **UI:** Streamlit (enterprise dark theme)
- **Data:** Pandas, in-memory CSV/JSON
- **Orchestration:** `SentinelOrchestrator` (shared context, sequential pipeline)
- **LLM (optional):** Groq, OpenAI
- **Deploy:** Streamlit Cloud, **Google Cloud Run** (`Procfile`), or Azure App Service (`startup.sh`)

---

## Folder Structure

```
SentinelOps AI/
├── app.py                 # Streamlit UI
├── orchestrator.py        # SentinelOrchestrator (shared context)
├── Procfile               # Cloud Run / Heroku-style: streamlit on $PORT
├── startup.sh             # Azure App Service
├── requirements.txt
├── agents/                # Eight agents + package re-exports
├── utils/                 # guardrails, llm_client, agent_metadata, RBAC
├── data/                  # Mock logs, rules, policy
└── docs/                  # Architecture, diagram, testing, Azure guide
```

---

## Setup (Local)

```bash
cd "/Users/milipatel/Desktop/SentinelOps AI"
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501`.

### Optional LLM Keys

```bash
cp .env.example .env
# Add GROQ_API_KEY and/or OPENAI_API_KEY
streamlit run app.py
```

Restart Streamlit after changing `.env`. Sidebar shows **Groq connected**, **OpenAI connected**, or **Mock mode active**.

---

## Verification

```bash
cd "/Users/milipatel/Desktop/SentinelOps AI"
python3 -c "from orchestrator import SentinelOrchestrator; o=SentinelOrchestrator(); print('ok')"
python3 -c "import app"
python3 -c "from utils.guardrails import validate_llm_output; print(validate_llm_output('email test@x.com'))"
```

Full manual checklist: [docs/testing_summary.md](docs/testing_summary.md).

---

## Deploy to Google Cloud Run

1. Build and deploy container or use Cloud Run source deploy with `Procfile`.
2. Set `PORT` (injected by Cloud Run); `Procfile` runs Streamlit on `$PORT`.
3. Add secrets: `GROQ_API_KEY`, `OPENAI_API_KEY` (optional).
4. Note service URL as live deployment link in this README.

```procfile
web: streamlit run app.py --server.port $PORT --server.address 0.0.0.0
```

---

## Deploy to Streamlit Community Cloud

1. Push repository to GitHub (`app.py` at root).
2. [share.streamlit.io](https://share.streamlit.io) → Main file: `app.py`.
3. Optional secrets for LLM keys.

---

## Deploy to Azure App Service

See [docs/azure_deployment_guide.md](docs/azure_deployment_guide.md). Set **WEBSITES_PORT** = `8000`, startup `bash startup.sh`.

---

## Example Scenarios

| Preset | Expected outcome |
|--------|------------------|
| Payment API latency + failed logins | Full 8-agent pipeline; validation may flag rollback language |
| Database CPU + checkout failures | DB pool exhaustion RCA |
| Suspicious privilege escalation | Security remediation with approvals |
| Auth outage after deployment | Post-deploy rollback recommendation |
| Unsafe: delete production DB | **Guardrail block** — no remediation |

---

## Demo Accounts & RBAC

Use the in-app login screen (fictional users). Roles control queue visibility, run analysis, remediation approval, and compliance pages. Observer is read-only.

---

## Future Improvements

- Parallel Log + Compliance execution with context merge
- LangGraph checkpointing and human-in-the-loop at Validation
- Azure Monitor / GCP Logging connectors
- SSO and persistent incident store
- Real-time alert ingestion

---

## License

MVP for Junior Forward Deployed Engineer pre-screening assignment.

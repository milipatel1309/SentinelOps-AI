# SentinelOps AI — Manual Testing Summary

Use this checklist when validating the MVP before demo or submission. Run locally with `streamlit run app.py` unless noted.

| Test Case | Expected | Status |
|-----------|----------|--------|
| Import `orchestrator.SentinelOrchestrator` | `python3 -c "from orchestrator import SentinelOrchestrator; ..."` prints `ok` | ☐ |
| Import `app` module | No import errors | ☐ |
| `validate_llm_output('email test@x.com')` | Returns `sanitized_output` with `[REDACTED_EMAIL]`, `violations` includes `email_address` | ☐ |
| Login as SOC Analyst | Dashboard loads; Run Analysis enabled | ☐ |
| Login as Observer | Run Analysis disabled; read-only queues | ☐ |
| Preset: Payment API latency | 8-agent pipeline completes; validation + auditor in workflow UI | ☐ |
| Preset: Unsafe delete production DB | Intake/compliance guardrail blocks; remediation skipped | ☐ |
| Workflow pipeline UI | Shows Validation node between Remediation and Auditor | ☐ |
| Shared context card | "Agent Communication: Shared Context Orchestration" visible | ☐ |
| Output badges | "Output Filtered" when PII patterns present; synthetic data note shown | ☐ |
| LLM fallback (no API keys) | Warning banner; deterministic mock; `used_fallback` in result | ☐ |
| LLM with Groq key | Sidebar "Groq connected"; no fallback warning | ☐ |
| Remediation approval (Manager) | Pending approval banner; approve/reject updates incident | ☐ |
| Compliance Reviewer role | Compliance Operations queue; policy-focused view | ☐ |
| Demo preload (Commander INC-001) | Prebuilt payload includes `validation` block | ☐ |
| Cloud Run / Procfile deploy | App listens on `$PORT`; health page loads | ☐ |

## Quick verification commands

```bash
cd "/Users/milipatel/Desktop/SentinelOps AI"
python3 -c "from orchestrator import SentinelOrchestrator; o=SentinelOrchestrator(); print('ok')"
python3 -c "import app"
python3 -c "from utils.guardrails import validate_llm_output; print(validate_llm_output('email test@x.com'))"
```

---

*Update Status column to ✅ after each test passes.*

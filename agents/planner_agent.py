"""PlannerAgent — build execution plan for downstream agents."""

from __future__ import annotations

from typing import Any

from utils.llm_client import LLMClient


class PlannerAgent:
    name = "PlannerAgent"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    def run(self, intake: dict[str, Any]) -> dict[str, Any]:
        severity = intake.get("severity", "MEDIUM")
        services = intake.get("affected_services", [])

        tasks = [
            {"id": "T1", "agent": "LogAnalysisAgent", "description": "Analyze cloud and security logs"},
            {"id": "T2", "agent": "ComplianceAgent", "description": "Validate against policy and guardrails"},
            {"id": "T3", "agent": "RootCauseAgent", "description": "Infer root cause from evidence"},
            {"id": "T4", "agent": "RemediationAgent", "description": "Generate safe remediation steps", "depends_on": ["T1", "T2", "T3"]},
            {"id": "T5", "agent": "AuditorAgent", "description": "Finalize audit trail and scores", "depends_on": ["T4"]},
        ]

        if severity in ("CRITICAL", "HIGH"):
            execution_order = ["parallel:T1,T2", "T3", "T4", "T5"]
        else:
            execution_order = ["parallel:T1,T2,T3", "T4", "T5"]

        return {
            "agent": self.name,
            "status": "completed",
            "tasks": tasks,
            "execution_order": execution_order,
            "estimated_duration_minutes": 4 if severity == "HIGH" else 2,
            "focus_services": services,
            "plan_summary": (
                f"Execute log analysis and compliance in parallel, then RCA, "
                f"remediation, and audit for {', '.join(services)}."
            ),
        }

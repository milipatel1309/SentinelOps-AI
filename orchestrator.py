"""
SentinelOps AI orchestrator.

Agents communicate via a shared ``context`` dictionary passed through the pipeline.
Each step reads prior outputs from ``context`` and writes its result back before the
next agent runs. The orchestrator collects workflow status, validation, and audit trail.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from agents.auditor_agent import AuditorAgent
from agents.compliance_agent import ComplianceAgent
from agents.intake_agent import IntakeAgent
from agents.log_analysis_agent import LogAnalysisAgent
from agents.planner_agent import PlannerAgent
from agents.remediation_agent import RemediationAgent
from agents.root_cause_agent import RootCauseAgent
from agents.validation_agent import ValidationAgent
from utils.agent_metadata import enrich_agent_output, utc_now, workflow_status_final
from utils.llm_client import LLMClient


class SentinelOrchestrator:
    """
    Sequential multi-agent pipeline with shared context.

    Flow: Intake → Planner → Log Analysis → Compliance → Root Cause
    → Remediation → Validation → Auditor → Final Report
    """

    def __init__(self) -> None:
        self.llm = LLMClient()
        self.intake_agent = IntakeAgent(self.llm)
        self.planner_agent = PlannerAgent(self.llm)
        self.log_agent = LogAnalysisAgent(self.llm)
        self.rca_agent = RootCauseAgent(self.llm)
        self.compliance_agent = ComplianceAgent(self.llm)
        self.remediation_agent = RemediationAgent(self.llm)
        self.validation_agent = ValidationAgent()
        self.auditor_agent = AuditorAgent()

    def run(self, incident_text: str) -> dict[str, Any]:
        audit_trail: list[dict[str, Any]] = []
        workflow: dict[str, dict[str, Any]] = {}
        timings: dict[str, dict[str, Any]] = {}

        context: dict[str, Any] = {
            "incident_text": incident_text,
            "audit_trail": audit_trail,
            "workflow": workflow,
            "timings": timings,
        }

        def _log(step: str, status: str, detail: str = "") -> None:
            audit_trail.append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "step": step,
                    "status": status,
                    "detail": detail,
                }
            )

        def _set_workflow(agent_id: str, status: str, detail: str = "") -> None:
            workflow[agent_id] = {"status": status, "detail": detail}

        def _run_agent(agent_id: str, runner: Callable[[], dict[str, Any]]) -> dict[str, Any]:
            started = utc_now()
            t0 = time.perf_counter()
            _set_workflow(agent_id, "running")
            output = runner()
            duration_ms = (time.perf_counter() - t0) * 1000
            completed = utc_now()
            timings[agent_id] = {"started": started, "completed": completed, "duration_ms": duration_ms}
            enriched = enrich_agent_output(
                output,
                agent_id=agent_id,
                started_at=started,
                completed_at=completed,
                duration_ms=duration_ms,
            )
            context[agent_id] = enriched
            return enriched

        # Intake
        intake = _run_agent("IntakeAgent", lambda: self.intake_agent.run(incident_text))
        context["intake"] = intake
        if intake.get("guardrail", {}).get("blocked"):
            _set_workflow("IntakeAgent", "blocked", intake.get("summary", ""))
            _log("IntakeAgent", "blocked", "Intake guardrail triggered")
            return self._blocked_result(
                context, intake, workflow, audit_trail, "intake_guardrail", timings=timings
            )
        _set_workflow("IntakeAgent", "completed", intake.get("summary", ""))
        _log("IntakeAgent", "completed", intake.get("summary", ""))

        # Planner
        planner = _run_agent("PlannerAgent", lambda: self.planner_agent.run(intake))
        context["planner"] = planner
        _set_workflow("PlannerAgent", "completed", planner.get("plan_summary", ""))
        _log("PlannerAgent", "completed", planner.get("plan_summary", ""))

        # Log Analysis
        log_analysis = _run_agent(
            "LogAnalysisAgent", lambda: self.log_agent.run(intake, incident_text)
        )
        context["log_analysis"] = log_analysis
        _set_workflow("LogAnalysisAgent", "completed", log_analysis.get("summary", ""))
        _log("LogAnalysisAgent", "completed", log_analysis.get("summary", ""))

        # Compliance
        compliance = _run_agent(
            "ComplianceAgent", lambda: self.compliance_agent.run(incident_text, intake)
        )
        context["compliance"] = compliance
        if compliance.get("blocked"):
            audit_trail.append(compliance.get("guardrail", {}).get("audit_entry", {}))
            _set_workflow("ComplianceAgent", "blocked", compliance.get("summary", ""))
            _log("ComplianceAgent", "blocked", compliance.get("summary", ""))
            return self._blocked_result(
                context,
                intake,
                workflow,
                audit_trail,
                "compliance_block",
                compliance=compliance,
                planner=planner,
                log_analysis=log_analysis,
                timings=timings,
            )
        _set_workflow("ComplianceAgent", "completed", compliance.get("summary", ""))
        _log("ComplianceAgent", "completed", compliance.get("summary", ""))

        # Root Cause
        rca = _run_agent(
            "RootCauseAgent",
            lambda: self.rca_agent.run(intake, log_analysis, incident_text),
        )
        context["rca"] = rca
        _set_workflow("RootCauseAgent", "completed", rca.get("summary", ""))
        _log("RootCauseAgent", "completed", rca.get("summary", ""))

        # Remediation
        remediation = _run_agent(
            "RemediationAgent",
            lambda: self.remediation_agent.run(intake, rca, compliance),
        )
        context["remediation"] = remediation
        rem_status = remediation.get("status", "completed")
        _set_workflow(
            "RemediationAgent",
            "blocked" if remediation.get("blocked") else "completed",
            remediation.get("summary", ""),
        )
        _log("RemediationAgent", rem_status, remediation.get("summary", ""))

        # Validation (after remediation, before auditor)
        validation = _run_agent(
            "ValidationAgent",
            lambda: self.validation_agent.run(remediation, context),
        )
        context["validation"] = validation
        val_status = validation.get("validation_status", "passed")
        wf_val = "completed" if validation.get("status") != "skipped" else "pending"
        if val_status == "warning":
            wf_val = "completed"
        _set_workflow("ValidationAgent", wf_val, validation.get("summary", ""))
        _log("ValidationAgent", val_status, validation.get("summary", ""))

        # Auditor
        auditor = _run_agent(
            "AuditorAgent",
            lambda: self.auditor_agent.run(
                incident_text=incident_text,
                intake=intake,
                planner=planner,
                log_analysis=log_analysis,
                rca=rca,
                compliance=compliance,
                remediation=remediation,
                validation=validation,
                workflow_status=workflow_status_final(workflow),
                audit_trail=audit_trail,
            ),
        )
        context["auditor"] = auditor
        _set_workflow("AuditorAgent", "completed", "Final report ready")
        _log("AuditorAgent", "completed", "Final report ready")

        return {
            "blocked": False,
            "incident_text": incident_text,
            "intake": intake,
            "planner": planner,
            "log_analysis": log_analysis,
            "rca": rca,
            "compliance": compliance,
            "remediation": remediation,
            "validation": validation,
            "auditor": auditor,
            "workflow_status": workflow_status_final(workflow),
            "audit_trail": audit_trail,
            "llm_provider": self.llm.provider,
            "used_fallback": getattr(self.llm, "last_used_fallback", False),
            "context_keys": list(context.keys()),
        }

    def _blocked_result(
        self,
        context: dict[str, Any],
        intake: dict[str, Any],
        workflow: dict[str, dict[str, Any]],
        audit_trail: list[dict[str, Any]],
        reason: str,
        compliance: dict[str, Any] | None = None,
        planner: dict[str, Any] | None = None,
        log_analysis: dict[str, Any] | None = None,
        timings: dict[str, dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        timings = timings or context.get("timings") or {}

        def _enrich(agent_id: str, data: dict[str, Any]) -> dict[str, Any]:
            t = timings.get(agent_id, {})
            return enrich_agent_output(
                data,
                agent_id=agent_id,
                started_at=t.get("started"),
                completed_at=t.get("completed"),
                duration_ms=t.get("duration_ms"),
            )

        remediation = _enrich(
            "RemediationAgent",
            {
                "agent": "RemediationAgent",
                "status": "skipped",
                "blocked": True,
                "summary": "Remediation not generated — workflow blocked.",
                "actions": [],
            },
        )
        validation = _enrich(
            "ValidationAgent",
            {
                "agent": "ValidationAgent",
                "status": "skipped",
                "validation_status": "skipped",
                "confidence_score": 0.0,
                "requires_approval": False,
                "summary": "Validation skipped — workflow blocked.",
            },
        )
        rca = _enrich(
            "RootCauseAgent",
            {
                "agent": "RootCauseAgent",
                "status": "skipped",
                "summary": "RCA skipped due to early compliance block.",
                "root_cause": "N/A — unsafe request",
                "confidence": 0.0,
            },
        )
        if log_analysis is None:
            log_analysis = {
                "agent": "LogAnalysisAgent",
                "status": "partial",
                "summary": "Limited analysis — workflow stopped early.",
                "anomalies": [],
                "evidence": [],
            }
        log_analysis = _enrich("LogAnalysisAgent", log_analysis)

        if planner is None:
            planner = {
                "agent": "PlannerAgent",
                "status": "pending",
                "plan_summary": "Not executed — workflow halted early.",
                "tasks": [],
            }
        planner = _enrich("PlannerAgent", planner)

        pending_agents = ("RootCauseAgent", "RemediationAgent", "ValidationAgent")
        if reason == "intake_guardrail":
            pending_agents = (
                "PlannerAgent",
                "LogAnalysisAgent",
                "ComplianceAgent",
                "RootCauseAgent",
                "RemediationAgent",
                "ValidationAgent",
            )
        elif reason == "compliance_block":
            pending_agents = ("RootCauseAgent", "RemediationAgent", "ValidationAgent")

        for agent_id in pending_agents:
            if agent_id not in workflow:
                workflow[agent_id] = {"status": "pending", "detail": "Not executed"}

        if isinstance(compliance, dict) and compliance.get("agent"):
            compliance_out = _enrich("ComplianceAgent", compliance)
        else:
            compliance_out = _enrich(
                "ComplianceAgent",
                {
                    "agent": "ComplianceAgent",
                    "blocked": True,
                    "status": "blocked",
                    "summary": str(intake.get("guardrail", {}).get("reason", "Unsafe request")),
                    "policy_violations": intake.get("guardrail", {}).get("matched_phrases", []),
                },
            )

        if "started_at" not in intake:
            intake = _enrich("IntakeAgent", intake)

        auditor = _enrich(
            "AuditorAgent",
            self.auditor_agent.run(
                incident_text="[BLOCKED]",
                intake=intake,
                planner=planner,
                log_analysis=log_analysis,
                rca=rca,
                compliance=compliance_out
                if isinstance(compliance_out, dict) and "agent" in compliance_out
                else {
                    "agent": "ComplianceAgent",
                    "blocked": True,
                    "summary": intake.get("guardrail", {}).get("reason", "Blocked"),
                    "compliance_score": 0.0,
                },
                remediation=remediation,
                validation=validation,
                workflow_status=workflow_status_final(workflow),
                audit_trail=audit_trail,
            ),
        )
        workflow["AuditorAgent"] = {"status": "completed", "detail": "Blocked incident report"}

        return {
            "blocked": True,
            "block_reason": reason,
            "incident_text": "",
            "intake": intake,
            "planner": planner,
            "log_analysis": log_analysis,
            "rca": rca,
            "compliance": compliance_out
            if isinstance(compliance_out, dict) and compliance_out.get("agent")
            else {
                "agent": "ComplianceAgent",
                "blocked": True,
                "status": "blocked",
                "summary": str(intake.get("guardrail", {}).get("reason", "Unsafe request")),
                "policy_violations": intake.get("guardrail", {}).get("matched_phrases", []),
            },
            "remediation": remediation,
            "validation": validation,
            "auditor": auditor,
            "workflow_status": workflow_status_final(workflow),
            "audit_trail": audit_trail,
            "llm_provider": self.llm.provider,
            "used_fallback": getattr(self.llm, "last_used_fallback", False),
        }

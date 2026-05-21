"""Multi-agent package — orchestrator is imported lazily to avoid circular imports."""

from __future__ import annotations

from agents.auditor_agent import AuditorAgent
from agents.compliance_agent import ComplianceAgent
from agents.intake_agent import IntakeAgent
from agents.log_analysis_agent import LogAnalysisAgent
from agents.planner_agent import PlannerAgent
from agents.remediation_agent import RemediationAgent
from agents.root_cause_agent import RootCauseAgent
from agents.validation_agent import ValidationAgent

__all__ = [
    "SentinelOrchestrator",
    "IntakeAgent",
    "PlannerAgent",
    "LogAnalysisAgent",
    "RootCauseAgent",
    "ComplianceAgent",
    "RemediationAgent",
    "ValidationAgent",
    "AuditorAgent",
]


def __getattr__(name: str):
    if name == "SentinelOrchestrator":
        from orchestrator import SentinelOrchestrator

        return SentinelOrchestrator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

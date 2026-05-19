"""AuditorAgent — final audit, risk/confidence scores, executive summary."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class AuditorAgent:
    name = "AuditorAgent"

    def run(
        self,
        incident_text: str,
        intake: dict[str, Any],
        planner: dict[str, Any],
        log_analysis: dict[str, Any],
        rca: dict[str, Any],
        compliance: dict[str, Any],
        remediation: dict[str, Any],
        workflow_status: list[dict[str, Any]],
        audit_trail: list[dict[str, Any]],
    ) -> dict[str, Any]:
        blocked = compliance.get("blocked", False)
        severity = intake.get("severity", "MEDIUM")
        rca_conf = float(rca.get("confidence", 0.5))
        compliance_score = float(compliance.get("compliance_score", 0.0))

        if blocked:
            risk_score = 98
            confidence_score = 15
        else:
            risk_score = self._risk_score(severity, log_analysis, rca_conf)
            confidence_score = self._confidence_score(rca_conf, compliance_score, log_analysis)

        executive_summary = self._executive_summary(
            incident_text, intake, rca, compliance, remediation, blocked
        )

        return {
            "agent": self.name,
            "status": "completed",
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "severity": severity,
            "affected_services": intake.get("affected_services", []),
            "workflow_status": workflow_status,
            "audit_trail": audit_trail,
            "executive_summary": executive_summary,
            "incident_summary": intake.get("summary", ""),
            "rca_summary": rca.get("summary", ""),
            "compliance_summary": compliance.get("summary", ""),
            "remediation_summary": remediation.get("summary", "N/A"),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "final_report_ready": True,
        }

    def _risk_score(
        self, severity: str, log_analysis: dict[str, Any], rca_conf: float
    ) -> int:
        base = {"LOW": 25, "MEDIUM": 45, "HIGH": 72, "CRITICAL": 90}.get(severity, 40)
        anomaly_boost = min(15, len(log_analysis.get("anomalies", [])) * 2)
        conf_adj = int((1 - rca_conf) * 10)
        return min(99, base + anomaly_boost + conf_adj)

    def _confidence_score(
        self, rca_conf: float, compliance_score: float, log_analysis: dict[str, Any]
    ) -> int:
        evidence_boost = min(20, len(log_analysis.get("evidence", [])) * 3)
        score = int(rca_conf * 50 + compliance_score * 30 + evidence_boost)
        return min(99, max(10, score))

    def _executive_summary(
        self,
        incident_text: str,
        intake: dict[str, Any],
        rca: dict[str, Any],
        compliance: dict[str, Any],
        remediation: dict[str, Any],
        blocked: bool,
    ) -> str:
        if blocked:
            return (
                "SentinelOps AI halted automated response due to policy violations or unsafe "
                "operator instructions. Security and compliance teams should review the request. "
                "No remediation was executed."
            )
        services = ", ".join(intake.get("affected_services", ["unknown"]))
        return (
            f"Incident processed for {services} at {intake.get('severity', 'MEDIUM')} severity. "
            f"Root cause: {rca.get('root_cause', 'under investigation')}. "
            f"{remediation.get('summary', '')} "
            "All actions logged for audit; approve flagged steps before production changes."
        )

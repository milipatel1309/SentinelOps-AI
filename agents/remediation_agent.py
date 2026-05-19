"""RemediationAgent — safe remediation recommendations with approval flags."""

from __future__ import annotations

from typing import Any

from utils.llm_client import LLMClient


class RemediationAgent:
    name = "RemediationAgent"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    def run(
        self,
        intake: dict[str, Any],
        rca: dict[str, Any],
        compliance: dict[str, Any],
    ) -> dict[str, Any]:
        if compliance.get("blocked"):
            return {
                "agent": self.name,
                "status": "skipped",
                "blocked": True,
                "reason": "Remediation skipped due to compliance block.",
                "actions": [],
                "summary": "No remediation generated — incident flagged as unsafe.",
            }

        keywords = intake.get("keywords", [])
        severity = intake.get("severity", "MEDIUM")
        actions = self._build_actions(keywords, rca, compliance)
        pending = [a for a in actions if a.get("requires_approval")]

        return {
            "agent": self.name,
            "status": "completed",
            "blocked": False,
            "auto_executed": False,
            "human_approval_required": bool(pending),
            "pending_approval_count": len(pending),
            "actions": actions,
            "rollback_plan": [
                "Capture current deployment revision",
                "Enable feature flag kill-switch if available",
                "Document change ticket before execution",
            ],
            "estimated_mttr_minutes": 25 if severity == "HIGH" else 45,
            "summary": (
                f"Generated {len(actions)} remediation steps "
                f"({len(pending)} require human approval; none auto-executed)."
            ),
        }

    def _build_actions(
        self,
        keywords: list[str],
        rca: dict[str, Any],
        compliance: dict[str, Any],
    ) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = [
            self._action(
                1,
                "Open SEV bridge and notify on-call + security",
                risk="low",
                requires_approval=False,
            ),
            self._action(
                2,
                "Enable enhanced logging and distributed tracing sampling",
                risk="low",
                requires_approval=False,
            ),
        ]

        if "payment" in keywords:
            actions.append(
                self._action(
                    len(actions) + 1,
                    "Scale PaymentAPI replicas and enable circuit breaker to AuthService",
                    risk="medium",
                    requires_approval=False,
                )
            )
        if "database" in keywords:
            actions.append(
                self._action(
                    len(actions) + 1,
                    "Fail over read traffic to replica and throttle heavy queries",
                    risk="high",
                    requires_approval=True,
                )
            )
        if "auth" in keywords or "deployment" in str(rca.get("root_cause", "")).lower():
            actions.append(
                self._action(
                    len(actions) + 1,
                    "Rollback AuthService deployment",
                    risk="medium",
                    requires_approval=True,
                )
            )
        if "privilege" in keywords:
            step = len(actions) + 1
            actions.append(
                self._action(
                    step,
                    "Revoke suspicious service account tokens and force MFA reset",
                    risk="high",
                    requires_approval=True,
                )
            )
            actions.append(
                self._action(
                    step + 1,
                    "Isolate affected IAM principals pending forensic review",
                    risk="high",
                    requires_approval=True,
                )
            )

        for item in compliance.get("requires_approval", []):
            actions.append(
                self._action(
                    len(actions) + 1,
                    f"Manual approval required for: {item}",
                    risk="high",
                    requires_approval=True,
                )
            )

        if len(actions) < 4:
            actions.append(
                self._action(
                    len(actions) + 1,
                    "Validate service health dashboards and close incident after 30m stable metrics",
                    risk="low",
                    requires_approval=False,
                )
            )

        return actions

    @staticmethod
    def _action(
        step: int,
        action: str,
        *,
        risk: str,
        requires_approval: bool,
    ) -> dict[str, Any]:
        return {
            "step": step,
            "action": action,
            "risk": risk,
            "requires_approval": requires_approval,
            "human_approval_required": requires_approval,
            "execution_status": (
                "pending_human_approval" if requires_approval else "recommended_not_executed"
            ),
            "auto_executed": False,
        }

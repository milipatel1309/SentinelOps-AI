"""RootCauseAgent — infer root cause from log evidence."""

from __future__ import annotations

from typing import Any

from utils.llm_client import LLMClient


class RootCauseAgent:
    name = "RootCauseAgent"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    def run(
        self,
        intake: dict[str, Any],
        log_analysis: dict[str, Any],
        incident_text: str,
    ) -> dict[str, Any]:
        anomalies = log_analysis.get("anomalies", [])
        keywords = intake.get("keywords", [])
        text = (incident_text or "").lower()

        rca = self._rule_based_rca(keywords, text, anomalies)
        mock = {
            "agent": self.name,
            "status": "completed",
            "root_cause": rca["root_cause"],
            "contributing_factors": rca["contributing_factors"],
            "confidence": rca["confidence"],
            "evidence_refs": log_analysis.get("evidence", [])[:5],
            "summary": rca["summary"],
        }

        if self.llm.provider != "mock":
            prompt = f"Incident: {incident_text}\nEvidence: {log_analysis.get('evidence')}"
            enriched = self.llm.complete(
                system_prompt="SRE root cause analyst. Return JSON with root_cause, contributing_factors, confidence, summary.",
                user_prompt=prompt,
                mock_response=mock,
            )
            for key in ("root_cause", "contributing_factors", "confidence", "summary"):
                if key in enriched:
                    mock[key] = enriched[key]

        return mock

    def _rule_based_rca(
        self, keywords: list[str], text: str, anomalies: list[dict]
    ) -> dict[str, Any]:
        if "privilege" in keywords or "escalat" in text:
            return {
                "root_cause": "Suspicious privilege escalation via compromised service account",
                "contributing_factors": [
                    "Repeated failed logins followed by admin role assignment",
                    "Anomalous IP geolocation on IAMService",
                ],
                "confidence": 0.82,
                "summary": "Security telemetry indicates credential abuse leading to privilege escalation.",
            }
        if "database" in keywords:
            return {
                "root_cause": "Database connection pool exhaustion under CPU saturation",
                "contributing_factors": [
                    "Sustained CPU > 90% on DatabaseCluster",
                    "Checkout timeouts correlated with query latency",
                ],
                "confidence": 0.88,
                "summary": "Performance degradation on primary DB cluster cascaded to checkout failures.",
            }
        if "payment" in keywords:
            return {
                "root_cause": "PaymentAPI latency spike coupled with AuthService login failures",
                "contributing_factors": [
                    "Elevated p99 latency on PaymentAPI",
                    "Auth token validation errors during peak traffic",
                ],
                "confidence": 0.79,
                "summary": "Cross-service dependency failure between payments and authentication.",
            }
        if "deployment" in text or "deploy" in text:
            return {
                "root_cause": "Regression introduced in AuthService deployment v2.14.3",
                "contributing_factors": [
                    "Error rate spike post-deploy window",
                    "Health check failures on new pods",
                ],
                "confidence": 0.91,
                "summary": "Post-deployment regression caused authentication outage.",
            }
        if anomalies:
            return {
                "root_cause": "Correlated infrastructure anomaly across monitored services",
                "contributing_factors": [f"Detected {len(anomalies)} telemetry anomalies"],
                "confidence": 0.65,
                "summary": "Insufficient single-domain signal; multi-signal correlation applied.",
            }
        return {
            "root_cause": "No definitive root cause — monitoring gaps suspected",
            "contributing_factors": ["Limited matching telemetry for incident scope"],
            "confidence": 0.45,
            "summary": "Recommend expanded log sampling and trace correlation.",
        }

"""IntakeAgent — parse incident description into structured intake."""

from __future__ import annotations

from typing import Any

from utils.guardrails import check_guardrails
from utils.llm_client import LLMClient


class IntakeAgent:
    name = "IntakeAgent"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    def run(self, incident_text: str) -> dict[str, Any]:
        guard = check_guardrails(incident_text, source="intake")
        keywords = self.llm.extract_keywords(incident_text)
        text_lower = (incident_text or "").lower()

        services = self._infer_services(text_lower, keywords)
        severity = self._infer_severity(text_lower, keywords)
        intent = self._infer_intent(text_lower, keywords)
        entities = self._extract_entities(text_lower, services)

        mock = {
            "agent": self.name,
            "status": "completed",
            "intent": intent,
            "entities": entities,
            "affected_services": services,
            "severity": severity,
            "keywords": keywords,
            "guardrail": guard.to_dict(),
            "summary": (
                f"Incident classified as {intent} affecting {', '.join(services)} "
                f"with {severity} severity."
            ),
        }

        if self.llm.provider != "mock":
            enriched = self.llm.complete(
                system_prompt="You are an SRE intake agent. Return JSON with intent, entities, affected_services, severity, summary.",
                user_prompt=incident_text,
                mock_response=mock,
            )
            mock.update({k: enriched.get(k, v) for k, v in mock.items() if k in enriched})

        return mock

    def _infer_services(self, text: str, keywords: list[str]) -> list[str]:
        mapping = {
            "payment": "PaymentAPI",
            "auth": "AuthService",
            "database": "DatabaseCluster",
            "deployment": "DeploymentPipeline",
            "privilege": "IAMService",
            "security": "SecurityGateway",
        }
        services = [mapping[k] for k in keywords if k in mapping]
        if "paymentapi" in text or "payment api" in text:
            services.append("PaymentAPI")
        if "auth" in text:
            services.append("AuthService")
        if "database" in text or "db " in text:
            services.append("DatabaseCluster")
        return list(dict.fromkeys(services)) or ["CorePlatform"]

    def _infer_severity(self, text: str, keywords: list[str]) -> str:
        if any(p in text for p in ("delete production", "ignore polic", "bypass")):
            return "CRITICAL"
        if "outage" in text or "failed" in text or "spike" in text:
            return "HIGH"
        if "latency" in text or "suspicious" in text:
            return "MEDIUM"
        return "LOW"

    def _infer_intent(self, text: str, keywords: list[str]) -> str:
        if "privilege" in keywords or "escalat" in text:
            return "security_investigation"
        if "database" in keywords:
            return "performance_degradation"
        if "payment" in keywords:
            return "service_degradation"
        if "auth" in keywords:
            return "authentication_failure"
        if "deployment" in text:
            return "post_deployment_incident"
        return "general_incident"

    def _extract_entities(self, text: str, services: list[str]) -> list[str]:
        entities = list(services)
        for token in ("checkout", "login", "cpu", "deployment", "admin"):
            if token in text:
                entities.append(token)
        return list(dict.fromkeys(entities))

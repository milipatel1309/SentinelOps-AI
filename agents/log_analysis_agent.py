"""LogAnalysisAgent — analyze mock CSV logs for anomalies."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from utils.llm_client import LLMClient

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class LogAnalysisAgent:
    name = "LogAnalysisAgent"

    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm or LLMClient()

    def run(self, intake: dict[str, Any], incident_text: str) -> dict[str, Any]:
        cloud_path = DATA_DIR / "cloud_logs.csv"
        sec_path = DATA_DIR / "security_events.csv"

        cloud_df = pd.read_csv(cloud_path)
        sec_df = pd.read_csv(sec_path)

        services = intake.get("affected_services", [])
        keywords = intake.get("keywords", self.llm.extract_keywords(incident_text))

        cloud_filtered = self._filter_cloud(cloud_df, services, keywords)
        sec_filtered = self._filter_security(sec_df, keywords, incident_text)

        anomalies = self._detect_anomalies(cloud_filtered, sec_filtered)
        evidence = self._build_evidence(cloud_filtered, sec_filtered, anomalies)

        return {
            "agent": self.name,
            "status": "completed",
            "cloud_log_rows_analyzed": len(cloud_df),
            "security_events_analyzed": len(sec_df),
            "relevant_cloud_rows": len(cloud_filtered),
            "relevant_security_events": len(sec_filtered),
            "anomalies": anomalies,
            "evidence": evidence,
            "top_metrics": self._top_metrics(cloud_filtered),
            "summary": f"Identified {len(anomalies)} anomalies across {len(services) or 1} service scope.",
        }

    def _filter_cloud(
        self, df: pd.DataFrame, services: list[str], keywords: list[str]
    ) -> pd.DataFrame:
        mask = pd.Series([False] * len(df))
        for svc in services:
            mask |= df["service"].str.contains(svc.split("Service")[0][:4], case=False, na=False)
        if "payment" in keywords:
            mask |= df["service"].str.contains("Payment", case=False, na=False)
        if "auth" in keywords:
            mask |= df["service"].str.contains("Auth", case=False, na=False)
        if "database" in keywords:
            mask |= df["service"].str.contains("Database", case=False, na=False)
        filtered = df[mask] if mask.any() else df.head(12)
        warn = filtered[filtered["status"].isin(["WARN", "CRITICAL", "ERROR"])]
        return warn if not warn.empty else filtered.head(8)

    def _filter_security(
        self, df: pd.DataFrame, keywords: list[str], text: str
    ) -> pd.DataFrame:
        text_l = text.lower()
        mask = df["severity"].isin(["HIGH", "CRITICAL"])
        if "privilege" in keywords or "escalat" in text_l:
            mask |= df["event_type"].str.contains("privilege|escalat|admin", case=False, na=False)
        if "auth" in keywords or "login" in text_l:
            mask |= df["event_type"].str.contains("login|auth|failed", case=False, na=False)
        filtered = df[mask] if mask.any() else df.head(6)
        return filtered

    def _detect_anomalies(
        self, cloud: pd.DataFrame, security: pd.DataFrame
    ) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        for _, row in cloud.iterrows():
            if row["status"] in ("WARN", "CRITICAL", "ERROR"):
                anomalies.append(
                    {
                        "type": "metric_threshold",
                        "service": row["service"],
                        "metric": row["metric"],
                        "value": row["value"],
                        "status": row["status"],
                        "timestamp": row["timestamp"],
                    }
                )
        for _, row in security.iterrows():
            if row["severity"] in ("HIGH", "CRITICAL"):
                anomalies.append(
                    {
                        "type": "security_event",
                        "event_type": row["event_type"],
                        "user": row["user"],
                        "ip": row["ip"],
                        "severity": row["severity"],
                        "timestamp": row["timestamp"],
                    }
                )
        return anomalies[:15]

    def _build_evidence(
        self,
        cloud: pd.DataFrame,
        security: pd.DataFrame,
        anomalies: list[dict[str, Any]],
    ) -> list[str]:
        evidence = []
        for _, row in cloud.head(5).iterrows():
            evidence.append(
                f"[{row['timestamp']}] {row['service']} {row['metric']}={row['value']} ({row['status']})"
            )
        for _, row in security.head(3).iterrows():
            evidence.append(
                f"[{row['timestamp']}] SEC {row['event_type']} user={row['user']} ip={row['ip']}"
            )
        if not evidence and anomalies:
            evidence.append(f"Correlated {len(anomalies)} anomaly signals from telemetry.")
        return evidence

    def _top_metrics(self, cloud: pd.DataFrame) -> list[dict[str, Any]]:
        if cloud.empty:
            return []
        return (
            cloud.groupby(["service", "metric"], as_index=False)["value"]
            .max()
            .head(5)
            .to_dict(orient="records")
        )

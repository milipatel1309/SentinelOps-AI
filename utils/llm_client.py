"""LLM client with Groq/OpenAI support, retries, and deterministic mock fallback."""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any

from dotenv import load_dotenv

# Local: .env via load_dotenv(). Azure App Service / Cloud Run: env vars → os.getenv().
load_dotenv()

MAX_LLM_RETRIES = 2
_RETRY_BACKOFF_SEC = 0.4


def get_llm_status() -> dict[str, str]:
    """Return active LLM mode and human-readable label for UI/diagnostics."""
    groq = bool((os.getenv("GROQ_API_KEY") or "").strip())
    openai = bool((os.getenv("OPENAI_API_KEY") or "").strip())
    if groq:
        return {"mode": "groq", "label": "Groq connected"}
    if openai:
        return {"mode": "openai", "label": "OpenAI connected"}
    return {"mode": "mock", "label": "Mock mode active"}


class LLMClient:
    """Unified LLM interface: Groq → OpenAI → rule-based mock with retries."""

    def __init__(self) -> None:
        self.groq_key = (os.getenv("GROQ_API_KEY") or "").strip() or None
        self.openai_key = (os.getenv("OPENAI_API_KEY") or "").strip() or None
        self._groq_client = None
        self._openai_client = None
        self.provider = self._detect_provider()
        self.last_used_fallback = self.provider == "mock"

    def _detect_provider(self) -> str:
        return get_llm_status()["mode"]

    def _get_groq(self):
        if self._groq_client is None and self.groq_key:
            try:
                from groq import Groq

                self._groq_client = Groq(api_key=self.groq_key)
            except Exception:
                self._groq_client = False
        return self._groq_client

    def _get_openai(self):
        if self._openai_client is None and self.openai_key:
            try:
                from openai import OpenAI

                self._openai_client = OpenAI(api_key=self.openai_key)
            except Exception:
                self._openai_client = False
        return self._openai_client

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        mock_response: dict[str, Any] | None = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """Return parsed JSON dict from LLM or deterministic mock fallback."""
        last_error: Exception | None = None

        for attempt in range(MAX_LLM_RETRIES + 1):
            try:
                if self.provider == "groq":
                    result = self._call_groq(system_prompt, user_prompt, temperature)
                    if result is not None:
                        self.last_used_fallback = False
                        result["used_fallback"] = False
                        return result
                if self.provider in ("groq", "openai") and self.openai_key:
                    result = self._call_openai(system_prompt, user_prompt, temperature)
                    if result is not None:
                        self.last_used_fallback = False
                        result["used_fallback"] = False
                        return result
            except Exception as exc:
                last_error = exc
                if attempt < MAX_LLM_RETRIES:
                    time.sleep(_RETRY_BACKOFF_SEC * (attempt + 1))
                    continue
                break

            if attempt < MAX_LLM_RETRIES and self.provider != "mock":
                time.sleep(_RETRY_BACKOFF_SEC * (attempt + 1))

        self.last_used_fallback = True
        fallback = dict(mock_response or {"raw": (user_prompt or "")[:500]})
        fallback["used_fallback"] = True
        if last_error is not None:
            fallback["fallback_reason"] = type(last_error).__name__
        return fallback

    def _call_groq(
        self, system_prompt: str, user_prompt: str, temperature: float
    ) -> dict[str, Any] | None:
        client = self._get_groq()
        if not client:
            return None
        resp = client.chat.completions.create(
            model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or "{}"
        return json.loads(content)

    def _call_openai(
        self, system_prompt: str, user_prompt: str, temperature: float
    ) -> dict[str, Any] | None:
        client = self._get_openai()
        if not client:
            return None
        resp = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or "{}"
        return json.loads(content)

    @staticmethod
    def extract_keywords(text: str) -> list[str]:
        text = (text or "").lower()
        keywords = []
        patterns = {
            "payment": r"payment|checkout|latency|transaction",
            "auth": r"auth|login|sso|credential",
            "database": r"database|db|cpu|query|postgres",
            "deployment": r"deploy|rollout|release|canary",
            "privilege": r"privilege|escalat|admin|sudo",
            "security": r"suspicious|breach|malware|exfil",
        }
        for name, pat in patterns.items():
            if re.search(pat, text):
                keywords.append(name)
        return keywords or ["general"]

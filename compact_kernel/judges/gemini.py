"""Google Gemini API judge (generateContent, JSON response mode)."""

from __future__ import annotations

from urllib.parse import quote

from .llm import LLMJudge


class GeminiJudge(LLMJudge):
    default_auth_header = "x-goog-api-key"

    def __init__(self, *a, **kw):
        kw.setdefault("base_url", "https://generativelanguage.googleapis.com")
        super().__init__(*a, **kw)

    def _request(self, system: str, user: str):
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"},
        }
        return f"{self.base_url}/v1beta/models/{quote(self.model, safe='')}:generateContent", body

    def _extract_text(self, resp: dict) -> str:
        parts = resp["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts)

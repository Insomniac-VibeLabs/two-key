"""Local Ollama judge (native /api/chat with format=json). No auth by default."""

from __future__ import annotations

from .llm import LLMJudge


class OllamaJudge(LLMJudge):
    default_auth_header = "none"

    def __init__(self, *a, **kw):
        kw.setdefault("base_url", "http://localhost:11434")
        super().__init__(*a, **kw)

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
        return f"{self.base_url}/api/chat", body

    def _extract_text(self, resp: dict) -> str:
        return resp["message"]["content"]

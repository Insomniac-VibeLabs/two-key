"""Anthropic Messages API judge (POST {base_url}/v1/messages)."""

from __future__ import annotations

from .llm import LLMJudge

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicJudge(LLMJudge):
    default_auth_header = "x-api-key"

    def __init__(self, *a, max_tokens: int = 300, **kw):
        kw.setdefault("base_url", "https://api.anthropic.com")
        super().__init__(*a, **kw)
        self.max_tokens = max_tokens

    def _auth_headers(self) -> dict:
        h = super()._auth_headers()
        h["anthropic-version"] = ANTHROPIC_VERSION
        return h

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        return f"{self.base_url}/v1/messages", body

    def _extract_text(self, resp: dict) -> str:
        blocks = resp["content"]
        return "".join(b["text"] for b in blocks if b.get("type") == "text")

"""OpenAI-compatible Chat Completions judge.

Covers OpenAI, xAI, and local servers that speak the same API (Ollama's
/v1 endpoint, llama.cpp server, vLLM, LM Studio, ...). Set ``base_url``
to the API root that serves ``/chat/completions``.
"""

from __future__ import annotations

from .llm import LLMJudge


class OpenAICompatibleJudge(LLMJudge):
    default_auth_header = "bearer"

    def __init__(self, *a, json_mode: bool = True, max_tokens: int = 300, **kw):
        super().__init__(*a, **kw)
        self.json_mode, self.max_tokens = json_mode, max_tokens

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        return f"{self.base_url}/chat/completions", body

    def _extract_text(self, resp: dict) -> str:
        return resp["choices"][0]["message"]["content"]

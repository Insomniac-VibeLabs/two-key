"""Local Ollama judge (native /api/chat with format=json). No auth by default.

``local_weights`` defaults to True: an Ollama judge is assumed to run a local
weight file (PRIOR_ART.md §4 (iii), "at least one local weight file"). This is a
declaration, not an attestation; set ``local_weights: false`` for remote or
cloud-hosted Ollama models. See DESIGN_OPTIONS.md §7.
"""

from __future__ import annotations

from .llm import LLMJudge


class OllamaJudge(LLMJudge):
    default_auth_header = "none"
    local_weights = True

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

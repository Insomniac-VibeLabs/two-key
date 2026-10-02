"""Anthropic Messages API judge (POST {base_url}/v1/messages).

The static system prompt and the principal's constitution are marked with an
ephemeral cache breakpoint. The untrusted action record and proposal sit after
that breakpoint, so they are not part of the reusable prefix. Cache entries
are isolated per Anthropic organization. A short constitution simply misses
the cache; Anthropic does not error. A 400 strips the breakpoints and retries
once. No beta header: current Messages API accepts cache_control without one,
and an unknown beta value can 400.
"""

from __future__ import annotations

from .llm import LLMJudge

ANTHROPIC_VERSION = "2023-06-01"
_CACHE = {"type": "ephemeral"}
_CONSTITUTION_END = "</principal_constitution>\n\n"


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

    def _content(self, user: str) -> list:
        if _CONSTITUTION_END in user:
            trusted, rest = user.split(_CONSTITUTION_END, 1)
            trusted += _CONSTITUTION_END
        else:
            trusted, rest = "", user
        blocks = []
        if trusted:
            blocks.append({"type": "text", "text": trusted, "cache_control": dict(_CACHE)})
        if rest:
            blocks.append({"type": "text", "text": rest})
        return blocks or [{"type": "text", "text": user}]

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "system": [{"type": "text", "text": system, "cache_control": dict(_CACHE)}],
            "messages": [{"role": "user", "content": self._content(user)}],
        }
        return f"{self.base_url}/v1/messages", body

    def _deoptimize(self, body: dict) -> dict | None:
        def strip(block):
            if not isinstance(block, dict) or "cache_control" not in block:
                return block
            return {k: v for k, v in block.items() if k != "cache_control"}

        system = body.get("system")
        messages = body.get("messages") or []
        if not isinstance(system, list) and not any(
                isinstance(b, dict) and "cache_control" in b
                for m in messages for b in (m.get("content") if isinstance(m.get("content"), list) else [])):
            return None
        out = dict(body)
        if isinstance(system, list):
            out["system"] = [strip(b) for b in system]
        out["messages"] = []
        for m in messages:
            content = m.get("content")
            out["messages"].append({**m, "content": [strip(b) for b in content]} if isinstance(content, list) else m)
        return out

    def _extract_text(self, resp: dict) -> str:
        blocks = resp["content"]
        return "".join(b["text"] for b in blocks if b.get("type") == "text")

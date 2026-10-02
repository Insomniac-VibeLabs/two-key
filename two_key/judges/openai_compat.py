"""OpenAI-compatible Chat Completions judge.

Covers OpenAI, xAI, and local servers that speak the same API (Ollama's
/v1 endpoint, llama.cpp server, vLLM, LM Studio, ...). Set ``base_url``
to the API root that serves ``/chat/completions``.

Cloud OpenAI and xAI get a strict ballot schema, and xAI gets
``reasoning_effort: low``, because those hosts accept both and a 300-token
ballot does not need the provider default (high) reasoning budget. A 400
falls back once to ``json_object`` with those knobs removed. The local
parser is still the authority. Other hosts stay on ``json_object`` so a
local server that does not implement structured outputs is not broken.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .llm import LLMJudge

_CLOUD_SCHEMA_HOSTS = {"api.openai.com", "api.x.ai"}


def ballot_schema(*, echo: bool) -> dict:
    props = {
        "consistent": {"type": "boolean"},
        "confidence": {"type": "number"},
        "rationale": {"type": "string"},
    }
    required = ["consistent", "confidence", "rationale"]
    if echo:
        props["action_hash"] = {"type": "string"}
        props["constitution_hash"] = {"type": "string"}
        required.extend(("action_hash", "constitution_hash"))
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


class OpenAICompatibleJudge(LLMJudge):
    default_auth_header = "bearer"

    def __init__(self, *a, json_mode: bool = True, max_tokens: int = 300,
                 response_format: str | None = None, reasoning_effort: str | None = None, **kw):
        super().__init__(*a, **kw)
        self.json_mode, self.max_tokens = json_mode, max_tokens
        if response_format not in (None, "auto", "json_object", "json_schema", "none"):
            raise ValueError(f"response_format must be auto, json_object, json_schema, or none, got {response_format!r}")
        if reasoning_effort not in (None, "low", "medium", "high", "xhigh"):
            raise ValueError(f"reasoning_effort must be low, medium, high, or xhigh, got {reasoning_effort!r}")
        self.response_format = response_format or "auto"
        self.reasoning_effort = reasoning_effort

    def _host(self) -> str:
        return (urlparse(self.base_url).hostname or "").lower()

    def _format(self) -> str:
        if not self.json_mode or self.response_format == "none":
            return "none"
        if self.response_format == "auto":
            # A ballot MAC is appended by the model, outside a closed schema.
            if self.ballot_key or self.ballot_key_env:
                return "json_object"
            return "json_schema" if self._host() in _CLOUD_SCHEMA_HOSTS else "json_object"
        if self.response_format == "json_schema" and (self.ballot_key or self.ballot_key_env):
            return "json_object"
        return self.response_format

    def _request(self, system: str, user: str):
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }
        fmt = self._format()
        if fmt == "json_schema":
            body["response_format"] = {"type": "json_schema", "json_schema": {
                "name": "two_key_ballot", "strict": True, "schema": ballot_schema(echo=self.echo_binding)}}
        elif fmt == "json_object":
            body["response_format"] = {"type": "json_object"}
        host = self._host()
        effort = self.reasoning_effort if self.reasoning_effort is not None else ("low" if host == "api.x.ai" else None)
        if effort:
            body["reasoning_effort"] = effort
        if host == "api.openai.com":
            body["store"] = False
        return f"{self.base_url}/chat/completions", body

    def _deoptimize(self, body: dict) -> dict | None:
        optional = ("reasoning_effort", "store", "prompt_cache_key")
        fmt = body.get("response_format") or {}
        if not any(k in body for k in optional) and fmt.get("type") != "json_schema":
            return None
        out = {k: v for k, v in body.items() if k not in optional}
        if fmt.get("type") == "json_schema" and self.json_mode:
            out["response_format"] = {"type": "json_object"}
        elif fmt.get("type") == "json_schema":
            out.pop("response_format", None)
        return out

    def _extract_text(self, resp: dict) -> str:
        return resp["choices"][0]["message"]["content"]

"""Google Gemini API judge (generateContent, JSON response mode).

responseSchema asks Gemini to emit the ballot shape. The local parser still
accepts or abstains. A 400 drops the schema and retries once with JSON mime
type only, for models that reject responseSchema.
"""

from __future__ import annotations

from urllib.parse import quote

from .llm import LLMJudge


def _schema(*, echo: bool) -> dict:
    props = {
        "consistent": {"type": "BOOLEAN"},
        "confidence": {"type": "NUMBER"},
        "rationale": {"type": "STRING"},
    }
    required = ["consistent", "confidence", "rationale"]
    if echo:
        props["action_hash"] = {"type": "STRING"}
        props["constitution_hash"] = {"type": "STRING"}
        required.extend(("action_hash", "constitution_hash"))
    return {"type": "OBJECT", "properties": props, "required": required}


class GeminiJudge(LLMJudge):
    default_auth_header = "x-goog-api-key"

    def __init__(self, *a, **kw):
        kw.setdefault("base_url", "https://generativelanguage.googleapis.com")
        super().__init__(*a, **kw)

    def _request(self, system: str, user: str):
        cfg = {"temperature": 0, "responseMimeType": "application/json"}
        if not (self.ballot_key or self.ballot_key_env):
            cfg["responseSchema"] = _schema(echo=self.echo_binding)
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": cfg,
        }
        return f"{self.base_url}/v1beta/models/{quote(self.model, safe='')}:generateContent", body

    def _deoptimize(self, body: dict) -> dict | None:
        cfg = dict(body.get("generationConfig") or {})
        if "responseSchema" not in cfg:
            return None
        cfg.pop("responseSchema", None)
        return {**body, "generationConfig": cfg}

    def _extract_text(self, resp: dict) -> str:
        parts = resp["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts)

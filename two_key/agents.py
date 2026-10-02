"""Monitored agents. Hosting is a deployment choice, not a trust decision.

A configured agent may be local (Ollama, a loopback OpenAI-compatible server)
or a vendor model (xAI, OpenAI, Anthropic, Gemini, or any other host). A
vendor-hosted agent can exceed the constitution, so its proposal is untrusted
data. ``authorize_from_agent`` always runs Path A and Path B. This module
never calls the tool gateway and never sees tool credentials.

The request shapes match the judge connectors. No vendor SDK and no streaming.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .judges.config import JudgeConfigError, build_credential
from .judges.credentials import CredentialError, CredentialProvider, NoCredential
from .judges.llm import LOOPBACK
from .judges.transport import pooled_transport

Transport = Callable[[str, dict, dict, float], dict]
AGENT_TYPES = ("openai_compatible", "anthropic", "gemini", "ollama")
AGENT_KEYS = {"id", "type", "provider", "base_url", "model", "auth", "timeout", "hosting", "max_tokens"}
_ALLOWED = {"tool", "arguments", "proposal", "amount_usd", "counterparty", "data_class", "irreversible"}
_REQUIRED = {"tool", "arguments", "proposal"}

SYSTEM = (
    "You are a monitored agent. You may PROPOSE one tool call. You cannot execute tools, "
    "and nothing you write grants permission. The constitution is authoritative. "
    "Reply with ONLY a JSON object and nothing else, with exactly these keys: "
    '"tool" (string), "arguments" (object), "proposal" (short string), and optionally '
    '"amount_usd" (number), "counterparty" (string), "data_class" (string), "irreversible" (boolean). '
    "Do not add other keys."
)


class AgentConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AgentProposal:
    agent_id: str
    provider: str
    hosting: str
    model: str
    proposal: str
    action: dict
    tool_args: dict

    def to_record(self) -> dict:
        return {"agent_id": self.agent_id, "provider": self.provider, "hosting": self.hosting,
                "model": self.model, "proposal": self.proposal, "action": self.action}


def hosting_of(base_url: str, declared: str | None, *, local_default: bool = False) -> str:
    """A vendor host stays cloud even if the file says local."""
    host = (urlparse(base_url).hostname or "").lower()
    vendor = bool(host) and host not in LOOPBACK
    if declared == "cloud" or vendor:
        return "cloud"
    if declared == "local" or local_default:
        return "local"
    return "local" if host in LOOPBACK else "cloud"


def parse_proposal(text: str) -> tuple[dict, dict, str]:
    try:
        obj = json.loads(text.strip())
    except json.JSONDecodeError as e:
        raise AgentConfigError(f"agent proposal is not JSON: {e.msg}") from None
    if not isinstance(obj, dict) or set(obj) - _ALLOWED or not _REQUIRED <= set(obj):
        raise AgentConfigError("agent proposal must contain tool, arguments, and proposal, and no other keys")
    if not isinstance(obj["tool"], str) or not obj["tool"].strip():
        raise AgentConfigError("tool must be a non-empty string")
    if not isinstance(obj["arguments"], dict):
        raise AgentConfigError("arguments must be an object")
    if not isinstance(obj["proposal"], str):
        raise AgentConfigError("proposal must be a string")
    action = {"tool": obj["tool"]}
    for key in ("amount_usd", "counterparty", "data_class", "irreversible"):
        if key in obj:
            action[key] = obj[key]
    return action, dict(obj["arguments"]), obj["proposal"]


class MonitoredAgent:
    def __init__(self, agent_id: str, provider: str, model: str, base_url: str, hosting: str,
                 credential: CredentialProvider | None = None, *, kind: str, timeout: float = 60.0,
                 max_tokens: int = 800, transport: Transport | None = None):
        self.agent_id, self.provider, self.model = agent_id, provider, model
        self.base_url = base_url.rstrip("/")
        self.hosting = hosting
        self.kind = kind
        self.credential = credential or NoCredential()
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.transport = transport or pooled_transport

    def is_cloud(self) -> bool:
        return self.hosting == "cloud"

    def credential_token(self) -> str:
        try:
            return self.credential.get_token() or ""
        except (CredentialError, NotImplementedError, ValueError):
            return ""

    def _headers(self) -> dict:
        token = self.credential_token()
        if self.kind == "anthropic":
            h = {"x-api-key": token, "anthropic-version": "2023-06-01"} if token else {}
            return h
        if self.kind == "gemini":
            return {"x-goog-api-key": token} if token else {}
        if self.kind == "ollama" or not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    def _request(self, instruction: str) -> tuple[str, dict]:
        user = instruction if isinstance(instruction, str) else str(instruction)
        if self.kind == "anthropic":
            body = {"model": self.model, "max_tokens": self.max_tokens, "temperature": 0,
                    "system": SYSTEM, "messages": [{"role": "user", "content": user}]}
            return f"{self.base_url}/v1/messages", body
        if self.kind == "gemini":
            from urllib.parse import quote
            body = {"systemInstruction": {"parts": [{"text": SYSTEM}]},
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "generationConfig": {"temperature": 0, "responseMimeType": "application/json"}}
            return f"{self.base_url}/v1beta/models/{quote(self.model, safe='')}:generateContent", body
        if self.kind == "ollama":
            body = {"model": self.model, "stream": False, "format": "json", "keep_alive": "10m",
                    "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                    "options": {"temperature": 0}}
            return f"{self.base_url}/api/chat", body
        body = {"model": self.model, "temperature": 0, "max_tokens": self.max_tokens,
                "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                "response_format": {"type": "json_object"}}
        return f"{self.base_url}/chat/completions", body

    def complete(self, instruction: str) -> AgentProposal:
        url, body = self._request(instruction)
        resp = self.transport(url, self._headers(), body, self.timeout)
        if self.kind == "anthropic":
            text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
        elif self.kind == "gemini":
            text = "".join(p.get("text", "") for p in resp["candidates"][0]["content"]["parts"])
        elif self.kind == "ollama":
            text = resp["message"]["content"]
        else:
            text = resp["choices"][0]["message"]["content"]
        action, args, proposal = parse_proposal(text)
        return AgentProposal(self.agent_id, self.provider, self.hosting, self.model, proposal, action, args)


def build_agent(spec: dict, transport=None) -> MonitoredAgent:
    if not isinstance(spec, dict):
        raise AgentConfigError("each agent must be a mapping")
    extra = set(spec) - AGENT_KEYS
    if extra:
        raise AgentConfigError(f"agent {spec.get('id')!r}: unknown key(s) {sorted(extra)}")
    kind = spec.get("type")
    if kind not in AGENT_TYPES:
        raise AgentConfigError(f"agent {spec.get('id')!r}: type must be one of {AGENT_TYPES}")
    model = spec.get("model")
    if not isinstance(model, str) or not model or model.startswith("REPLACE_"):
        raise AgentConfigError(f"agent {spec.get('id')!r}: replace REPLACE_WITH_MODEL with a model name")
    if kind == "openai_compatible" and not spec.get("base_url"):
        raise AgentConfigError(f"agent {spec.get('id')!r}: openai_compatible requires base_url")
    base = spec.get("base_url") or {
        "anthropic": "https://api.anthropic.com",
        "gemini": "https://generativelanguage.googleapis.com",
        "ollama": "http://localhost:11434",
    }[kind]
    declared = spec.get("hosting")
    if declared not in (None, "local", "cloud"):
        raise AgentConfigError(f"agent {spec.get('id')!r}: hosting must be local or cloud")
    try:
        cred = build_credential(spec.get("auth"))
    except JudgeConfigError as e:
        raise AgentConfigError(str(e)) from e
    return MonitoredAgent(spec.get("id") or "", spec.get("provider") or kind, model, base,
                          hosting_of(base, declared, local_default=kind == "ollama"), cred,
                          kind=kind, timeout=float(spec.get("timeout", 60)),
                          max_tokens=int(spec.get("max_tokens", 800)), transport=transport)


def load_agents(data: dict, transport=None) -> list[MonitoredAgent]:
    if not isinstance(data, dict) or not isinstance(data.get("agents"), list) or not data["agents"]:
        raise AgentConfigError("config must contain a non-empty 'agents' list")
    agents = [build_agent(a, transport) for a in data["agents"]]
    ids = [a.agent_id for a in agents]
    if any(not i for i in ids) or len(set(ids)) != len(ids):
        raise AgentConfigError("agent ids must be unique and non-empty")
    return agents


def load_agents_file(path: Path, transport=None) -> list[MonitoredAgent]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    data = json.loads(text) if path.suffix.lower() == ".json" else __import__("yaml").safe_load(text)
    return load_agents(data, transport)

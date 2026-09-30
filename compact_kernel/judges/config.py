"""Load the principal's Path B judge list from judges.yaml (or .json).

Format (see examples/judges.yaml):

    quorum:
      required_yes: 2          # k-of-n
      min_responding: 2        # spec 5.4 "K"
      min_distinct_providers: 1
      # PRIOR_ART.md §4 (iii) options (defaults shown; see quorum.QuorumPolicy):
      min_vendors: 1           # >= 2 in the §4 reference profile
      min_local_judges: 0      # >= 1 in the §4 reference profile
      heterogeneity_scope: selection   # selection | responding
      judge_inputs: record_only        # record_only | record_and_proposal
      ballot_binding: stamp            # stamp | echo
      require_path_a_first: false
    judges:
      - id: grok
        type: openai_compatible   # openai_compatible | anthropic | gemini | ollama
        provider: xai             # free-form label, used by min_distinct_providers
        base_url: https://api.x.ai/v1
        model: REPLACE_WITH_MODEL
        auth: {type: env, var: XAI_API_KEY}
        vendor: xai               # optional; defaults to provider
        local_weights: false      # optional; ollama defaults to true
        echo_binding: false       # optional; required true when ballot_binding: echo

Auth types: none | env | keyring | username_password | oauth_device_code | callback.
Hooks (``login``, ``fetch_token``, ``callback``) are "module:function" strings
that are imported at load time. The config file is authored by the principal
and is trusted to the same degree as code.

Secrets never appear in this file, only the names of env vars or keyring entries.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Callable

from ..quorum import QuorumConfigError, QuorumPolicy, check_judge_set
from .anthropic import AnthropicJudge
from .base import Judge
from .credentials import (CallbackTokenProvider, CredentialProvider, EnvApiKey, KeyringApiKey, NoCredential,
                          OAuthDeviceCodeProvider, UsernamePasswordProvider)
from .gemini import GeminiJudge
from .ollama import OllamaJudge
from .openai_compat import OpenAICompatibleJudge

ADAPTERS = {
    "openai_compatible": OpenAICompatibleJudge,
    "anthropic": AnthropicJudge,
    "gemini": GeminiJudge,
    "ollama": OllamaJudge,
}
DEFAULT_PROVIDER = {"openai_compatible": "openai-compatible", "anthropic": "anthropic",
                    "gemini": "google", "ollama": "ollama-local"}
JUDGE_KEYS = {"id", "type", "provider", "base_url", "model", "auth", "timeout", "json_mode",
              "max_tokens", "auth_header", "allow_insecure_http", "vendor", "local_weights", "weights_sha256",
              "echo_binding"}
QUORUM_KEYS = {"required_yes", "min_responding", "min_distinct_providers", "timeout_seconds", "parallel",
               "min_vendors", "min_local_judges", "heterogeneity_scope", "judge_inputs", "ballot_binding",
               "require_path_a_first"}


class JudgeConfigError(ValueError):
    pass


def _hook(spec: Any) -> Callable:
    if not isinstance(spec, str) or ":" not in spec:
        raise JudgeConfigError(f"hook must be 'module:function', got {spec!r}")
    mod, fn = spec.split(":", 1)
    try:
        return getattr(importlib.import_module(mod), fn)
    except (ImportError, AttributeError) as e:
        raise JudgeConfigError(f"cannot import hook {spec!r}: {e}") from e


def build_credential(auth: Any) -> CredentialProvider:
    if auth is None:
        return NoCredential()
    if not isinstance(auth, dict) or "type" not in auth:
        raise JudgeConfigError("auth must be a mapping with a 'type'")
    t = auth["type"]
    if any(k in auth for k in ("key", "api_key", "password", "token", "secret")):
        raise JudgeConfigError("secrets must not be written in judges config; reference an env var or keyring")
    if t == "none":
        return NoCredential()
    if t == "env":
        return EnvApiKey(auth.get("var", ""))
    if t == "keyring":
        return KeyringApiKey(auth["service"], auth["username"])
    if t == "username_password":
        return UsernamePasswordProvider(auth["username"], auth["password_env"],
                                        _hook(auth["login"]) if "login" in auth else None)
    if t == "oauth_device_code":
        return OAuthDeviceCodeProvider(auth["client_id"], auth["device_authorization_endpoint"],
                                       auth["token_endpoint"], auth.get("scope", ""),
                                       _hook(auth["fetch_token"]) if "fetch_token" in auth else None)
    if t == "callback":
        return CallbackTokenProvider(_hook(auth["callback"]))
    raise JudgeConfigError(f"unknown auth type {t!r}")


def build_judge(spec: dict, transport=None) -> Judge:
    if not isinstance(spec, dict):
        raise JudgeConfigError("each judge must be a mapping")
    extra = set(spec) - JUDGE_KEYS
    if extra:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: unknown key(s) {sorted(extra)}")
    t = spec.get("type")
    if t not in ADAPTERS:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: type must be one of {sorted(ADAPTERS)}")
    model = spec.get("model")
    if not isinstance(model, str) or not model or model.startswith("REPLACE_"):
        raise JudgeConfigError(f"judge {spec.get('id')!r}: set 'model' to a model you have access to")
    kw: dict[str, Any] = {
        "judge_id": spec.get("id"), "provider": spec.get("provider", DEFAULT_PROVIDER[t]), "model": model,
        "credential": build_credential(spec.get("auth")), "transport": transport,
    }
    for k in ("base_url", "timeout", "auth_header", "allow_insecure_http", "json_mode", "max_tokens",
              "vendor", "local_weights", "weights_sha256", "echo_binding"):
        if k in spec:
            kw[k] = spec[k]
    if t == "openai_compatible" and "base_url" not in kw:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: openai_compatible requires base_url")
    try:
        return ADAPTERS[t](**kw)
    except (TypeError, ValueError) as e:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: {e}") from e


def load_config(data: dict, transport=None) -> tuple[list[Judge], QuorumPolicy]:
    if not isinstance(data, dict) or not isinstance(data.get("judges"), list) or not data["judges"]:
        raise JudgeConfigError("config must contain a non-empty 'judges' list")
    judges = [build_judge(j, transport) for j in data["judges"]]
    ids = [j.judge_id for j in judges]
    if len(set(ids)) != len(ids):
        raise JudgeConfigError("judge ids must be unique")
    q = data.get("quorum") or {}
    if set(q) - QUORUM_KEYS:
        raise JudgeConfigError(f"unknown quorum keys {sorted(set(q) - QUORUM_KEYS)}")
    try:
        policy = QuorumPolicy(**q) if q else QuorumPolicy(required_yes=min(2, len(judges)))
    except QuorumConfigError as e:
        raise JudgeConfigError(str(e)) from e
    if policy.required_yes > len(judges):
        raise JudgeConfigError(f"required_yes={policy.required_yes} exceeds number of judges {len(judges)}")
    try:
        check_judge_set(judges, policy)
    except QuorumConfigError as e:
        raise JudgeConfigError(str(e)) from e
    return judges, policy


def load_config_file(path: Path, transport=None) -> tuple[list[Judge], QuorumPolicy]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        import yaml
        data = yaml.safe_load(text)
    return load_config(data, transport)

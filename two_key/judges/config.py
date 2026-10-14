"""Load the principal's Path B judge list from judges.yaml (or .json).

Format (see examples/judges.yaml):

    quorum:
      required_yes: 2          # k-of-n; omit for min(2, number of judges)
      min_responding: 2        # "K": minimum valid ballots
      min_distinct_providers: 1
      # profile: high_assurance  # opt-in: judges from 2 makers, 1 local judge, require_local_yes
      # Defaults shown (one judge is enough; see quorum.QuorumPolicy):
      min_makers: 1            # >= 2 with profile: high_assurance
      min_local_judges: 0      # >= 1 with profile: high_assurance
      require_local_yes: false # true with profile: high_assurance
      heterogeneity_scope: selection   # selection | responding
      judge_inputs: record_only        # record_only | record_and_proposal
      ballot_binding: stamp            # stamp | echo
      require_path_a_first: false      # stored, not a skip
      tool_args_on_derive_deny: false # true sends argument bytes after a derive deny
      # allow_same_provider_judge: deprecated, no effect (the same provider is allowed)
      # allow_same_model_distinct_tenant: deprecated, no effect (a judge is refused on the agent's credential)
    monitored_agent:             # required; read by identity.load_monitored_agent_file
      id: my-agent
      model: REPLACE_WITH_MODEL
      provider: openai          # a label; recorded, never compared
      base_url: https://api.openai.com/v1
      credential_env: OPENAI_AGENT_API_KEY   # or username_env + password_env (HTTPS only), or credential: none
      # tenant: {organization: org-123}   # optional: organization, project, account, deployment
      # upstream: api.openai.com # declare for a loopback/private proxy or daemon: an alias model, or the same model as a judge
    judges:
      - id: grok
        type: openai_compatible   # openai_compatible | anthropic | gemini | ollama
        provider: xai             # free-form label, used by min_distinct_providers
        base_url: https://api.x.ai/v1
        model: REPLACE_WITH_MODEL
        auth: {type: env, var: XAI_API_KEY}
        maker: xai                # optional; who made the model; defaults to provider
        local_weights: false      # optional; ollama defaults to true
        echo_binding: false       # optional; required true when ballot_binding: echo

Auth types: none | env | keyring | callback | basic. ``basic`` is
``{type: basic, username_env: NAME, password_env: NAME}``, sent as HTTP Basic over HTTPS only.
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

from ..quorum import QuorumConfigError, QuorumPolicy, check_judge_set, unmeetable_floor
from ..strict import StrictParseError, load_file_strict
from .anthropic import AnthropicJudge
from .base import Judge
from .credentials import (BasicAuthCredential, CallbackTokenProvider, CredentialProvider, EnvApiKey, KeyringApiKey,
                          NoCredential)
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
              "max_tokens", "auth_header", "allow_insecure_http", "maker", "local_weights", "weights_sha256",
              "echo_binding", "ballot_key_env", "receives_proposal", "response_format", "reasoning_effort",
              "tenant", "upstream"}
QUORUM_KEYS = {"required_yes", "min_responding", "min_distinct_providers", "timeout_seconds", "parallel",
               "min_makers", "min_local_judges", "heterogeneity_scope", "judge_inputs", "ballot_binding",
               "require_path_a_first", "require_local_yes", "tool_args_on_derive_deny", "profile",
               "allow_same_provider_judge", "allow_same_model_distinct_tenant"}
TOP_LEVEL_KEYS = {"judges", "quorum", "monitored_agent"}
# default: one judge is enough. high_assurance: QuorumPolicy.high_assurance() (2 makers, 1 local, local yes).
QUORUM_PROFILES = {"default", "high_assurance"}


# The keys each auth type takes; any other key is refused (#52).
AUTH_KEYS = {"none": {"type"}, "env": {"type", "var"}, "keyring": {"type", "service", "username"},
             "callback": {"type", "callback"}, "basic": {"type", "username_env", "password_env"}}


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
    if not isinstance(t, str):
        raise JudgeConfigError(f"unknown auth type {t!r}")
    allowed = AUTH_KEYS.get(t)
    if allowed is not None and set(auth) - allowed:
        # A misspelled key (vars:, servce:) must not be dropped silently (#52).
        raise JudgeConfigError(f"auth type {t} takes only {sorted(allowed - {'type'}) or 'type'}, not "
                               f"{sorted(map(str, set(auth) - allowed))}")
    if t == "none":
        return NoCredential()
    if t == "env":
        return EnvApiKey(auth.get("var", ""))
    if t == "keyring":
        return KeyringApiKey(auth["service"], auth["username"])
    if t == "basic":
        names = auth.get("username_env"), auth.get("password_env")
        if any(not isinstance(n, str) or not n or n.startswith("REPLACE_") for n in names):
            raise JudgeConfigError("auth type basic needs username_env and password_env: the names of the "
                                   "environment variables that hold them")
        return BasicAuthCredential(*names)
    if t == "username_password":
        raise JudgeConfigError("username_password is now auth type basic (username_env and password_env; HTTPS only)")
    if t == "oauth_device_code":
        raise JudgeConfigError(f"{t} is not in the concept line; use auth type env or callback")
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
        raise JudgeConfigError(f"judge {spec.get('id')!r}: replace REPLACE_WITH_MODEL with a model name your account can use")
    if "ballot_key" in spec:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: do not write ballot_key in the file; set ballot_key_env to an environment variable")
    env_name = spec.get("ballot_key_env")
    if env_name is not None and (not isinstance(env_name, str) or not env_name or env_name.startswith("REPLACE_")):
        raise JudgeConfigError(f"judge {spec.get('id')!r}: ballot_key_env must name an environment variable")
    kw: dict[str, Any] = {
        "judge_id": spec.get("id"), "provider": spec.get("provider", DEFAULT_PROVIDER[t]), "model": model,
        "credential": build_credential(spec.get("auth")), "transport": transport,
    }
    for k in ("base_url", "timeout", "auth_header", "allow_insecure_http", "json_mode", "max_tokens",
              "maker", "local_weights", "weights_sha256", "echo_binding", "ballot_key_env", "receives_proposal",
              "response_format", "reasoning_effort"):
        if k in spec:
            kw[k] = spec[k]
    if t == "openai_compatible" and "base_url" not in kw:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: openai_compatible requires base_url")
    try:
        judge = ADAPTERS[t](**kw)
    except (TypeError, ValueError) as e:
        raise JudgeConfigError(f"judge {spec.get('id')!r}: {e}") from e
    if "tenant" in spec or "upstream" in spec:
        from ..identity import IdentityError, validate_tenant, validate_upstream
        try:
            judge.tenant = validate_tenant(spec.get("tenant"), f"judge {spec.get('id')!r}") or None
            # where a proxy forwards; operator-attested, ledgered, not verified
            judge.upstream = sorted(validate_upstream(spec.get("upstream"), f"judge {spec.get('id')!r}")) or None
        except IdentityError as e:
            raise JudgeConfigError(str(e)) from None
    return judge


def load_config(data: dict, transport=None) -> tuple[list[Judge], QuorumPolicy]:
    """Judges and quorum policy. The ``monitored_agent`` block is read by identity.load_monitored_agent."""
    if not isinstance(data, dict) or not isinstance(data.get("judges"), list) or not data["judges"]:
        raise JudgeConfigError("config must contain a non-empty 'judges' list")
    unknown = set(data) - TOP_LEVEL_KEYS
    if unknown:  # a typo such as "quorm:" must not silently drop the quorum block
        raise JudgeConfigError(f"unknown top-level key(s) {sorted(map(str, unknown))}; "
                               f"allowed: {sorted(TOP_LEVEL_KEYS)}")
    judges = [build_judge(j, transport) for j in data["judges"]]
    ids = [j.judge_id for j in judges]
    if len(set(ids)) != len(ids):
        raise JudgeConfigError("duplicate_judge_id: judge ids must be unique")
    q = data.get("quorum") or {}
    if not isinstance(q, dict):
        raise JudgeConfigError("quorum must be a mapping")
    q = dict(q)
    if set(q) - QUORUM_KEYS:
        raise JudgeConfigError(f"unknown quorum keys {sorted(set(q) - QUORUM_KEYS)}")
    profile = q.pop("profile", "default")
    if profile not in QUORUM_PROFILES:
        raise JudgeConfigError(f"quorum profile must be one of {sorted(QUORUM_PROFILES)}")
    try:
        if profile == "high_assurance":
            policy = QuorumPolicy.high_assurance(**q)
        else:
            policy = QuorumPolicy(**q)
    except QuorumConfigError as e:
        raise JudgeConfigError(str(e)) from e
    policy = policy.resolved(len(judges))  # required_yes omitted: min(2, number of judges)
    # The same reason TwoKey and convene give (HOWTO "Quorum policy"), so a config file reports it too.
    floor = unmeetable_floor(judges, policy)
    if floor:
        raise JudgeConfigError(f"{floor} (required_yes={policy.required_yes}, "
                               f"min_responding={policy.effective_min_responding}, judges={len(judges)})")
    if policy.timeout_seconds is None:
        raise JudgeConfigError("quorum timeout_seconds must be a positive number (a hard deadline), not null")
    try:
        check_judge_set(judges, policy)
    except QuorumConfigError as e:
        raise JudgeConfigError(str(e)) from e
    return judges, policy


def load_config_file(path: Path, transport=None) -> tuple[list[Judge], QuorumPolicy]:
    try:
        data = load_file_strict(path)
    except StrictParseError as e:
        raise JudgeConfigError(f"{path}: {e}") from None
    return load_config(data, transport)

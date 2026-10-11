"""
Two-Key: a Path B judge must not be the monitored agent
=======================================================
The rule (the owner's, revised 2026-10-08, restated 2026-10-09): at least one
judge, and no judge may be the monitored agent. A judge may run any model from
any vendor. A judge must not be the monitored agent: ``TwoKey`` refuses to start
(``judge_matches_agent:``) when a judge holds the monitored agent's credential
(the same API token, or the same username and password), at any address: a
credential identifies its holder, so the address it is sent to does not matter.
That holds whether or not either side sends the credential (a judge with
``auth_header: none``, an ``agents.yaml`` Ollama agent) and whichever form it is
held in (a token ``user:pass`` and a Basic pair ``user`` / ``pass`` are the same
username and password). Two sides that send no credential have only their
address to tell them apart, so they are refused on the same address. The
operator configures who the agent is; Two-Key refuses a judge that is the agent
and makes likely accidents visible.

The agent's identity comes only from operator configuration
(``TwoKey(monitored_agent=...)``, the ``monitored_agent:`` block of
judges.yaml, and any configured ``agents``), never from anything the agent
says about itself. The declaration names the model, the provider (recorded as
a label, never compared), the endpoint ``base_url``, the credential (the
name of the environment variable that holds the agent's key,
``credential_env``; the two variables that hold a username and password,
``username_env`` and ``password_env``, sent as HTTP Basic over HTTPS only; or
``credential: none`` for a keyless loopback or private-address agent), and optionally a
``tenant`` mapping (see below). If any required field is missing or cannot
be read, Two-Key refuses to start.

Each judge and agent is resolved to:

- ``model``: the model id, normalized (case, router prefixes such as
  ``openai/`` or Bedrock's ``anthropic.``, dated snapshot suffixes such as
  ``-2024-08-06`` or ``-20241022``, ``-latest``, Vertex ``@`` versions,
  Bedrock ``-v2:0``, Ollama ``:latest``, and a few known aliases). The id is
  NFKC-normalized first, Unicode dashes are folded to ``-``, and zero-width
  characters are removed, so ``gpt\u20104o`` and fullwidth ``gpt-4o`` equal
  ``gpt-4o``.
- ``endpoint``: the normalized ``host:port`` of ``base_url`` (lower case,
  default port filled in, every alias of this machine written ``localhost``:
  loopback names and addresses in any spelling such as ``127.1``,
  ``localhost.localdomain``, ``0.0.0.0``/``::``, and the machine's own names
  and addresses). Other hosts are compared literally.
- ``upstreams``: who really serves or made the model, as upstream hosts.
  A direct provider host is itself (``api.openai.com``). A recognized router
  (OpenRouter, Azure OpenAI and Azure AI, Bedrock, Vertex, Cloudflare AI
  Gateway, Portkey) or a ``provider/model`` id (LiteLLM style) resolves to the
  model maker's API host, or ``maker:<name>`` for a maker without one. A
  loopback or private host is itself. An unrecognized host or router that
  cannot be resolved from the model id stays **unresolved**. Upstream labels
  are normalized (``host`` or ``host:port``, default port removed). A shared
  maker upstream is not compared; the same *model* reaching the same route
  is warned (see ``routes``).
- ``routes``: where the model is actually served, for the same-model warning:
  the endpoint, every declared ``upstream:``, and ``ollama.com`` for an Ollama
  cloud model.
- ``tenant``: account ids, each scoped by provider family, from what the
  base_url shows plus what the operator declares under ``tenant:``
  (keys ``organization``, ``project``, ``account``, ``deployment``):
  Azure resource (host) and deployment (``/openai/deployments/<name>``),
  Vertex project (``/projects/<id>/`` in the path, or declared ``project``),
  Bedrock ``account`` (declared) with the region from the host, OpenAI
  ``organization`` / ``project`` (declared). Elsewhere a declared id is scoped
  by provider family: the endpoint's, or for a proxy (local or unrecognized
  host) the family of its declared upstream, its Ollama cloud model, or its
  model maker, never the proxy's address.
- ``credential``: a fingerprint of every credential the side holds, sent or
  not, with leading and trailing whitespace stripped. An API token is
  fingerprinted with HMAC-SHA256 (``hmac-sha256:...``); a username and
  password, as one ``username:password`` pair, with PBKDF2-HMAC-SHA256
  (``pbkdf2-sha256-600000:...``, 600,000 iterations), because a password may
  be guessable. Any secret that contains ``:`` is fingerprinted as a pair, so a
  username and password match whether a side holds them as HTTP Basic or as
  a ``user:pass`` token. ``credential_sent`` records whether the connector
  sends it. Both are keyed
  by a random per-install secret, ``fingerprint.key`` beside the ledger key
  (``<ledger>.ledger-key/``, created once with O_EXCL, mode 0600). That key
  stops someone who sees a fingerprint outside the key directory (a copied
  record, an export) from testing guesses. It does not stop someone who holds
  the key directory, who can also decrypt the ledger: there a random API
  token is safe by its length, and a password only by PBKDF2's cost. Raw
  keys and passwords are never stored or logged. ``none`` means the endpoint
  takes no key.

Refusals, judge against agent, message prefix ``judge_matches_agent:``:

- the same credential fingerprint, at any address: an API token, a
  username/password pair, or any credential the agent declares. Every
  credential each side holds is compared, sent or not. A
  placeholder value that a local server ignores (``EMPTY``) counts too: give
  each side its own value, or leave it off one side (``auth: {type: none}``
  on a judge, ``credential: none`` on the agent);
- the same address (normalized ``endpoint``, ``host:port``, every alias of
  this machine folded to ``localhost``) with no credential sent on either
  side: Two-Key has nothing to tell them apart by.

Two-Key also refuses to start, with its own message, when a judge's or the
agent's address or credential cannot be read at start-up.

Everything else is allowed: any model, any vendor, any endpoint. Likely
accidents are allowed with a warning on stderr, and every warning is
recorded in ``constitution_loaded`` (``judge_agent_separation.warnings``):
one side without a credential on the same address, the same model on the
same address, the same model through a shared route or through a local or
unrecognized proxy with no declared ``upstream:``, a shared tenant id, and an
identity whose upstream cannot be resolved. Addresses are compared as
configured; DNS names are not resolved.

``allow_same_model_distinct_tenant`` and ``allow_same_provider_judge`` are
deprecated no-ops: nothing they used to lift is refused any more.

The runtime check stays as a second layer: a judge whose credential equals
the frozen agent session abstains with ``cloud_judge_reused_agent_session``,
wherever it connects. On every call Two-Key also re-reads the credential
named for the monitored agent and compares that too. A placeholder session
does not hide it. The value is not sent to the judge and not written down.
A session that is not that credential is still the caller's to pass. A
keyless agent (``credential: none``) has nothing to add.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import ipaddress
import secrets
import socket
import stat
import re
import sys
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from .agent_meta import type_tag
from .netloc import fold_model_id, host_is_local, host_is_loopback, model_is_cloud

FINGERPRINT_DOMAIN = b"two-key/credential-fingerprint/1\x00"
NO_CREDENTIAL = "none"
IN_PROCESS = "in-process"
AGENT_KEYS = {"id", "model", "provider", "base_url", "credential_env", "credential", "username_env", "password_env",
              "tenant", "upstream"}
TENANT_KEYS = ("organization", "project", "account", "deployment")
# What refuses a judge (the same specific agent), and what only warns (a likely accident, recorded).
SEPARATION_RULE = "same_held_credential_or_keyless_same_address"
SEPARATION_CHECKS = ("same_credential", "same_address_no_credential")
SEPARATION_WARNINGS = ("same_address_one_side_keyless", "same_model_same_address", "same_model_shared_route",
                       "same_model_unknown_proxy", "shared_tenant", "unresolved_identity")


class IdentityError(ValueError):
    """The agent or a judge cannot be identified, or a judge could be the agent."""


FINGERPRINT_KEY_BYTES = 32


def load_fingerprint_key(path: str | os.PathLike) -> bytes:
    """Load the per-install HMAC key at ``path``, creating it the first time.

    32 random bytes, created with O_EXCL (two processes never write different
    keys) at mode 0600 in a 0700 directory. An existing key is read with
    O_NOFOLLOW and refused if it is not a regular file, is group- or
    world-accessible, or is not 32 bytes. Never regenerated.
    """
    path = os.fspath(path)
    if not os.path.lexists(path):
        try:
            os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
            os.chmod(os.path.dirname(path) or ".", 0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = None                      # another process created it first: read theirs
        except OSError as e:
            raise IdentityError(f"fingerprint_key_unavailable: cannot create {path}: {e.strerror}") from None
        if fd is not None:
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_bytes(FINGERPRINT_KEY_BYTES))
                fh.flush()
                os.fsync(fh.fileno())
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise IdentityError(f"fingerprint_key_unreadable: {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise IdentityError(f"fingerprint_key_unreadable: {path} is not a regular file")
        if st.st_mode & 0o077:
            raise IdentityError(f"fingerprint_key_insecure: {path} is readable by group or others; chmod 600 it")
        data = os.read(fd, FINGERPRINT_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) != FINGERPRINT_KEY_BYTES:
        raise IdentityError(f"fingerprint_key_unreadable: {path} is not a {FINGERPRINT_KEY_BYTES}-byte key")
    return data


def fingerprint_key_id(key: bytes) -> str:
    """A public id for the HMAC key, so a ledger reader knows which install's fingerprints these are."""
    return hashlib.sha256(b"two-key/fingerprint-key-id/1\x00" + key).hexdigest()[:16]


def credential_fingerprint(secret: str | None, key: bytes | None = None) -> str:
    """Fingerprint of the secret with surrounding whitespace stripped; ``none`` for no secret.

    ``hmac-sha256:`` under the per-install key (TwoKey always passes one: ``Ledger.fingerprint_key``).
    Without a key, a plain ``sha256:`` (offline use only).
    """
    secret = (secret or "").strip()
    if not secret:
        return NO_CREDENTIAL
    data = FINGERPRINT_DOMAIN + secret.encode("utf-8", "surrogatepass")
    if key is not None:
        return "hmac-sha256:" + hmac.new(key, data, hashlib.sha256).hexdigest()
    return "sha256:" + hashlib.sha256(data).hexdigest()


# A username and password may be guessable, so the pair is stretched: PBKDF2-HMAC-SHA256 (NIST SP 800-132) with the
# per-install key (256 bits) as the salt, at 600,000 iterations (OWASP's setting where FIPS 140 is required; about
# 0.15 s). PBKDF2 is in OpenSSL's FIPS provider; scrypt is not, and is not an approved function, so it would stop a
# later approved mode (ROADMAP 0.9). API tokens are random and keep the cheap HMAC above. The prefix names the
# parameters, so a later change of cost is visible in the ledger.
PASSWORD_KDF = {"alg": "pbkdf2-hmac-sha256", "iterations": 600_000, "dklen": 32}
PASSWORD_FINGERPRINT_ALG = "pbkdf2-sha256-600000"


def password_fingerprint(pair: str | None, key: bytes | None) -> str:
    """Fingerprint of a ``username:password`` pair, whitespace stripped from its two ends only: PBKDF2-HMAC-SHA256
    with the per-install key as the salt.

    A key is required; there is no unkeyed form for a password."""
    pair = (pair or "").strip()
    if not pair:
        return NO_CREDENTIAL
    if key is None:
        raise IdentityError("fingerprint_key_required: a username and password are fingerprinted only under the "
                            "per-install key")
    k = PASSWORD_KDF
    try:
        derived = hashlib.pbkdf2_hmac("sha256", FINGERPRINT_DOMAIN + pair.encode("utf-8", "surrogatepass"), key,
                                      k["iterations"], k["dklen"])
    except (ValueError, MemoryError, AttributeError) as e:   # an OpenSSL that refuses these parameters
        raise IdentityError(f"password_fingerprint_failed: PBKDF2 ({PASSWORD_FINGERPRINT_ALG}) failed "
                            f"({type_tag(e)})") from None
    return f"{PASSWORD_FINGERPRINT_ALG}:{derived.hex()}"


# ---------------------------------------------------------------- model ids
_MAKER_HOSTS = {
    "openai": "api.openai.com", "anthropic": "api.anthropic.com", "google": "generativelanguage.googleapis.com",
    "xai": "api.x.ai", "mistral": "api.mistral.ai", "deepseek": "api.deepseek.com", "cohere": "api.cohere.com",
}
_PREFIX_MAKERS = {
    "openai": "openai", "anthropic": "anthropic", "google": "google", "gemini": "google", "xai": "xai",
    "x-ai": "xai", "meta-llama": "meta", "meta": "meta", "mistralai": "mistral", "mistral": "mistral",
    "qwen": "alibaba", "alibaba": "alibaba", "deepseek": "deepseek", "deepseek-ai": "deepseek",
    "cohere": "cohere", "microsoft": "microsoft", "amazon": "amazon", "ai21": "ai21", "nvidia": "nvidia",
    "moonshotai": "moonshot", "zhipuai": "zhipu", "writer": "writer",
}
# LiteLLM-style prefixes that name a router, not a maker; the rest of the id is resolved again.
_ROUTER_PREFIXES = {"bedrock", "vertex_ai", "vertex", "azure", "azure_ai", "openrouter", "litellm_proxy"}
_FAMILIES = [
    (re.compile(r"^(gpt|chatgpt|o[1-9]\b|o[1-9]-|text-davinci|davinci|babbage|gpt-oss)"), "openai"),
    (re.compile(r"^claude"), "anthropic"),
    (re.compile(r"^(gemini|gemma|palm|text-bison|chat-bison)"), "google"),
    (re.compile(r"^grok"), "xai"),
    (re.compile(r"^(llama|codellama|meta-llama)"), "meta"),
    (re.compile(r"^(qwen|qwq)"), "alibaba"),
    (re.compile(r"^(mistral|mixtral|codestral|ministral|pixtral|magistral|devstral)"), "mistral"),
    (re.compile(r"^deepseek"), "deepseek"),
    (re.compile(r"^phi"), "microsoft"),
    (re.compile(r"^command"), "cohere"),
    (re.compile(r"^(nemotron|nvidia)"), "nvidia"),
    (re.compile(r"^(kimi|moonshot)"), "moonshot"),
    (re.compile(r"^glm"), "zhipu"),
]
_ALIASES = {"chatgpt-4o": "gpt-4o", "gemini-pro": "gemini-1.0-pro", "gpt-4-turbo-preview": "gpt-4-turbo"}
_SUFFIXES = [
    re.compile(r"-20\d{2}-\d{2}-\d{2}$"),     # -2024-08-06
    re.compile(r"-20\d{6}$"),                 # -20241022
    re.compile(r"-v\d+(:\d+)?$"),             # Bedrock -v2:0
    re.compile(r"-(latest|cloud)$"),
    re.compile(r"-\d{2}-\d{2}$"),             # -preview-05-06
    re.compile(r"-\d{4}$"),                   # -0613, -2407
    re.compile(r"-0\d{2}$"),                  # Gemini -001
    re.compile(r"-(instruct|chat|it)$"),
]


def _bare(model: str) -> tuple[str, str | None]:
    """(model id without router/maker prefixes, maker named by a prefix if any)."""
    m = fold_model_id(model)                                  # NFKC, Unicode dashes, zero-width, case
    m = re.sub(r"^gpt-35(?=-|$)", "gpt-3.5", m)               # Azure OpenAI names gpt-3.5 "gpt-35"
    maker = None
    m = re.sub(r"^projects/[^/]+/locations/[^/]+/", "", m)
    pub = re.match(r"^publishers/([^/]+)/models/(.+)$", m)
    if pub:
        maker = _PREFIX_MAKERS.get(pub.group(1), maker)
        m = pub.group(2)
    if m.startswith("models/"):
        m = m[len("models/"):]
    while "/" in m:
        head, m = m.split("/", 1)
        if head not in _ROUTER_PREFIXES:
            maker = _PREFIX_MAKERS.get(head, maker)
    m = re.sub(r"^(us|eu|apac|us-gov|global|jp|au)\.", "", m)          # Bedrock cross-region ids
    bedrock = re.match(r"^([a-z0-9-]+)\.(.+)$", m)
    if bedrock and bedrock.group(1) in _PREFIX_MAKERS:
        maker = _PREFIX_MAKERS[bedrock.group(1)]
        m = bedrock.group(2)
    return m, maker


def normalize_model(model: str) -> str:
    """Comparable model id. Two ids that may name the same model should normalize the same."""
    m, _ = _bare(model)
    m = m.split("@", 1)[0]                                    # Vertex @20241022 / @001
    m = re.sub(r":(latest|cloud)$", "", m)                    # Ollama tags that name no variant
    m = re.sub(r":\d+$", "", m)                               # Bedrock :0
    m = m.replace(":", "-").replace("_", "-")
    if m.startswith("claude"):
        m = re.sub(r"(?<=\d)\.(?=\d)", "-", m)                # claude-3.5-sonnet == claude-3-5-sonnet
    changed = True
    while changed:
        changed = False
        for pat in _SUFFIXES:
            new = pat.sub("", m)
            if new != m and new:
                m, changed = new, True
        if m.startswith("claude") and re.search(r"-\d+-0$", m):
            m, changed = m[:-2], True                          # claude-opus-4-0 == claude-opus-4
    m = _ALIASES.get(m, m)
    m = re.sub(r"(?<=[a-z])-(?=\d)", "", m)                   # llama-3.1 == llama3.1, gpt-4o == gpt4o
    return m


def model_maker(model: str) -> str | None:
    bare, maker = _bare(model)
    if maker:
        return maker
    for pat, name in _FAMILIES:
        if pat.match(bare):
            return name
    return None


def _maker_upstream(maker: str) -> str:
    return _MAKER_HOSTS.get(maker, f"maker:{maker}")


# ---------------------------------------------------------------- endpoints
_DIRECT_HOSTS = {
    "api.openai.com": "openai", "api.anthropic.com": "anthropic", "generativelanguage.googleapis.com": "google",
    "api.x.ai": "xai", "api.mistral.ai": "mistral", "api.deepseek.com": "deepseek", "api.cohere.com": "cohere",
    "api.cohere.ai": "cohere",
}
# Inference hosts that serve other makers' models themselves: the host is an upstream, and so is the maker.
_INFERENCE_HOSTS = {"api.groq.com", "api.together.xyz", "api.fireworks.ai", "api.deepinfra.com",
                    "api.perplexity.ai", "ollama.com"}


def _router(host: str) -> str | None:
    if host in ("openrouter.ai", "api.openrouter.ai"):
        return "openrouter"
    if host.endswith(".openai.azure.com"):
        return "azure-openai"
    if host.endswith((".services.ai.azure.com", ".models.ai.azure.com", ".inference.ai.azure.com")):
        return "azure-ai"
    if re.fullmatch(r"bedrock-runtime(-fips)?\.[a-z0-9-]+\.amazonaws\.com", host):
        return "bedrock"
    if host == "aiplatform.googleapis.com" or host.endswith("-aiplatform.googleapis.com"):
        return "vertex"
    if host == "gateway.ai.cloudflare.com":
        return "cloudflare-ai-gateway"
    if host == "api.portkey.ai":
        return "portkey"
    return None


_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


@lru_cache(maxsize=1)
def _own_addresses() -> frozenset[str]:
    """This machine's own names and addresses (best effort, no network traffic)."""
    out: set[str] = set()
    try:
        names = {socket.gethostname().lower(), socket.getfqdn().lower()} - {""}
    except OSError:
        names = set()
    out |= names
    for name in names:
        try:
            for info in socket.getaddrinfo(name, None):
                out.add(str(info[4][0]).split("%", 1)[0].lower())
        except (OSError, UnicodeError):
            pass
    # The source address of the default route. Connecting a UDP socket sends no packet; the target is
    # a documentation address that is never contacted.
    for family, target in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.connect((target, 9))
                out.add(str(probe.getsockname()[0]).split("%", 1)[0].lower())
        except OSError:
            pass
    return frozenset(out)


def _legacy_ipv4(host: str):
    """``127.1``, ``0x7f.1``, ``2130706433``: forms inet_aton accepts but ipaddress does not."""
    if not re.fullmatch(r"[0-9a-fx.]+", host) or not re.search(r"[0-9]", host):
        return None
    try:
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def local_alias(host: str) -> bool:
    """True for a name or address that reaches this machine: a loopback name or address (any
    127.0.0.0/8 spelling, ``::1``), ``localhost.localdomain``, an unspecified address (which a client
    connects to as this machine), or one of this machine's own names or addresses."""
    host = (host or "").lower().rstrip(".").strip("[]").split("%", 1)[0]
    if not host:
        return False
    if host in _LOCAL_NAMES or host_is_loopback(host):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = _legacy_ipv4(host)
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if ip.is_unspecified or ip.is_loopback:
            return True
        return str(ip) in _own_addresses()
    return host in _own_addresses()


def endpoint_key(base_url: str) -> str:
    """``host:port`` with the default port filled in; every local alias of this machine is ``localhost``."""
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    if u.scheme == IN_PROCESS:
        return f"{IN_PROCESS}:{host}"
    try:
        port = u.port or {"https": 443, "http": 80}.get(u.scheme, 0)
    except ValueError:
        port = 0
    if local_alias(host):
        host = "localhost"
    return f"{host}:{port}"


def normalize_upstream(label: str) -> str:
    """A comparable upstream: a URL or ``host[:port]`` becomes lower-case ``host`` or ``host:port`` with a
    default port (80, 443) removed and local aliases written ``localhost``; ``maker:<name>`` and
    ``in-process:`` labels are kept as they are.

    Declared labels are folded first (NFKC, zero-width / soft-hyphen stripped, Unicode dashes to
    ASCII, strip, lower case). A bare maker name such as ``openai`` maps to that maker's API host
    (``api.openai.com``).
    """
    s = fold_model_id(label).rstrip("/")
    if not s or s.startswith(("maker:", f"{IN_PROCESS}:")):
        return s
    if s in _PREFIX_MAKERS:
        return _maker_upstream(_PREFIX_MAKERS[s])
    try:
        u = urlparse(s if "://" in s else f"//{s}")
        host = (u.hostname or "").rstrip(".")
        port = u.port
    except ValueError:
        return s
    if not host:
        return s
    if local_alias(host):
        host = "localhost"
    elif ":" in host:
        host = f"[{host}]"
    return host if port in (None, 80, 443) else f"{host}:{port}"


def resolve_upstream_info(base_url: str, model: str) -> tuple[frozenset[str], str | None, str | None]:
    """(upstream hosts, router name, resolved_by). An empty set means unresolved (resolved_by None).

    ``resolved_by``: ``endpoint`` (the host itself says who serves the model), ``model_prefix`` (the
    model id names its maker; operator-attested through the model name, not verified). A loopback or
    private endpoint whose model names no recognizable maker is unresolved: a local proxy can route
    an alias anywhere. ``declared_upstream`` is set by ``_identity`` when the operator declares one.
    """
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    maker = model_maker(model)
    up: set[str] = set()
    if u.scheme == IN_PROCESS:
        return frozenset({f"{IN_PROCESS}:{host}"}), None, "endpoint"
    router = _router(host)
    bare, prefixed = _bare(model)
    by: str | None = None
    if host in _DIRECT_HOSTS:
        up.add(_maker_upstream(_DIRECT_HOSTS[host]))
        if maker:
            up.add(_maker_upstream(maker))
        by = "endpoint"
    elif router == "azure-openai":
        up.add(_maker_upstream("openai"))        # deployment names are free text; the maker is OpenAI
        by = "endpoint"
    elif router is not None:
        if maker:
            up.add(_maker_upstream(maker))
            by = "model_prefix"
    elif host in _INFERENCE_HOSTS:
        up.add(endpoint_key(base_url))
        if maker:
            up.add(_maker_upstream(maker))
        by = "endpoint"
    elif host_is_local(host):
        if maker or model_is_cloud(model):
            up.add(endpoint_key(base_url))
            if maker:
                up.add(_maker_upstream(maker))
            if model_is_cloud(model):
                up.add("ollama.com")             # an Ollama cloud model, proxied by the local daemon
            by = "model_prefix"
        # otherwise unresolved: a local proxy (LiteLLM and the like) can route an alias to anything
    else:
        if prefixed:                             # LiteLLM-style provider/model id on an unrecognized host
            up.add(_maker_upstream(prefixed))
            by = "model_prefix"
        # otherwise unresolved: an unrecognized host may be a router to anything
    up = {normalize_upstream(x) for x in up}
    return frozenset(up), router, (by if up else None)


def resolve_upstreams(base_url: str, model: str) -> tuple[frozenset[str], str | None]:
    """(upstream hosts, router name). An empty set means unresolved."""
    up, router, _ = resolve_upstream_info(base_url, model)
    return up, router


def validate_upstream(upstream: Any, who: str) -> frozenset[str]:
    """An operator-declared ``upstream:`` (a host or label, or a list of them). Ledgered; not verified."""
    if upstream is None:
        return frozenset()
    items = [upstream] if isinstance(upstream, str) else upstream
    if not isinstance(items, (list, tuple)) or not items:
        raise IdentityError(f"{who}: upstream must be a non-empty string or list of strings")
    out = set()
    for v in items:
        if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
            raise IdentityError(f"{who}: upstream entries must be non-empty strings")
        out.add(normalize_upstream(v))
    return frozenset(out)


# ---------------------------------------------------------------- tenants
def validate_tenant(tenant: Any, who: str) -> dict[str, str]:
    """An operator-declared ``tenant:`` mapping: organization, project, account, deployment.

    ``None`` (omit the field) means no tenant. An empty mapping ``{}`` is invalid — omit
    ``tenant`` instead of passing an empty dict.
    """
    if tenant is None:
        return {}
    if not isinstance(tenant, Mapping):
        raise IdentityError(f"{who}: tenant must be a mapping of {', '.join(TENANT_KEYS)}")
    if len(tenant) == 0:
        raise IdentityError(f"{who}: tenant mapping must not be empty (omit tenant instead)")
    extra = set(tenant) - set(TENANT_KEYS)
    if extra:
        raise IdentityError(f"{who}: unknown tenant key(s) {sorted(extra)}")
    out = {}
    for k, v in tenant.items():
        if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
            raise IdentityError(f"{who}: tenant {k} must be a non-empty string")
        out[k] = v.strip()
    return out


def _family(label: str) -> str:
    """The provider family of a normalized upstream label, for scoping tenant ids."""
    if label.startswith("maker:"):
        return label[len("maker:"):]
    host = label.rsplit(":", 1)[0] if label.count(":") == 1 else label
    if host in _DIRECT_HOSTS:
        return _DIRECT_HOSTS[host]
    if host == "ollama.com":
        return "ollama"
    if host.endswith(".openai.com") and not host.endswith(".azure.com"):
        return "openai"
    router = _router(host)
    return {"azure-openai": "azure", "azure-ai": "azure", "bedrock": "aws", "vertex": "gcp"}.get(router or "", router or label)


def _tenant_scopes(host: str, base_url: str, model: str | None, upstreams: frozenset[str]) -> list[str]:
    """Where a declared tenant id lives: the provider family of the endpoint, or for a proxy (a local
    or unrecognized host) the family of its declared upstream, its Ollama cloud model, or its model
    maker. Never the proxy's own address while any of those is known."""
    if host in _DIRECT_HOSTS or host == "ollama.com" or host.endswith(".openai.com"):
        return [_family(host)]
    if host in _INFERENCE_HOSTS:
        return [host]
    if upstreams:
        return sorted({_family(u) for u in upstreams})
    if model and model_is_cloud(model):
        return ["ollama"]
    maker = model_maker(model) if model else None
    if maker:
        return [maker]
    return [endpoint_key(base_url)]


def resolve_tenants(base_url: str, declared: Mapping[str, str] | None = None, *, model: str | None = None,
                    upstreams: Iterable[str] = ()) -> frozenset[str]:
    """Account ids, scoped by provider family, from the base_url plus the operator's declaration.

    A declared id on a proxy is scoped by the family it reaches (declared ``upstreams``, an Ollama
    cloud model, or the model maker), so ``project: p1`` behind a local proxy to OpenAI is the same
    tenant as ``project: p1`` at api.openai.com."""
    u = urlparse(base_url or "")
    host = (u.hostname or "").lower().rstrip(".")
    path = u.path or ""
    router = _router(host)
    declared = dict(declared or {})
    ids: set[str] = set()
    if router in ("azure-openai", "azure-ai"):
        resource = host.split(".", 1)[0]
        ids.add(f"azure:resource:{resource}")
        m = re.search(r"/openai/deployments/([^/?#]+)", path)
        for dep in {m.group(1) if m else None, declared.pop("deployment", None)} - {None}:
            ids.add(f"azure:deployment:{resource}/{dep.lower()}")
        scope = "azure"
    elif router == "bedrock":
        region = host.split(".")[1]
        account = declared.pop("account", None)
        if account:
            ids.add(f"aws:account:{account.lower()}@{region}")
        scope = "aws"
    elif router == "vertex":
        m = re.search(r"/projects/([^/?#]+)", path)
        for project in {m.group(1) if m else None, declared.pop("project", None)} - {None}:
            ids.add(f"gcp:project:{project.lower()}")
        scope = "gcp"
    else:
        scope = None
    scopes = [scope] if scope else _tenant_scopes(host, base_url, model, frozenset(upstreams))
    for sc in scopes:
        for k, v in declared.items():
            ids.add(f"{sc}:{k}:{v.lower()}")
    return frozenset(ids)


# ---------------------------------------------------------------- identities
@dataclass(frozen=True)
class ResolvedIdentity:
    role: str                 # "agent" or "judge"
    id: str
    model_declared: str
    model: str
    endpoint: str
    upstreams: frozenset[str]
    router: str | None
    credentials: frozenset[str] = field(default_factory=frozenset)   # fingerprints; may include "none"
    provider_label: str | None = None
    tenants: frozenset[str] = field(default_factory=frozenset)       # scoped account ids, see resolve_tenants
    resolved_by: str | None = None    # endpoint | model_prefix | declared_upstream; None = unresolved
    declared_upstreams: frozenset[str] = field(default_factory=frozenset)   # normalized operator `upstream:`
    local: bool = False               # the endpoint is this machine or a private address (a proxy or daemon)
    routes: frozenset[str] = field(default_factory=frozenset)   # endpoint + declared upstreams (+ ollama.com)
    tenant_declared: bool = False     # the operator declared a non-empty tenant: mapping
    proxy: bool = False               # local, or a host that is no recognized vendor, router, or inference host
    # Whether the connector sends the credential it holds. A judge with auth_header: none and an agents.yaml
    # ollama agent without Basic auth do not: they reach their address keyless, which is all the keyless-address
    # rule looks at. The same-credential rule compares every credential held (``credentials``), sent or not.
    sends: bool = True

    @property
    def unresolved(self) -> bool:
        return not self.upstreams or not self.model

    def to_record(self) -> dict:
        return {"role": self.role, "id": self.id, "model": self.model, "model_declared": self.model_declared,
                "upstream": sorted(self.upstreams) or None, "router": self.router, "endpoint": self.endpoint,
                "credential_fingerprint": sorted(self.credentials) or None,
                "credential_sent": _keyed(self),
                "tenant": sorted(self.tenants) or None, "resolved_by": self.resolved_by,
                "upstream_declared": sorted(self.declared_upstreams) or None, "local_endpoint": self.local,
                "routes": sorted(self.routes) or None, "tenant_declared": self.tenant_declared,
                "proxy_endpoint": self.proxy,
                "provider_label": self.provider_label, "resolved": not self.unresolved}


def _identity(role: str, ident: str, model: str, base_url: str, credentials: Iterable[str],
              provider_label: str | None, tenant: Mapping[str, str] | None = None,
              upstream: frozenset[str] = frozenset(), sends: bool = True) -> ResolvedIdentity:
    upstreams, router, by = resolve_upstream_info(base_url, model)
    upstream = frozenset(normalize_upstream(u) for u in upstream)
    if upstream:                       # operator-attested; ledgered, not verified
        upstreams, by = frozenset(upstreams | upstream), "declared_upstream"
    host = (urlparse(base_url or "").hostname or "").lower().rstrip(".")
    local = urlparse(base_url or "").scheme != IN_PROCESS and (local_alias(host) or host_is_local(host))
    # A host that is no recognized vendor, router, or inference host (litellm, host.docker.internal,
    # proxy.corp.example, 100.64.x, 169.254.x) says nothing about who serves the model, whatever the
    # model id's maker prefix claims: for the same-model check it is a proxy, like a local one.
    proxy = local or (urlparse(base_url or "").scheme != IN_PROCESS and host not in _DIRECT_HOSTS
                      and host not in _INFERENCE_HOSTS and _router(host) is None)
    # Where the model is really served, for the same-model comparison: the endpoint itself, every
    # declared upstream, and ollama.com for an Ollama cloud model (the local daemon forwards it there).
    routes = {normalize_upstream(base_url)} | set(upstream)
    if model_is_cloud(model):
        routes.add("ollama.com")
    return ResolvedIdentity(role, ident, model, normalize_model(model), endpoint_key(base_url), upstreams,
                            router, frozenset(credentials), provider_label,
                            resolve_tenants(base_url, tenant, model=model, upstreams=upstream), by,
                            upstream, local, frozenset(routes - {""}), bool(tenant), proxy, sends)


def _secret_from(credential: Any) -> str:
    """Read a judge or agent credential once, at start-up, to fingerprint it."""
    if credential is None or getattr(credential, "kind", None) == "none":
        return ""
    try:
        token = credential.get_token()
    except Exception as e:
        raise IdentityError(f"credential could not be read at start-up ({type_tag(e)}); "
                            "Two-Key cannot show it differs from the monitored agent's") from None
    if not token:
        raise IdentityError("credential is empty at start-up")
    return token


def secret_fingerprint(secret: str | None, fp_key: bytes | None) -> str:
    """Fingerprint a secret by what it contains: one with ``:`` may be a ``username:password`` pair (HTTP Basic, or a
    token that holds one), so PBKDF2 (``password_fingerprint``); anything else HMAC (``credential_fingerprint``).
    So a username and password match whether a side holds them as a Basic pair or as a ``user:pass`` token, and a
    password never gets the cheap hash."""
    secret = (secret or "").strip()
    return password_fingerprint(secret, fp_key) if ":" in secret else credential_fingerprint(secret, fp_key)


def _fingerprint(credential: Any, fp_key: bytes | None) -> str:
    """Read a judge's or agent's credential once and fingerprint it (``secret_fingerprint``). A credential sent as HTTP
    Basic (``kind == "basic"``, as the judge and agent connectors decide) is always a pair."""
    from .judges.credentials import BasicAuthCredential
    if isinstance(credential, BasicAuthCredential) or getattr(credential, "kind", None) == "basic":
        try:
            pair = credential.get_token()
        except Exception as e:      # as _secret_from: any failure to read refuses
            raise IdentityError(f"credential could not be read at start-up ({type_tag(e)}); "
                                "Two-Key cannot show it differs from the monitored agent's") from None
        if not isinstance(pair, str) or not pair.strip():   # as _secret_from: an empty credential refuses
            raise IdentityError("credential is empty at start-up")
        return password_fingerprint(pair, fp_key)
    return secret_fingerprint(_secret_from(credential), fp_key)


def judge_identity(judge: Any, fp_key: bytes | None = None) -> ResolvedIdentity:
    jid = str(getattr(judge, "judge_id", "?"))
    if getattr(judge, "is_test_double", False) and not getattr(judge, "base_url", None):
        maker = str(getattr(judge, "maker", None) or getattr(judge, "provider", "test-double"))
        return ResolvedIdentity("judge", jid, f"test-double/{jid}", f"test-double/{jid}",
                                f"{IN_PROCESS}:{jid}", frozenset({f"{IN_PROCESS}:{maker}"}), None,
                                frozenset({NO_CREDENTIAL}), getattr(judge, "provider", None))
    model, base_url = getattr(judge, "model", None), getattr(judge, "base_url", None)
    if not isinstance(model, str) or not model or not isinstance(base_url, str) or not base_url:
        raise IdentityError(f"judge {jid!r} declares no model and base_url; Two-Key cannot show it is not "
                            "the monitored agent")
    try:
        fp = _fingerprint(getattr(judge, "credential", None), fp_key)
    except IdentityError as e:
        raise IdentityError(f"judge {jid!r}: {e}") from None
    tenant = validate_tenant(getattr(judge, "tenant", None), f"judge {jid!r}")
    upstream = validate_upstream(getattr(judge, "upstream", None), f"judge {jid!r}")
    # A connector that never sends its credential (auth_header: none, an Ollama judge's default) reaches its
    # address keyless. It still holds that credential, which the same-credential rule compares.
    return _identity("judge", jid, model, base_url, {fp}, getattr(judge, "provider", None), tenant, upstream,
                     sends=getattr(judge, "auth_header", None) != "none")


@dataclass(frozen=True)
class AgentDeclaration:
    """The operator's statement of who the monitored agent is."""

    model: str
    provider: str
    base_url: str
    credential_env: str | None = None
    credential: str | None = None        # only "none", for a keyless loopback or private-address agent
    id: str = "monitored-agent"
    tenant: Mapping[str, str] | None = None   # organization / project / account / deployment, if declared
    upstream: Any = None                      # operator-declared upstream host(s), for a proxy; not verified
    username_env: str | None = None           # HTTP Basic over HTTPS: the variables holding the username
    password_env: str | None = None           # and the password

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "AgentDeclaration":
        if not isinstance(data, Mapping):
            raise IdentityError("monitored_agent must be a mapping")
        extra = set(data) - AGENT_KEYS
        if extra:
            raise IdentityError(f"monitored_agent: unknown key(s) {sorted(extra)}")
        return cls(model=data.get("model"), provider=data.get("provider"), base_url=data.get("base_url"),
                   credential_env=data.get("credential_env"), credential=data.get("credential"),
                   id=data.get("id") or "monitored-agent",
                   username_env=data.get("username_env"), password_env=data.get("password_env"),
                   tenant=validate_tenant(data.get("tenant"), "monitored_agent") or None,
                   upstream=data.get("upstream"))

    def validate(self, *, allow_in_process: bool = False) -> None:
        for name in ("model", "provider", "base_url"):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
                raise IdentityError(f"monitored_agent {self.id!r}: declare {name}")
        u = urlparse(self.base_url)
        if u.scheme == IN_PROCESS:
            if not allow_in_process:
                raise IdentityError("in_process_agent_refused: an in-process monitored agent is for offline tests "
                                    "only: pass allow_test_doubles=True and use test-double judges only")
        elif u.scheme not in ("https", "http") or not u.hostname:
            raise IdentityError(f"monitored_agent {self.id!r}: base_url must be an http(s) URL")
        if self.credential not in (None, NO_CREDENTIAL):
            raise IdentityError("monitored_agent credential may only be 'none'; name the key with credential_env")
        basic = self.username_env is not None or self.password_env is not None
        if [self.credential_env is not None, self.credential is not None, basic].count(True) != 1:
            raise IdentityError(f"monitored_agent {self.id!r}: declare exactly one of credential_env, "
                                "username_env with password_env, or credential: none")
        if basic:
            for name in ("username_env", "password_env"):
                v = getattr(self, name)
                if not isinstance(v, str) or not v.strip() or v.startswith("REPLACE_"):
                    raise IdentityError(f"monitored_agent {self.id!r}: declare {name} (the name of an environment "
                                        "variable) with the other one")
            if u.scheme != "https":
                raise IdentityError(f"monitored_agent {self.id!r}: a username and password are sent only over "
                                    "HTTPS; use an https base_url")
        if self.credential == NO_CREDENTIAL and u.scheme != IN_PROCESS and not host_is_local(u.hostname or ""):
            raise IdentityError(f"monitored_agent {self.id!r}: credential: none is only for a loopback or "
                                "private-address agent; declare credential_env")
        validate_tenant(self.tenant, f"monitored_agent {self.id!r}")
        validate_upstream(self.upstream, f"monitored_agent {self.id!r}")

    def resolve(self, *, allow_in_process: bool = False, fp_key: bytes | None = None) -> ResolvedIdentity:
        self.validate(allow_in_process=allow_in_process)
        try:
            fp = self._fingerprint(fp_key)
        except IdentityError as e:
            raise IdentityError(f"monitored_agent {self.id!r}: {e}") from None
        return _identity("agent", self.id, self.model, self.base_url, {fp}, self.provider,
                         validate_tenant(self.tenant, f"monitored_agent {self.id!r}"),
                         validate_upstream(self.upstream, f"monitored_agent {self.id!r}"))

    def _fingerprint(self, fp_key: bytes | None) -> str:
        if self.username_env is not None:
            from .judges.credentials import BasicAuthCredential, CredentialError
            try:   # the pair, read exactly as a judge's is, so the two fingerprints match
                pair = BasicAuthCredential(self.username_env, self.password_env).get_token()
            except CredentialError as e:
                raise IdentityError(str(e)) from None
            return password_fingerprint(pair, fp_key)
        if self.credential_env is not None:
            value = os.environ.get(self.credential_env) if isinstance(self.credential_env, str) else None
            if not value:
                raise IdentityError(f"credential_env {self.credential_env} is not set")
            return secret_fingerprint(value, fp_key)
        return NO_CREDENTIAL

    def to_record(self) -> dict:
        return {"id": self.id, "model": self.model, "provider": self.provider, "base_url": self.base_url,
                "credential_env": self.credential_env, "credential": self.credential,
                "username_env": self.username_env, "password_env": self.password_env,
                "tenant": dict(self.tenant) if self.tenant else None,
                "upstream": sorted(validate_upstream(self.upstream, "monitored_agent")) or None}


def configured_agent_secrets(sources: Iterable[Any]) -> frozenset[str]:
    """The monitored agent's credentials, re-read now, with surrounding whitespace removed.

    ``credential: none`` contributes nothing. A declared credential that cannot be read raises
    ``IdentityError`` with a fixed message: the value is not included. The caller denies the round.
    Nothing here is stored or written to the ledger.
    """
    found: set[str] = set()
    for source in sources:
        found.update(_one_agent_secret(source))
    return frozenset(secret for secret in (value.strip() for value in found) if secret)


def _one_agent_secret(source: Any) -> set[str]:
    if isinstance(source, Mapping) and not isinstance(source, AgentDeclaration):
        source = AgentDeclaration.from_mapping(source)
    if isinstance(source, AgentDeclaration):
        return _declaration_secret(source)
    credential = getattr(source, "credential", None)
    if credential is None or getattr(credential, "kind", None) == NO_CREDENTIAL:
        return set()
    from .judges.credentials import CredentialError
    try:
        token = credential.get_token()
    except (CredentialError, NotImplementedError, ValueError):
        raise IdentityError("monitored agent credential cannot be read") from None
    if not isinstance(token, str):
        raise IdentityError("monitored agent credential cannot be read")
    return {token}


def _declaration_secret(decl: AgentDeclaration) -> set[str]:
    if decl.credential == NO_CREDENTIAL:
        return set()
    if decl.username_env is not None:
        from .judges.credentials import BasicAuthCredential, CredentialError
        try:
            return {BasicAuthCredential(decl.username_env, decl.password_env).get_token()}
        except CredentialError:
            raise IdentityError("monitored agent credential cannot be read") from None
    if isinstance(decl.credential_env, str):
        value = os.environ.get(decl.credential_env)
        if not value:
            raise IdentityError("monitored agent credential cannot be read")
        return {value}
    raise IdentityError("monitored agent credential cannot be read")


def configured_agent_identity(agent: Any, fp_key: bytes | None = None) -> ResolvedIdentity:
    """A MonitoredAgent from agents.yaml is operator configuration too. An Ollama agent sends no key unless it uses
    Basic auth, so it reaches its address keyless; a key configured for it still counts as the agent's credential
    for the same-credential rule."""
    credential = getattr(agent, "credential", None)
    try:
        fp = _fingerprint(credential, fp_key)
    except IdentityError as e:
        raise IdentityError(f"agent {agent.agent_id!r}: {e}") from None
    unsent = getattr(agent, "kind", None) == "ollama" and getattr(credential, "kind", None) != "basic"
    return _identity("agent", str(agent.agent_id), agent.model, agent.base_url, {fp},
                     getattr(agent, "provider", None),
                     validate_tenant(getattr(agent, "tenant", None), f"agent {agent.agent_id!r}"),
                     validate_upstream(getattr(agent, "upstream", None), f"agent {agent.agent_id!r}"),
                     sends=not unsent)


@dataclass(frozen=True)
class SeparationReport:
    ok: bool
    agents: tuple[ResolvedIdentity, ...]
    judges: tuple[ResolvedIdentity, ...]
    refusals: tuple[str, ...]

    tenant_optin: bool = False                 # deprecated flag, recorded as set; it lifts nothing
    tenant_optin_pairs: tuple[dict, ...] = ()  # always empty now; kept so the ledger record keeps its shape
    warnings: tuple[dict, ...] = ()            # likely accidents that were allowed: agent, judge, check, detail

    def to_record(self) -> dict:
        return {"ok": self.ok, "rule": "judge_is_not_monitored_agent", "same_agent": SEPARATION_RULE,
                "checks": list(SEPARATION_CHECKS), "warning_checks": list(SEPARATION_WARNINGS),
                "same_provider": "allowed",
                "same_model_tenant_optin": self.tenant_optin,
                "same_model_tenant_optin_pairs": list(self.tenant_optin_pairs),
                "refusals": list(self.refusals),
                "warnings": [dict(w) for w in self.warnings],
                "agents": [a.to_record() for a in self.agents],
                "judges": [j.to_record() for j in self.judges]}


TENANT_OPTIN_DEPRECATED = ("two-key: allow_same_model_distinct_tenant is deprecated and has no effect: a judge is "
                           "refused when it uses the monitored agent's credential, at any address")


def _keyed(side: ResolvedIdentity) -> bool:
    """Whether this side sends a credential: the keyless-address rule and its warning look only at this."""
    return side.sends and bool(side.credentials - {NO_CREDENTIAL})


def compare(agent: ResolvedIdentity, judge: ResolvedIdentity, *,
            allow_same_model_distinct_tenant: bool = False) -> str | None:
    """The refusal for one judge against one agent, or None.

    A judge is refused when it holds the monitored agent's credential, at any address (a credential identifies its
    holder): every credential either side holds is compared, sent or not (``secret_fingerprint``).
    It is also refused when it connects to the agent's address with no credential sent on either side, which
    leaves Two-Key nothing to tell them apart by. Any other pairing is allowed; ``separation_warnings`` lists the
    likely accidents among them. ``allow_same_model_distinct_tenant`` is accepted for older callers and ignored."""
    who = f"judge {judge.id!r} vs agent {agent.id!r}"
    if (agent.credentials & judge.credentials) - {NO_CREDENTIAL}:
        unsent = "" if judge.sends and agent.sends else ", held though not sent"
        where = (f"on the same address {judge.endpoint}" if agent.endpoint == judge.endpoint
                 else f"(agent at {agent.endpoint}, judge at {judge.endpoint})")
        return (f"{who}: the same credential{unsent} {where}; a credential identifies its holder at any address. "
                "Give the judge its own credential, or leave the shared one off one side: auth: {type: none} on a "
                "judge, credential: none on the agent (for a placeholder a local server ignores, give each side its "
                "own value)")
    if agent.endpoint != judge.endpoint:
        return None
    if not _keyed(agent) and not _keyed(judge):
        return (f"{who}: the same address {judge.endpoint} and no credential on either side, so Two-Key cannot "
                "tell them apart (give the judge its own endpoint or its own credential)")
    return None


def separation_warnings(agent: ResolvedIdentity, judge: ResolvedIdentity) -> list[dict]:
    """Likely accidents in a pairing that ``compare`` allows. Each is recorded, never refused."""
    out: list[dict] = []

    def add(check: str, detail: str) -> None:
        out.append({"agent": agent.id, "judge": judge.id, "check": check, "detail": detail})

    same_address = agent.endpoint == judge.endpoint
    if same_address and _keyed(agent) != _keyed(judge):
        add("same_address_one_side_keyless",
            f"the same address {judge.endpoint}, and only one side has a credential (a daemon may ignore it)")
    if agent.model and agent.model == judge.model:
        if same_address:
            add("same_model_same_address", f"the same model {judge.model!r} on the same address {judge.endpoint}")
        else:
            via = agent.routes & judge.routes
            if via:
                add("same_model_shared_route", f"the same model {judge.model!r} through {sorted(via)[0]}")
            for side, label in ((judge, "judge"), (agent, "agent")):
                if side.proxy and not side.declared_upstreams:
                    add("same_model_unknown_proxy",
                        f"the same model {judge.model!r} through a local or unrecognized proxy or daemon "
                        f"({label} at {side.endpoint}) with no declared upstream")
                    break
    shared = agent.tenants & judge.tenants
    if shared:
        add("shared_tenant", f"a shared tenant {sorted(shared)[0]}")
    for side, label in ((agent, "agent"), (judge, "judge")):
        if side.unresolved:
            add("unresolved_identity", f"the {label} upstream is unresolved (an unrecognized router or host, or a "
                                       "local proxy with no recognizable model maker; declare upstream:)")
            out[-1]["side"] = label   # about one identity, so check_separation reports it once
    return out


def check_separation(agents: Sequence[ResolvedIdentity], judges: Sequence[ResolvedIdentity],
                     allow_same_provider_judge: bool | None = None, *,
                     allow_same_model_distinct_tenant: bool = False) -> SeparationReport:
    """Refuse any judge that holds the monitored agent's credential, or shares its address with no credential sent
    on either side (``compare``); warn on, and record, the likely accidents.

    ``allow_same_provider_judge`` and ``allow_same_model_distinct_tenant`` are deprecated no-ops; each prints a
    note on stderr when set."""
    if not agents:
        raise IdentityError("monitored_agent_required: declare the monitored agent (monitored_agent: model, provider, base_url, "
                            "and credential_env, username_env with password_env, or credential: none) whenever "
                            "judges are configured")
    if allow_same_provider_judge:
        warn_allow_same_provider_judge()
    optin = allow_same_model_distinct_tenant is True
    if optin:
        print(TENANT_OPTIN_DEPRECATED, file=sys.stderr)
    refusals = [r for a in agents for j in judges if (r := compare(a, j))]
    if refusals:
        raise IdentityError("judge_matches_agent: a judge must not be the monitored agent: " + "; ".join(refusals))
    found, reported = [], set()
    for w in (w for a in agents for j in judges for w in separation_warnings(a, j)):
        if "side" in w:
            key = (w["check"], w["side"], w[w["side"]])
            if key in reported:
                continue
            reported.add(key)
        found.append(w)
    found = tuple(found)
    for w in found:
        print(f"two-key: WARNING: judge {w['judge']!r} vs agent {w['agent']!r}: {w['detail']} ({w['check']}); "
              "allowed and recorded in constitution_loaded", file=sys.stderr)
    return SeparationReport(True, tuple(agents), tuple(judges), (), optin, (), found)


def warn_allow_same_provider_judge() -> None:
    print("two-key: allow_same_provider_judge is deprecated and has no effect: the same provider is allowed "
          "by default; a judge is refused only when it is the same agent", file=sys.stderr)


def load_monitored_agent(data: Mapping[str, Any] | None) -> AgentDeclaration | None:
    """The ``monitored_agent:`` block of a judges config, if present."""
    if not isinstance(data, Mapping) or data.get("monitored_agent") is None:
        return None
    return AgentDeclaration.from_mapping(data["monitored_agent"])


def load_monitored_agent_file(path) -> AgentDeclaration | None:
    from .strict import StrictParseError, load_file_strict
    try:
        data = load_file_strict(path)
    except StrictParseError as e:
        raise IdentityError(f"{path}: {e}") from None
    return load_monitored_agent(data)

# Two-Key how-to

A step-by-step guide to every part of the prototype. For the short
version, see the [README](../README.md#quickstart); for every option in one
place, see the [configuration reference](../README.md#configuration-reference).

Every command and code block in this file was run, top to bottom, by
`tools/doccheck.py` in a copy of the repository with a fresh virtualenv and
an empty HOME. The judges' HTTP calls went to a local fake that answers in
each provider's response format (it approves everything except wire
transfers and medical data). The adapters, prompts, parsing, and quorum
logic are real, but no real model was contacted. Blocks marked *not run*
say why.

## Contents

1. [Install](#1-install)
2. [Keys](#2-keys)
3. [Writing a constitution](#3-writing-a-constitution)
4. [Signing, verifying, loading, and reloading](#4-signing-verifying-loading-and-reloading)
5. [Judges: one entry per provider](#5-judges-one-entry-per-provider)
6. [Auth modes](#6-auth-modes)
7. [Quorum settings](#7-quorum-settings)
8. [Authorizing actions](#8-authorizing-actions)
9. [Gateway integration](#9-gateway-integration)
10. [Ordering and short-circuit](#10-ordering-and-short-circuit)
11. [Revocation](#11-revocation)
12. [The ledger](#12-the-ledger)
13. [Crypto: FIPS mode, classic and hybrid keys, token modes](#13-crypto-fips-mode-classic-and-hybrid-keys-token-modes)
14. [Performance and tests](#14-performance-and-tests)

All commands run from the repository root.

## 1. Install

<!-- check: skip the checker works in a copy of the repository -->
```bash
git clone https://github.com/Insomniac-VibeLabs/two-key.git
cd two-key
```

Create a virtualenv and install the package with its optional extras:
`yaml` (PyYAML, for `.yaml` rules and judge files) and `pq` (`cryptography>=50`,
which provides ML-DSA-65 for hybrid post-quantum keys). Add `keyring` if you
want API keys from the OS keyring. The only hard dependency is
`cryptography>=41`, so classical keys work without the extras.

<!-- check: expect=^ok$ -->
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -q -e ".[yaml,pq]"
python -c "import two_key, cryptography, yaml; print('ok')"
```

## 2. Keys

The principal key signs your constitution and your ledger head. A separate
witness key also signs the head. Choose a
suite:

| Suite | Files | Use when |
|---|---|---|
| `ed25519` (default) | `principal.pem`, `principal.pub.pem` | Simplest; no ML-DSA needed |
| `ecdsa-p384` | `principal.keys.json`, `principal.pub.json` | FIPS modules where Ed25519 isn't approved |
| `hybrid-mldsa65-ed25519` | as above | Post-quantum hybrid: ML-DSA-65 and Ed25519 must both verify |
| `hybrid-mldsa65-p384` | as above | Post-quantum hybrid with a P-384 classical half |

Put the passphrase in an environment variable without echoing it. Every
`keygen` and `sign-constitution` below reads it with `--passphrase-env`.
Without that flag you're prompted interactively.

<!-- check: expect=^fingerprint: ed25519: -->
```bash
read -rsp "Key passphrase: " TWOKEY_KEY_PASSPHRASE; echo; export TWOKEY_KEY_PASSPHRASE
python -m two_key keygen --out ~/.two-key --passphrase-env TWOKEY_KEY_PASSPHRASE
```

A hybrid key goes in its own directory. Keygen refuses to overwrite an
existing key.

<!-- check: expect=^fingerprint: hybrid-mldsa65-ed25519: -->
```bash
python -m two_key keygen --out ~/.two-key-pq --suite hybrid-mldsa65-ed25519 \
    --passphrase-env TWOKEY_KEY_PASSPHRASE
ls ~/.two-key-pq
```

<!-- check: expect=refusing to overwrite -->
<!-- check: expect-fail -->
```bash
python -m two_key keygen --out ~/.two-key --passphrase-env TWOKEY_KEY_PASSPHRASE
```

Private key files are created with mode 0600. Legacy PEM keys are
encrypted by `cryptography`'s best available PKCS#8 scheme; key bundles use
PBKDF2-HMAC-SHA-384 (600,000 iterations) and AES-256-GCM (bundles written
earlier with PBKDF2-HMAC-SHA-256 still load). Load either kind
in Python with `keys.load_private_any` / `keys.load_public_any`.

### Seed-phrase backup (personal mode, optional)

`keygen --seed-phrase` derives the key from a new 24-word BIP-39 phrase and
prints the words once. Write them down offline. Anyone with them can
rebuild the key. Add `--seed-passphrase-prompt` (or
`--seed-passphrase-env VAR`) for an optional BIP-39 passphrase; a
different passphrase gives a different key. The key file is written as
usual, with its own passphrase. See [KEYS_AND_PKI.md](KEYS_AND_PKI.md) for
the derivation.

<!-- check: expect=^SEED PHRASE BACKUP: shown once -->
<!-- check: expect=^ +1\. \w+ +2\. \w+ -->
<!-- check: expect=^fingerprint: ed25519: -->
```bash
python -m two_key keygen --out ~/.two-key-seed --seed-phrase --passphrase-env TWOKEY_KEY_PASSPHRASE
```

To rebuild the key file, pipe the words in (or type them at the hidden
prompt). `--expect-pub` refuses to write unless the result matches the key
you expect. `verify-seed-phrase` writes nothing. The phrase below is the
public BIP-39 test vector; never use it for a real key.

<!-- check: expect=^recovered private key: .*principal.pem -->
<!-- check: expect=^OK: the phrase re-derives ed25519: -->
```bash
PHRASE="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
echo "$PHRASE" | python -m two_key recover-key --out ~/.two-key-vector --passphrase-env TWOKEY_KEY_PASSPHRASE
echo "$PHRASE" | python -m two_key verify-seed-phrase --pub ~/.two-key-vector/principal.pub.pem
```

A wrong or swapped word fails the checksum. Seed phrases are refused in
`fips_mode` and in enterprise mode, which uses PKI (section 12):

<!-- check: expect=^REJECTED: checksum mismatch -->
<!-- check: expect=^REFUSED: seed-phrase backup is disabled in fips_mode -->
<!-- check: expect=^REFUSED: seed-phrase backup is for personal mode only -->
```bash
echo "art abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon " | python -m two_key verify-seed-phrase || true
echo "$PHRASE" | python -m two_key --fips verify-seed-phrase 2>&1 || true
echo "$PHRASE" | python -m two_key verify-seed-phrase --deployment-mode enterprise 2>&1 || true
```

## 3. Writing a constitution

A constitution has two parts, and you sign them together as one document:

- **Prose** for the Path B judges: your values and limits in your own words.
  Be concrete ("never spend more than $200 without asking me"). The judges
  read only this and the action record.
- **Hard rules** for Path A, in a fenced block whose info string is
  `twokey-rules`, containing JSON: a list of rules, or `{"hard_rules": [...]}`.
  The document must contain **exactly one** such block. Other code blocks
  count as prose.

<!-- check: file=my-constitution.md -->
````markdown
# My constitution

I am the principal. The agent works for me, not for the model vendor.

- Never spend more than $200 without my live confirmation.
- Never send medical or classified data anywhere.
- Never wire money. Paying known utility bills is fine.
- Prefer reversible actions.

```twokey-rules
{"hard_rules": [
  {"id": "tool-allowlist", "allow_only_tools": ["search", "email_draft", "pay_bill", "summarize"]},
  {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
  {"id": "no-sensitive-data", "deny_if": {"data_class_in": ["medical", "classified"]}},
  {"id": "spend-cap", "deny_if": {"amount_usd_gt": 200}},
  {"id": "irreversible-cap", "deny_if_irreversible_over": 50},
  {"id": "blocked-parties", "deny_counterparties": ["offshore-mule.example"]}
]}
```
````

### Rule types

| Rule | Value | The action is denied when |
|---|---|---|
| `allow_only_tools` | list of tool names | its `tool` isn't listed. **Required**: at least one allow-list rule, so unknown tools fail closed |
| `deny_counterparties` | list of names | its `counterparty` is listed |
| `deny_if` | any of `tool`, `amount_usd_gt`, `data_class_in`, `irreversible` | **all** the conditions you give hold (AND) |
| `deny_if_irreversible_over` | number ≥ 0 | `irreversible` is true and `amount_usd` exceeds the number |

An optional `id` names the rule in deny reasons (`rule_denied:spend-cap`);
ids must be unique. Rules are checked in order, and the first failing rule
is reported. Strings are trimmed and case-folded. Unknown rule types or
keys, wrong value types, empty lists, and unknown data classes are
rejected when you sign, so a typo can't silently weaken a rule.

### The action record Path A reads

Path A never sees prose. It evaluates a normalized record:

| Field | Missing means | Values |
|---|---|---|
| `tool` | (required) | tool name |
| `amount_usd` | `0` | 0 … 1e12 (negative is rejected) |
| `counterparty`, `destination`, `currency` | `""`, `""`, `"usd"` | strings |
| `data_class` | `classified` | `public`, `personal`, `medical`, `financial`, `classified` |
| `irreversible` | `true` | boolean |
| `duration_hours` | `0` | 0 … 1e6 |
| `tags`, `raw` | `[]`, `{}` | logged, never read by Path A |

The missing-field defaults are deliberately conservative: an action that
doesn't say it is reversible is treated as irreversible, and one that
doesn't give a data class is treated as classified. **Who fills in this
record** (the proposing model, deterministic extractors, a classifier) is
an open design question (`DESIGN_OPTIONS.md` §1, "F"). The prototype takes
it from the caller, and the gateway can re-derive scope fields from the
literal arguments (§9).

Signing checks the rules, so mistakes surface immediately:

<!-- check: expect=no allow_only_tools rule -->
<!-- check: expect-fail -->
```bash
printf 'Be careful.\n\n```twokey-rules\n[{"deny_if": {"tool": "wire_transfer"}}]\n```\n' > bad.md
python -m two_key sign-constitution --document bad.md --principal did:twokey:alice \
    --key ~/.two-key/principal.pem --passphrase-env TWOKEY_KEY_PASSPHRASE --out bad.signed.json
```

### The two-file format

You can instead keep the prose and the rules in separate files (format
`/1`): `--text` takes `.txt`/`.md`/`.markdown` (up to 1 MB) and `--rules`
takes `.json`/`.yaml`/`.yml`. Both forms are signed as one document, and
both produce the same compiled hashes for the same prose and rules.

<!-- check: expect=^OK: principal=did:twokey:alice -->
```bash
python -m two_key sign-constitution --text examples/constitution.md \
    --rules examples/hard_rules.yaml --principal did:twokey:alice \
    --key ~/.two-key/principal.pem --passphrase-env TWOKEY_KEY_PASSPHRASE \
    --out two-file.signed.json
python -m two_key verify-constitution --signed two-file.signed.json \
    --pub ~/.two-key/principal.pub.pem
```

## 4. Signing, verifying, loading, and reloading

<!-- check: expect=^OK: principal=did:twokey:alice created_at=.* rules=6 bytecode=\d+ -->
```bash
python -m two_key sign-constitution --document my-constitution.md \
    --principal did:twokey:alice --key ~/.two-key/principal.pem \
    --passphrase-env TWOKEY_KEY_PASSPHRASE --out my-constitution.signed.json
python -m two_key verify-constitution --signed my-constitution.signed.json \
    --pub ~/.two-key/principal.pub.pem
```

Any change after signing is caught. So is a signature from a different key
(for example, a vendor's) and a suite downgrade:

<!-- check: expect=^REJECTED: signature does not match -->
<!-- check: expect-fail -->
```bash
sed 's/\$200/$20000/' my-constitution.signed.json > tampered.signed.json
python -m two_key verify-constitution --signed tampered.signed.json \
    --pub ~/.two-key/principal.pub.pem
```

<!-- check: expect=downgrade refused -->
<!-- check: expect-fail -->
```bash
python -m two_key verify-constitution --signed my-constitution.signed.json --pub ~/.two-key-pq/principal.pub.json
```

When Two-Key loads a constitution, it compiles the one signed document
twice: the rules become Path A bytecode, after a static check that the
bytecode reads only structured fields, and the prose becomes the judges'
text. Both hashes (`bytecode_hash`, `nl_hash`) are recorded in the ledger's
`constitution_loaded` entry and bound into every ballot and token.

The rest of this guide builds TwoKey instances with this small helper. Copy it
into your own project and adapt the paths.

<!-- check: file=my_two_key.py -->
```python
"""my_two_key.py: build a TwoKey from the files created in this guide."""
import os
from pathlib import Path

from two_key import keys
from two_key.constitution import load_envelope
from two_key.judges.config import load_config_file
from two_key.core import TwoKey

HOME = Path.home() / ".two-key"


def load_key():
    return keys.load_private_any(HOME / "principal.pem", os.environ["TWOKEY_KEY_PASSPHRASE"].encode())


def make_two_key(ledger="ledger.jsonl", judges_file="judges.yaml",
                constitution="my-constitution.signed.json", **options):
    judges, quorum = load_config_file(Path(judges_file))
    options.setdefault("quorum_policy", quorum)
    # A cloud judge must not reuse the monitored agent's credential. Two-Key
    # reads TWOKEY_AGENT_SESSION once, here, and refuses to start without it.
    if any(getattr(j, "is_cloud", lambda: False)() for j in judges):
        options.setdefault("agent_session_env", "TWOKEY_AGENT_SESSION")
    return TwoKey(load_envelope(Path(constitution)), keys.load_public_any(HOME / "principal.pub.pem"),
                         HOME / ledger, judges, ledger_signing_key=load_key(), **options)
```

It needs a `judges.yaml`. Section 5 explains every option; for now:

<!-- check: file=judges.yaml -->
```yaml
quorum: {required_yes: 2, min_responding: 2}
judges:
  - {id: grok, type: openai_compatible, provider: xai, base_url: "https://api.x.ai/v1",
     model: "<xai-model-name>", auth: {type: env, var: XAI_API_KEY}}
  - {id: claude, type: anthropic, provider: anthropic, model: "<anthropic-model-name>",
     auth: {type: env, var: ANTHROPIC_API_KEY}}
  - {id: local, type: ollama, provider: local, vendor: alibaba, model: "qwen2.5:7b"}
```

The xAI and Anthropic judges are cloud judges. Two-Key will not start until
`TWOKEY_AGENT_SESSION` holds the monitored agent's own credential, and that
value must not be one of the judge keys. The helper passes
`agent_session_env="TWOKEY_AGENT_SESSION"` when any judge is not local.

<!-- check: expect=^loaded two-key-constitution/2 -->
```bash
read -rsp "xAI API key: " XAI_API_KEY; echo; export XAI_API_KEY
read -rsp "Anthropic API key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
export TWOKEY_AGENT_SESSION=monitored-agent-not-a-judge-key
python - <<'PY'
from my_two_key import make_two_key
tk = make_two_key("howto-4.jsonl")
print("loaded", tk.compiled.source_format, "bytecode_hash", tk.compiled.bytecode_hash[:16],
      "nl_hash", tk.compiled.nl_hash[:16])
PY
```

**Reloading.** `reload_constitution` accepts only a document signed by the
same trusted key and naming the same principal. A change to the text or the
rules also needs `acknowledge=True`: that is a separate step from the
agent's request. After a successful reload, tokens issued earlier are
refused by the gateway. A refused reload leaves the active constitution in
place and is logged as `constitution_reload_refused`.

<!-- check: expect=^old token: constitution_hash_mismatch -->
<!-- check: expect=^vendor reload refused: ConstitutionSignatureError -->
<!-- check: expect=constitution_reload_refused -->
```python
from pathlib import Path
from two_key import keys
from two_key.constitution import build_source_document, sign_document
from my_two_key import load_key, make_two_key

tk = make_two_key("howto-4b.jsonl")
gw = tk.gateway(tools={"pay_bill": lambda payee, amount: "paid"})
args = {"payee": "power-co.example", "amount": 30}
fields = {"amount_usd": 30, "counterparty": "power-co.example", "data_class": "financial"}
d = tk.authorize({"tool": "pay_bill", **fields, "irreversible": False}, "Pay the power bill.", args)

# The principal tightens the spend cap and signs the new version.
src = Path("my-constitution.md").read_text().replace('"amount_usd_gt": 200', '"amount_usd_gt": 100')
tk.reload_constitution(sign_document(build_source_document("did:twokey:alice", src), load_key()),
                      acknowledge=True)
print("old token:", gw.invoke(d.capability, "pay_bill", args, fields).reason)

# A vendor tries to push its own version.
vendor_key = keys.generate_private_key()
try:
    tk.reload_constitution(sign_document(build_source_document("did:twokey:alice", src), vendor_key))
except Exception as e:
    print("vendor reload refused:", type(e).__name__, e)
print("last ledger entry:", tk.ledger.entries[-1].kind)
```

If the reloaded document compiles to exactly the same hashes (the same
bytes re-loaded), the gateway's reason is `constitution_changed_since_issue`
instead.

## 5. Judges: one entry per provider

`judges.yaml` (or `.json`) lists the judges and the quorum. The loader
rejects unknown keys, duplicate ids, `REPLACE_…` model placeholders, and
secrets written into the file. It does not check that a model name exists;
a wrong one shows up at run time as an abstaining ballot with `http 404`.

<!-- check: file=judges-all.yaml -->
```yaml
quorum:
  required_yes: 3
  min_responding: 4
judges:
  # OpenAI-compatible Chat Completions: xAI, OpenAI, and local servers (vLLM,
  # llama.cpp server, LM Studio, Ollama's /v1). base_url is the API root that
  # serves /chat/completions.
  - id: grok
    type: openai_compatible
    provider: xai
    base_url: https://api.x.ai/v1
    model: <xai-model-name>
    auth: {type: env, var: XAI_API_KEY}
  - id: gpt
    type: openai_compatible
    provider: openai
    base_url: https://api.openai.com/v1
    model: <openai-model-name>
    auth: {type: env, var: OPENAI_API_KEY}
    json_mode: true          # default; sends response_format={"type": "json_object"}
    max_tokens: 300          # default
  - id: lan-vllm
    type: openai_compatible
    provider: my-vllm
    vendor: meta             # who made the weights, for min_vendors
    local_weights: true      # runs from weights you control
    base_url: http://127.0.0.1:8000/v1   # loopback may use plain HTTP
    model: <served-model-name>
    auth_header: none        # no credential header
  # Anthropic Messages API (base_url defaults to https://api.anthropic.com)
  - id: claude
    type: anthropic
    provider: anthropic
    model: <anthropic-model-name>
    auth: {type: env, var: ANTHROPIC_API_KEY}
    timeout: 20              # per-request seconds (default 30)
  # Google Gemini (base_url defaults to https://generativelanguage.googleapis.com)
  - id: gemini
    type: gemini
    provider: google
    model: <gemini-model-name>
    auth: {type: env, var: GEMINI_API_KEY}
  # Local Ollama (native /api/chat; base_url defaults to http://localhost:11434)
  - id: llama-local
    type: ollama
    provider: local
    model: <ollama-model-name>
    weights_sha256: <sha256-of-the-weights-file>   # optional; recorded, not verified
```

<!-- check: expect=^OK: 6 judges; required_yes=3 min_responding=4 -->
```bash
python -m two_key check-judges --config judges-all.yaml
```

Notes per provider:

- **openai_compatible** requires `base_url`. The credential is sent as
  `Authorization: Bearer …` (`auth_header: bearer`). `json_mode` applies
  only here; `max_tokens` applies here and to `anthropic`.
- **anthropic** sends `x-api-key` and `anthropic-version: 2023-06-01`.
- **gemini** sends `x-goog-api-key` and asks for a JSON response.
- **ollama** sends no credential by default and is marked
  `local_weights: true`. Set `local_weights: false` if your Ollama serves
  a remote or cloud model. The recommended model name is `qwen2.5:7b`
  (see below).

Call shape, without a vendor SDK. Streaming is not used: the ballot is one
short JSON object, and a partial stream is not a ballot. The default
transport reuses a connection per thread and origin, does not follow
redirects, and retries a dropped connection or HTTP 429/502/503/504 at most
twice inside the judge timeout. A 401 is not retried.

- **openai_compatible** on `api.openai.com` and `api.x.ai` sends
  `response_format: json_schema` (strict ballot schema, no extra keys) when
  `response_format` is omitted or `auto`. xAI also gets `reasoning_effort: low`
  unless you set `reasoning_effort`. OpenAI gets `store: false`. A 400 falls
  back once to `json_object` with those knobs removed. Any other host stays
  on `json_object`, so llama.cpp, vLLM, and LM Studio are unchanged. Set
  `response_format: json_schema` to force the schema, or `json_object` to
  force the old mode. A ballot key (`ballot_key_env`) keeps `json_object`,
  because the optional MAC is outside the closed schema.
- **anthropic** marks the system prompt and the constitution with
  `cache_control: {type: ephemeral}`. The action record and proposal are
  after that breakpoint, so they are not part of the cached prefix. No
  `anthropic-beta` header. A short constitution misses the cache and still
  runs. A 400 strips the breakpoints and retries once.
- **gemini** sends `responseSchema` for the ballot. A 400 drops it and
  retries once with JSON mime type only.
- **ollama** sends `keep_alive: 10m` and `stream: false`, so the weights
  stay loaded between ballots.
- `https://` is required except for loopback hosts (`localhost`,
  `127.0.0.1`, `::1`). For a LAN server over plain HTTP, set
  `allow_insecure_http: true`; that sends prompts unencrypted.
- `vendor` defaults to `provider`. Set it to the model's maker when a
  reseller or proxy fronts someone else's model, so vendor-diversity
  checks count the right thing.

Every judge gets a system prompt telling it that the action record is
untrusted data. It must answer with exactly `{"consistent": bool,
"confidence": 0..1, "rationale": str}`. Anything else (prose, code fences,
extra keys, wrong types) is an abstention, and so are HTTP errors,
credential errors, and timeouts.

### Recommended local judge: Qwen2.5-7B-Instruct

This is a recommendation, not a dependency. Two-Key does not download or
ship the weights. [Qwen2.5-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct)
(Apache-2.0, Copyright 2024 Alibaba Cloud) is the local model that best
matches the ballot parser: Ollama asks for JSON at temperature 0, the
model is trained to emit JSON and to keep the system role when untrusted
text tries to override it, and Alibaba is a different vendor from the
cloud judges in the example. A ballot that is not exactly the three keys
above abstains, so a specialist judge that emits `<feedback>` and
`<score>` tags will not count. Qwen3 thinking models have the same
problem if a reasoning trace leaks into the reply.

`qwen2.5:3b` is the smaller fallback (about 2 GB at Q4). Below 3B, expect
more abstentions. Record `weights_sha256` if you want the ballot to name
the file you pulled; Two-Key stores the hash and does not check it.

These commands need Ollama and a weight download, so the doc checker
skips them. *Not run:* no network, and no Ollama in the sandbox.

<!-- check: skip needs Ollama and a weight download; not run by doccheck -->
```bash
# Install Ollama from https://ollama.com, then pull the recommended model.
ollama pull qwen2.5:7b
ollama show qwen2.5:7b --modelfile
```

<!-- check: file=judges-qwen.yaml -->
```yaml
quorum:
  required_yes: 2
  min_responding: 2
  min_vendors: 2
  min_local_judges: 1
judges:
  - id: grok
    type: openai_compatible
    provider: xai
    base_url: https://api.x.ai/v1
    model: <xai-model-name>
    auth: {type: env, var: XAI_API_KEY}
  - id: claude
    type: anthropic
    provider: anthropic
    model: <anthropic-model-name>
    auth: {type: env, var: ANTHROPIC_API_KEY}
  - id: local-qwen
    type: ollama
    provider: local
    vendor: alibaba
    base_url: http://localhost:11434
    model: qwen2.5:7b
    local_weights: true
    # weights_sha256: <sha256 of the GGUF>   # optional; recorded, not verified
```

<!-- check: expect=^OK: 3 judges; required_yes=2 min_responding=2 -->
```bash
python -m two_key check-judges --config judges-qwen.yaml
```

To serve the same Hugging Face weights yourself, use `openai_compatible`
against a loopback vLLM or llama.cpp server instead of `ollama`. Set
`local_weights: true` and `vendor: alibaba`. The model id is whatever that
server reports, often `Qwen/Qwen2.5-7B-Instruct`. Keep the license file
next to any copy of the weights you redistribute. Do not commit the
weights to this repository.

**Writing your own judge.** Subclass `Judge` and return a `Ballot`. A
judge that raises is recorded as an abstention.

<!-- check: expect=^custom judge: yes -->
```python
from two_key.action import normalize_action
from two_key.judges.base import Ballot, Judge


class KeywordJudge(Judge):
    """Example only: votes no if the constitution text forbids the tool by name."""
    def __init__(self, judge_id="keyword"):
        self.judge_id, self.provider = judge_id, "in-house"

    def score(self, constitution_text, action, proposal):
        bad = f"never use {action.tool}" in constitution_text.lower()
        return Ballot(self.judge_id, self.provider, "no" if bad else "yes", 0.6, "keyword check")


b = KeywordJudge().score("Never use wire_transfer.", normalize_action({"tool": "pay_bill"}), "")
print("custom judge:", b.vote)
```

## 6. Auth modes

`auth:` says where a judge's credential comes from. Secrets never go in the
file; a `key`, `api_key`, `password`, `token`, or `secret` field is
refused. Credentials are read at call time, never logged, and redacted in
`repr()`.

<!-- check: file=my_hooks.py -->
```python
"""my_hooks.py: auth hooks referenced from judges.yaml as "my_hooks:<function>"."""
import os


def get_sso_token():
    """callback hook: return a current bearer token from your SSO client.
    Replace this with a call to your identity provider's SDK or token cache."""
    return os.environ["MY_SSO_TOKEN"]
```

<!-- check: file=judges-auth.yaml -->
```yaml
quorum: {required_yes: 1}
judges:
  - id: env-key            # API key from an environment variable (working)
    type: openai_compatible
    base_url: https://api.x.ai/v1
    model: <xai-model-name>
    auth: {type: env, var: XAI_API_KEY}
  - id: keyring-key        # API key from the OS keyring (working; pip install keyring)
    type: anthropic
    model: <anthropic-model-name>
    auth: {type: keyring, service: two-key, username: anthropic}
  - id: sso                # bearer token from your SSO hook (working hook)
    type: openai_compatible
    base_url: https://llm-gateway.example.com/v1
    model: <model-name>
    auth: {type: callback, callback: "my_hooks:get_sso_token"}
```

<!-- check: expect=^OK: 3 judges -->
```bash
python -m two_key check-judges --config judges-auth.yaml
```

To store a key in the OS keyring:

<!-- check: skip needs an interactive OS keyring backend, which the check sandbox doesn't have -->
```bash
pip install keyring
keyring set two-key anthropic      # prompts for the secret
```

The stubs fail closed. A judge whose credential can't be obtained
abstains, and the reason is recorded:

<!-- check: expect=^sso: yes -->
<!-- check: expect=^keyring-key: abstain credential: -->
```bash
MY_SSO_TOKEN=example-token python - <<'PY'
from pathlib import Path
from two_key.action import normalize_action
from two_key.judges.config import load_config_file

judges, _ = load_config_file(Path("judges-auth.yaml"))
action = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
for j in judges:
    # A cloud judge will not vote without the monitored agent's own credential,
    # and that credential must not be the judge's key.
    b = j.score_bound("Searching the web is fine.", action, "", None,
                      agent_session="monitored-agent-not-a-judge-key")
    print(f"{j.judge_id}: {b.vote} {b.error or ''}"[:110])
PY
```

The username/password and device-code auth types are rejected. A real login
is a `callback` hook.

## 7. Quorum settings

Path B passes only if all of these hold, checked in this order:

1. The judge set meets `min_vendors` and `min_local_judges` (checked at
   Two-Key start, at config load, and on every convene).
2. At least `required_yes` judges are configured.
3. At least **K** = `min_responding` judges returned a valid yes/no ballot.
   Otherwise the result is a deny *without counting*.
4. With `heterogeneity_scope: responding`, the judges that responded also
   meet the two floors.
5. The valid ballots come from at least `min_distinct_providers` provider
   labels.
6. At least **T** = `required_yes` of them say yes.

Here are the outcomes, shown with fixed-vote test doubles
(`two_key.testing`; never use them in production):

<!-- check: expect=^T=2, one yes, two abstain\s+-> False insufficient_responses:1<2 counted=False -->
<!-- check: expect=^K=3 > valid ballots\s+-> False insufficient_responses:2<3 counted=False -->
<!-- check: expect=^T=2, one yes, two no\s+-> False insufficient_yes:1<2 counted=True -->
<!-- check: expect=^section4, no local judge\s+-> False judge_set_not_heterogeneous:insufficient_local_judges:0<1 -->
<!-- check: expect=^section4, satisfied\s+-> True quorum_pass counted=True -->
<!-- check: expect=^local judge abstained\s+-> False responding_not_heterogeneous -->
```python
from two_key.action import normalize_action
from two_key.quorum import QuorumPolicy, convene
from two_key.testing import FixedJudge as J

action = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
cases = {
    "T=2, one yes, two abstain": (QuorumPolicy(required_yes=2),
                                  [J("a", "yes"), J("b", "abstain"), J("c", "abstain")]),
    "K=3 > valid ballots": (QuorumPolicy(required_yes=2, min_responding=3),
                            [J("a", "yes"), J("b", "yes"), J("c", "abstain")]),
    "T=2, one yes, two no": (QuorumPolicy(required_yes=2), [J("a", "yes"), J("b", "no"), J("c", "no")]),
    "section4, no local judge": (QuorumPolicy.section4(), [J("a", "yes", "xai"), J("b", "yes", "anthropic")]),
    "section4, satisfied": (QuorumPolicy.section4(),
                            [J("a", "yes", "xai"), J("b", "yes", "anthropic"),
                             J("c", "yes", "local", local_weights=True)]),
    "local judge abstained": (QuorumPolicy.section4(heterogeneity_scope="responding"),
                              [J("a", "yes", "xai"), J("b", "yes", "anthropic"),
                               J("c", "abstain", "local", local_weights=True)]),
}
for name, (policy, judges) in cases.items():
    q = convene(judges, "Searching is fine.", action, "", policy)
    print(f"{name:<26} -> {q.passed} {q.reason} counted={q.counted} yes={q.yes} valid={q.valid}")
```

### The stricter profile: `QuorumPolicy.section4()`

`QuorumPolicy.section4(required_yes=2, min_responding=None, **overrides)`
sets `min_vendors=2`, `min_local_judges=1`, `judge_inputs="record_only"`,
and `require_path_a_first=True`. These are the mechanisms the author selected
from `PRIOR_ART.md` §4 (iii). They are not the general default, because
which default to use is still open (`DESIGN_OPTIONS.md` §7). In YAML, write
the keys out. Two-Key refuses to start, and `check-judges` reports
INVALID, if the judge set can't meet them:

<!-- check: file=judges-strict.yaml -->
```yaml
quorum:
  required_yes: 2           # T
  min_responding: 3         # K
  min_vendors: 2
  min_local_judges: 1
  heterogeneity_scope: responding
  judge_inputs: record_only
  ballot_binding: echo      # every judge must echo the ballot hashes
  require_path_a_first: true
  timeout_seconds: 30
  parallel: true
judges:
  - {id: grok, type: openai_compatible, provider: xai, base_url: "https://api.x.ai/v1",
     model: "<xai-model-name>", auth: {type: env, var: XAI_API_KEY}, echo_binding: true}
  - {id: claude, type: anthropic, provider: anthropic, model: "<anthropic-model-name>",
     auth: {type: env, var: ANTHROPIC_API_KEY}, echo_binding: true}
  - {id: local, type: ollama, provider: local, model: "<ollama-model-name>", echo_binding: true}
```

<!-- check: expect=^OK: 3 judges; required_yes=2 min_responding=3 -->
```bash
python -m two_key check-judges --config judges-strict.yaml
```

<!-- check: expect=insufficient_local_judges:0<1 -->
<!-- check: expect-fail -->
```bash
grep -v "id: local" judges-strict.yaml > judges-no-local.yaml
python -m two_key check-judges --config judges-no-local.yaml
```

### Ballot binding

Every ballot is bound to H(normalized action record), H(constitution), and
the two compilation hashes. With `ballot_binding: stamp` (the default), the
convenor attaches the binding to each ballot. With `ballot_binding: echo`,
each LLM judge (with `echo_binding: true`) gets the two hashes in its prompt
and must return them as two extra JSON keys. A ballot that doesn't echo
them, or echoes different ones, is an abstention. This run goes through the
real prompt and parser against the fake HTTP judges:

<!-- check: expect=^True dual_path_pass -->
<!-- check: expect=bindings: \['echo', 'echo', 'echo'\] -->
```python
from my_two_key import make_two_key

tk = make_two_key("howto-7.jsonl", judges_file="judges-strict.yaml")
d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "Look up the weather.", {})
print(d.allowed, d.reason)
q = next(e for e in reversed(tk.ledger.entries) if e.kind == "quorum_result").body
print("bindings:", [b["binding"] for b in q["ballots"]])
```

### What judges see (`judge_inputs`)

`record_only` (the default) sends the prose and the normalized action
record. `record_and_proposal` also sends the proposing model's text. That
text can carry injected instructions, so it's opt-in. The proposal is
always written to the ledger either way.

### Timeouts and parallelism

`timeout_seconds` (default 45, or `null` for none) is one overall deadline
for all judges together. Judges run in parallel daemon threads
(`parallel: true`). A judge that misses the deadline is an abstention, so
a hung provider can't produce a yes or hold up the decision. Each LLM judge
also has its own HTTP `timeout` (default 30 s).

<!-- check: expect=^slow: abstain timeout: no ballot within 0.5s -->
<!-- check: expect=^elapsed under 1s: True -->
```python
import time
from two_key.action import normalize_action
from two_key.judges.base import Ballot, Judge
from two_key.quorum import QuorumPolicy, convene


class SlowJudge(Judge):
    def __init__(self):
        self.judge_id, self.provider = "slow", "example"

    def score(self, text, action, proposal):
        time.sleep(3)
        return Ballot(self.judge_id, self.provider, "yes", 0.9, "late")


class QuickJudge(SlowJudge):
    def __init__(self, i):
        self.judge_id, self.provider = f"quick-{i}", "example"

    def score(self, text, action, proposal):
        return Ballot(self.judge_id, self.provider, "yes", 0.9, "fast")


t = time.monotonic()
q = convene([SlowJudge(), QuickJudge(1), QuickJudge(2)], "Fine.", normalize_action({"tool": "search"}), "",
            QuorumPolicy(required_yes=2, timeout_seconds=0.5))
for b in q.ballots:
    print(f"{b.judge_id}: {b.vote} {b.error or ''}")
print("elapsed under 1s:", time.monotonic() - t < 1, "| passed:", q.passed)
```

## 8. Authorizing actions

A monitored agent may be local or cloud-hosted. Vendor control does not put
it inside the constitution. List the agents in `examples/agents.yaml` (xAI,
OpenAI, Anthropic, Gemini, Ollama, or another OpenAI-compatible server) and
call `authorize_from_agent`. That sends the constitution and one instruction, both fenced and escaped, to the named agent, then authorizes the reply. It does not call
the gateway. A cloud agent receives the constitution text. The instruction
is not written to the ledger; a failed call records its digest and length.
Plain HTTP is refused except on loopback. OpenAI and xAI get a proposal schema and xAI gets `reasoning_effort: low`; a 400 falls back once. Credentials are read once at startup so a later environment change cannot hide reuse.

<!-- check: skip needs model names and a constructed TwoKey; covered by tests/test_agents.py -->
```python
from two_key.agents import load_agents_file
agents = load_agents_file("examples/agents.yaml")  # after replacing model names
# pass agents=agents to TwoKey. A cloud agent credential must differ from every judge credential.
decision = tk.authorize_from_agent("grok", "Draft a payment of 42.50 to power-co.example")
```


`tk.authorize(action, proposal, tool_args)` takes the normalized action
record, the proposing model's text, and the literal tool-call arguments.
It returns a `Decision`:

| Field | Meaning |
|---|---|
| `allowed`, `reason` | `True`, `"dual_path_pass"`, or a deny reason (`invalid_action:…`, `path_a_denied:rule_denied:<id>`, `path_b_denied:<quorum reason>`, `internal_error:…`) |
| `vm_allowed`, `vm_reason`, `denied_by_rule` | Path A result |
| `quorum_passed`, `quorum` | Path B result and tally (`None` if Path B was skipped) |
| `capability`, `token_payload` | The token (a bearer secret) and its payload, only when allowed |
| `ledger_digest` | Ledger head after the decision |

Any exception inside `authorize` is a deny; nothing fails open.

<!-- check: expect=^pay \$30 bill\s+True dual_path_pass -->
<!-- check: expect=^wire money\s+False path_a_denied:rule_denied:tool-allowlist -->
<!-- check: expect=^pay \$500 bill\s+False path_a_denied:rule_denied:spend-cap -->
<!-- check: expect=^irreversible \$80\s+False path_a_denied:rule_denied:irreversible-cap -->
<!-- check: expect=^no data_class\s+False path_a_denied:rule_denied:no-sensitive-data -->
<!-- check: expect=^unknown field\s+False invalid_action:unknown action fields -->
```python
from my_two_key import make_two_key

tk = make_two_key("howto-8.jsonl")
bill = {"tool": "pay_bill", "counterparty": "power-co.example", "data_class": "financial", "irreversible": False}
cases = {
    "pay $30 bill": {**bill, "amount_usd": 30},
    "wire money": {**bill, "tool": "wire_transfer", "amount_usd": 30},
    "pay $500 bill": {**bill, "amount_usd": 500},
    "irreversible $80": {**bill, "amount_usd": 80, "irreversible": True},
    "no data_class": {"tool": "search", "irreversible": False},   # defaults to classified
    "unknown field": {**bill, "urgency": "high"},
}
for name, action in cases.items():
    d = tk.authorize(action, f"Please {name}.", {"note": name})
    print(f"{name:<18} {d.allowed} {d.reason}")
```

`wire_transfer` is denied by `tool-allowlist`, not `no-wires`: it isn't on
the allow-list, and rules are checked in order. Keeping the explicit
`no-wires` rule still helps, because it keeps denying wires if someone later
adds `wire_transfer` to the allow-list.

## 9. Gateway integration

The gateway is the only component that should hold real tool credentials
and run tools. Create it with `tk.gateway()` so it shares the TwoKey
instance's token key and ledger.

The gateway reads the caller's arguments once, into immutable bytes (the
typed `two-key-enc/2` encoding). It hashes those bytes for the token check
and runs the tool with a fresh copy decoded from them. A caller can't
change what runs after the check, by mutating its object or by handing
over a mapping that answers differently the second time. Arguments may be
`dict` (string keys only), `list`, `tuple`, `str`, `int`, `float`, `bool`,
and `None`. Anything else is denied as `invalid_call:`. A tuple and a list
are different values: a token for one doesn't match a call with the other.

<!-- check: expect=^1 wrong args\s+args_mismatch -->
<!-- check: expect=^2 other tool\s+tool_mismatch -->
<!-- check: expect=^3 caller lies about amount\s+invalid_call:declared call fields disagree with extractor -->
<!-- check: expect=^4 correct call\s+executed paid 42.5 to power-co.example -->
<!-- check: expect=^5 same token again\s+replayed -->
<!-- check: expect=^6 after TTL\s+expired -->
```python
import time
from my_two_key import make_two_key

tk = make_two_key("howto-9.jsonl", ttl_seconds=1)


def pay_bill(payee, amount):
    return f"paid {amount} to {payee}"


def pay_bill_fields(args):          # extractor: derive the scope fields from the literal args
    return {"amount_usd": args["amount"], "counterparty": args["payee"], "data_class": "financial"}


gw = tk.gateway(tools={"pay_bill": pay_bill}, extractors={"pay_bill": pay_bill_fields})
args = {"payee": "power-co.example", "amount": 42.5}
d = tk.authorize({"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example",
                 "data_class": "financial", "irreversible": False}, "Pay the electric bill.", args)
steps = [  # (label, tool, args, call_fields declared by the caller)
    ("1 wrong args", "pay_bill", {"payee": "power-co.example", "amount": 4250}, None),
    ("2 other tool", "email_draft", args, {"data_class": "financial"}),
    ("3 caller lies about amount", "pay_bill", args, {"amount_usd": 1, "counterparty": "power-co.example",
                                                      "data_class": "financial"}),
    ("4 correct call", "pay_bill", args, None),
    ("5 same token again", "pay_bill", args, None),
]
for name, tool, a, fields in steps:
    r = gw.invoke(d.capability, tool, a, fields)
    print(f"{name:<27} {r.reason} {r.result or ''}")

d = tk.authorize({"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example",
                 "data_class": "financial", "irreversible": False}, "Pay the electric bill.", args)
time.sleep(1.1)
print(f"{'6 after TTL':<27} {gw.invoke(d.capability, 'pay_bill', args).reason}")
```

Denied calls don't use up the token, which is why step 4 still works. In
step 3 the extractor derives the amount from the literal arguments, so a
caller can't declare a smaller one. The token is bound to the exact
arguments (`args_hash`), so changing any argument gives `args_mismatch`.
`amount_exceeds_scope`, `counterparty_mismatch`, and `data_class_mismatch`
apply when the scope fields come from `call_fields` and they differ from
the authorized scope.

**How to call it.** `gateway.invoke(token, tool, args, call_fields=None)`
returns `GatewayResult(allowed, reason, result)`. For each call the gateway
needs the scope fields (`amount_usd`, `counterparty`, `data_class`). They
come from a registered extractor, or from `call_fields` you pass. If both
are present they must agree. Missing fields take the conservative defaults,
so a call that doesn't state its data class is treated as `classified`.
Counterparty and data class must equal the token's scope exactly, and the
amount must not exceed it.

**Checks, in order**, each with its deny reason:

| Check | Deny reason |
|---|---|
| token format, tag, expiry | `malformed_token`, `unsupported_token_version`, `bad_signature`, `expired` |
| call fields valid | `invalid_call:…` |
| principal, tool, literal args hash | `wrong_principal`, `tool_mismatch`, `args_mismatch` |
| amount, counterparty, data class vs scope | `amount_exceeds_scope`, `counterparty_mismatch`, `data_class_mismatch` |
| the ledger still contains the gateway's last-known view | `ledger_fork_detected` |
| the token's chain digest is a known entry | `unknown_ledger_root` |
| the token's Merkle root is the view or an ancestor of it (consistency proof) | `token_missing_ledger_binding`, `ledger_root_not_ancestor` |
| the token's constitution hashes match the latest `constitution_loaded` entry | `constitution_hash_mismatch` |
| no reload or revocation since issuance | `constitution_changed_since_issue`, `revoked` |
| the token's own `capability_issued` entry exists and matches | `capability_not_recorded` |
| single use, shared by every gateway on the ledger | `replayed`; an open attempt is `already_attempted`; across processes also `ledger_concurrent_writer` |

On success the gateway checkpoints `redemption_started` before the tool
runs, then logs `capability_redeemed` and `tool_executed` (a hash of the
result, not the result). A crash after that intent does not run the tool
again. A tool that raises logs `redemption_aborted` and
`allowed=False, reason="tool_error:<Type>"`, and the same token can be
tried again. A tool with no registered executor does not spend the token
and returns `tool_not_registered`. Every recorded entry links to
the token's `capability_issued` entry. Outbound scanning, when configured,
still happens on the frozen arguments before the intent. Inbound scanning
still happens on the tool result before the caller receives it.

**Options.**
- `checkpoint_every` (default 1) signs the ledger head after every N
  calls. With `0`, you call `tk.ledger.checkpoint()` yourself, for
  example on a timer. Until then, the new entries show as `size_mismatch`
  in `verify-ledger`.
- `view_refresh` (default `token`) moves the gateway's view of the ledger
  forward whenever a verified token proves a newer root. `every_call` also
  proves consistency with the current ledger on every call, at the cost of
  one more proof.

<!-- check: expect=^before checkpoint: size_mismatch -->
<!-- check: expect=^after checkpoint: ok -->
```python
from my_two_key import load_key, make_two_key

tk = make_two_key("howto-9b.jsonl")
gw = tk.gateway(tools={"search": lambda q: f"results for {q}"}, checkpoint_every=0)
args = {"q": "weather"}
d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "Weather?", args)
print(gw.invoke(d.capability, "search", args, {"data_class": "public"}).reason)
pub = load_key().public_key()
print("before checkpoint:", tk.ledger.verify(pub).reason)
tk.ledger.checkpoint()
print("after checkpoint:", tk.ledger.verify(pub).reason)
```

**Deployment rules for the prototype.**
- Run the gateway in the **same process** as Two-Key, using
  `tk.gateway()`. The ledger is owned by one process, and a second
  process opening the same file won't see new entries, so its checks fail
  closed.
- You can create **several** gateways on one TwoKey instance (for example one per
  tool family or per worker thread). The used-token record lives in Two-Key's ledger, not in the gateway, so every gateway consults the same
  record and a token is accepted **exactly once** however many gateways or
  threads present it. The checks and the redemption run under the ledger's
  lock. See the example below.
- A gateway in a **second process** (or a second `PersonalLedger` opened on
  the same file) still can't redeem a token twice: on POSIX the redemption
  holds an `flock` on the ledger file and first checks that nobody else has
  appended since this instance last wrote. If someone has, it refuses with
  `replayed` (the other writer already redeemed this token),
  `already_attempted` (an intent is already open), or
  `ledger_concurrent_writer` (the file changed in some other way). The
  refusal isn't logged, because that instance's view is stale and
  appending would fork the chain. That instance then refuses all further
  writes until it's reopened. This is a fail-closed guard, not
  multi-process support: the ledger still has one owning process.
- Tokens are bearer secrets. Pass them straight from `authorize` to
  `invoke`; don't log or store them.
- A restarted TwoKey instance gets a new random HMAC key (`capability_secret`), so
  tokens from before the restart stop working. Replay protection survives
  restarts: the ledger rebuilds spent tokens from `capability_redeemed`
  and open attempts from `redemption_started` (an abort clears the attempt).

Two gateways on one TwoKey instance, same token:

<!-- check: expect=^first gateway: executed -->
<!-- check: expect=^second gateway: replayed -->
<!-- check: expect=^redemptions recorded: 1 -->
```python
from my_two_key import make_two_key

tk = make_two_key("howto-9b.jsonl")
args = {"payee": "power-co.example", "amount": 42.5}
fields = {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}
gw1 = tk.gateway(tools={"pay_bill": lambda payee, amount: "paid"})
gw2 = tk.gateway(tools={"pay_bill": lambda payee, amount: "paid"})
d = tk.authorize({"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example",
                 "data_class": "financial", "irreversible": False}, "Pay the electric bill.", args)
print("first gateway:", gw1.invoke(d.capability, "pay_bill", args, fields).reason)
print("second gateway:", gw2.invoke(d.capability, "pay_bill", args, fields).reason)
jti = d.token_payload["jti"]
print("redemptions recorded:", sum(1 for e in tk.ledger.entries
                                   if e.kind == "capability_redeemed" and e.body["jti"] == jti))
```

### Content scanning: DLP and antivirus (optional)

The gateway can pass what an agent is about to send, and what a tool
returns to it, to third-party DLP and antivirus software through five hook
types: a vendor API (REST or gRPC), ICAP, an in-process plugin, a local
sidecar, or an asynchronous scanner. None is required, and with no scanners
the gateway behaves exactly as above.

The author decided three things (`CONCEPTION_NOTES.md` Entry 6):
- **Timeout:** both the seconds to wait (`timeout_seconds`, default 10) and
  the action (`on_timeout`) are configurable. The action defaults to block
  and can be set to `"allow"`.
- **Most restrictive wins:** if Two-Key or any scanner denies, the call is
  blocked.
- **What scanners get:** scanners get the exact bytes being sent and the
  decoded strings, for malicious-script detection.

And then five more (Entry 7):
- **Errors:** a scanner error is logged in the ledger (`scan_errors`) and
  treated like a timeout.
- **Order:** scanners run in parallel by default.
- **Holding:** an asynchronous scanner holds until its verdict or the
  timeout.
- **Disagreement:** any conviction denies, including a DLP data class the
  token doesn't permit.
- **Inbound:** what a tool returns is scanned before the agent gets it.

See [SCANNING_HOOKS.md](SCANNING_HOOKS.md) for the options, their pros and
cons, and the open questions.

The example below uses the built-in `PatternScanner` (an example plugin,
not a DLP product). Words such as "diagnosis" are refused before a token
is issued. The scanner example uses a chart id the core word list does
not know, labelled `public`:

<!-- check: expect=^no scanners\s+executed -->
<!-- check: expect=^dlp, labelled public\s+scan_data_class_mismatch \['medical'\] -->
<!-- check: expect=^av, EICAR attachment\s+scan_blocked:example-av -->
<!-- check: expect=^slow scanner, default\s+scan_timeout:slow-av -->
<!-- check: expect=^slow scanner, allow\s+executed -->
<!-- check: expect=^inbound, EICAR result\s+result_withheld:scan_blocked:example-av -->
```python
import base64
from my_two_key import make_two_key
import time
from two_key.scanning import EICAR, ContentScanner, PatternRule, PatternScanner, ScanReport, ScanSettings

tk = make_two_key("howto-9c.jsonl")
dlp = PatternScanner("example-dlp", kind="dlp",
                     rules=[PatternRule("mrn", rb"(?i)mrn-[0-9]+", label="health", data_class="medical")])
av = PatternScanner("example-av", kind="av", rules=PatternScanner.example_rules())
tools = {"email_draft": lambda to, body, attachment_b64="": "drafted"}
fields = {"counterparty": "clinic.example", "data_class": "public"}


def token(args):
    return tk.authorize({"tool": "email_draft", "counterparty": "clinic.example", "data_class": "public",
                         "irreversible": False}, "Draft the note.", args).capability


def last_scan():
    e = [e for e in tk.ledger.entries if e.kind in ("capability_redeemed", "gateway_denied")][-1]
    return e.body["content_scans"][0]


plain = {"to": "clinic.example", "body": "See you Tuesday"}
print(f"{'no scanners':<22}", tk.gateway(tools=tools).invoke(token(plain), "email_draft", plain, fields).reason)
said = {"to": "clinic.example", "body": "Diagnosis: example condition"}
denied = tk.authorize({"tool": "email_draft", "counterparty": "clinic.example", "data_class": "public",
                       "irreversible": False}, "Draft the note.", said)
print(f"{'word list':<22}", denied.allowed, denied.reason)
chart = {"to": "clinic.example", "body": "chart mrn-100200"}
gw = tk.gateway(tools=tools, scanners=[dlp])
print(f"{'dlp, labelled public':<22}", gw.invoke(token(chart), "email_draft", chart, fields).reason,
      last_scan()["data_classes"])
mail = {"to": "clinic.example", "body": "see attached", "attachment_b64": base64.b64encode(EICAR).decode()}
gw = tk.gateway(tools=tools, scanners=[av],
                file_extractors={"email_draft": lambda a: [("att", base64.b64decode(a["attachment_b64"]),
                                                            "application/octet-stream")]})
print(f"{'av, EICAR attachment':<22}", gw.invoke(token(mail), "email_draft", mail, fields).reason)


class SlowScanner(ContentScanner):      # stands in for a scanner that doesn't answer in time
    def scan(self, request, timeout):
        time.sleep(0.5)
        return ScanReport("allow")


plain = {"to": "clinic.example", "body": "See you Tuesday"}
for name, action in (("default", "block"), ("allow", "allow")):
    gw = tk.gateway(tools=tools, scanners=[SlowScanner("slow-av", kind="av")],
                    scan_settings=ScanSettings(timeout_seconds=0.1, on_timeout=action))
    print(f"{'slow scanner, ' + name:<22}", gw.invoke(token(plain), "email_draft", plain, fields).reason)

gw = tk.gateway(tools={"email_draft": lambda **a: {"reply": EICAR.decode()}}, scanners=[av])
print(f"{'inbound, EICAR result':<22}", gw.invoke(token(plain), "email_draft", plain, fields).reason)
```

The word "diagnosis" labelled `public` is refused before a token
(`record_args_mismatch:sensitive_labeled_public`). The DLP scanner then
finds `medical` in `mrn-100200`, which that word list does not know. The
token permits only `public`, so the DLP convicts and the call is denied. The
`gateway_denied` entry records the verdict: the scanner id and version, the
digest of the scanned bytes (equal to the token's `args_hash`), the outcome,
and the data classes seen (`scan_data_classes`). A scan denial happens before redemption, so the
token isn't used up. A scanner can only add a deny: a call Two-Key denies is
never sent to the scanners.

The slow scanner doesn't answer within `timeout_seconds`. With the default
`on_timeout="block"` the call is denied. With `on_timeout="allow"` it runs,
and the `timeout` is still recorded in `scan_errors`. A scanner error is
handled the same way.

In the last line, the tool runs, but its result contains the EICAR test
string. The inbound scan blocks it, so the agent gets
`result_withheld:scan_blocked:example-av` instead of the result. The
`tool_executed` entry records `result_scans` and `result_withheld`.

## 10. Both paths must answer

Path A runs, then Path B. Both always answer. A deny from either path denies the action. A missing answer denies it too: Path A raising is `path_a_no_response`, and a Path B quorum that was not counted is `path_b_no_response`. `short_circuit_path_b` is ignored. The ledger records `vm_result` and `quorum_result` on every proposal.

<!-- check: expect=^both paths: path_a_denied:rule_denied:tool-allowlist quorum={'yes': -->
```python
from my_two_key import make_two_key

wire = {"tool": "wire_transfer", "amount_usd": 10, "counterparty": "bank.example", "data_class": "financial"}
d = make_two_key("howto-10a.jsonl").authorize(wire, "Wire $10.", {})
print("both paths:", d.reason, "quorum=" + str(d.quorum))
```

A Path B quorum that is not counted (`no_judges`, too few responses, a timeout before a counted ballot) is `path_b_no_response`. A Path A exception is `path_a_no_response`. Neither is an allow.

## 11. Revocation

`tk.revoke(jti)` revokes one token. `tk.revoke()` with no argument
revokes every token issued so far; later tokens are unaffected. Each call
appends a `revocation` entry, and the gateway refuses revoked tokens with
`revoked`.

<!-- check: expect=^one token: revoked -->
<!-- check: expect=^all so far: revoked revoked -->
<!-- check: expect=^issued after: executed -->
```python
from my_two_key import make_two_key

tk = make_two_key("howto-11.jsonl")
gw = tk.gateway(tools={"search": lambda q: "ok"})
act, args, f = {"tool": "search", "data_class": "public", "irreversible": False}, {"q": "x"}, {"data_class": "public"}

d = tk.authorize(act, "Search.", args)
tk.revoke(d.token_payload["jti"], reason="changed my mind")
print("one token:", gw.invoke(d.capability, "search", args, f).reason)

d1, d2 = tk.authorize(act, "Search.", args), tk.authorize(act, "Search.", args)
tk.revoke(reason="lost my phone")
print("all so far:", gw.invoke(d1.capability, "search", args, f).reason, gw.invoke(d2.capability, "search", args, f).reason)
d3 = tk.authorize(act, "Search.", args)
print("issued after:", gw.invoke(d3.capability, "search", args, f).reason)
```

## 12. The ledger

The ledger is two files with mode 0600: `<name>.jsonl`, one JSON entry per
line in a hash chain, and `<name>.jsonl.head.json`, the chain head signed by
your key. The head covers `{size, head digest, Merkle root}`. Entry kinds
include:

- `constitution_loaded`, `constitution_reload_refused`
- `proposal`, `action_normalized`, `vm_result`
- `quorum_result` (every ballot and the round's binding), `quorum_skipped`
- `capability_issued`, `decision`
- `redemption_started`, `redemption_aborted`, `capability_redeemed`, `tool_executed`, `tool_error`, `gateway_denied`
- `revocation`, `anchored`

The ledger file and the signed head are AES-256-GCM. The decryption key and
the witness key live outside the ledger directory, as siblings named
`<ledger-directory>.ledger-key` and `<ledger-directory>.witness`. Copying
the ledger directory does not copy them. The principal key cannot unwrap
the log or sign a head by itself. A missing or wrong key fails closed.

### Verify

<!-- check: expect=^OK: ok \(entries= -->
```bash
python -m two_key verify-ledger --ledger ~/.two-key/howto-8.jsonl \
    --pub ~/.two-key/principal.pub.pem --key ~/.two-key/principal.pem \
    --passphrase-env TWOKEY_KEY_PASSPHRASE
```

The ledger file is ciphertext. Copying it without the outside ledger key
is refused, even if you still have the principal key. The unit tests cover
a rewritten chain, which `verify-ledger` reports as `hash_chain_broken`.

<!-- check: expect=^REJECTED: ledger key missing -->
<!-- check: expect-fail -->
```bash
mkdir -p /tmp/two-key-tamper && cp ~/.two-key/howto-8.jsonl* /tmp/two-key-tamper/
python -m two_key verify-ledger --ledger /tmp/two-key-tamper/howto-8.jsonl \
    --pub ~/.two-key/principal.pub.pem --key ~/.two-key/principal.pem \
    --passphrase-env TWOKEY_KEY_PASSPHRASE
```

### Merkle proofs

An **inclusion proof** shows that one entry is in the ledger with a given
root. A **consistency proof** (RFC 9162) shows that an older root is a
prefix of a newer one, which means nothing was rewritten in between. The
gateway uses consistency proofs on every call; you can use both for audits
or to prove an entry to someone else.

<!-- check: expect=^inclusion ok: True -->
<!-- check: expect=^consistency ok: True -->
<!-- check: expect=^forged root rejected: True -->
```python
from pathlib import Path
from two_key.ledger import PersonalLedger
from my_two_key import load_key

led = PersonalLedger(Path.home() / ".two-key" / "howto-8.jsonl", signing_key=load_key())
p = led.inclusion_proof(3)
print("inclusion ok:", PersonalLedger.verify_inclusion_proof(p), "| proof nodes:", len(p["proof"]))

old_size = 5
old_root = led.merkle_root(old_size)       # a root you recorded earlier (e.g. from a token or an anchor)
c = led.consistency_proof(old_size)        # up to the current size
print("consistency ok:", PersonalLedger.verify_consistency_proof(c, old_root, led.merkle_root()))
print("forged root rejected:", not PersonalLedger.verify_consistency_proof(c, "00" * 32, led.merkle_root()))
```

Always verify a consistency proof against roots **you** already hold, not
the roots printed inside the proof.

### Head signing and fsync

- `head_signing="decision"` (the default) signs one head per decision;
  `"append"` signs after every entry, which costs more time.
- `ledger_fsync=True` (the default) fsyncs every write. `False` is faster
  but can lose the last entries on power failure.
- Used directly, `PersonalLedger(path, signing_key, auto_sign_every=N)`
  signs after every N appends, and `0` means only on `checkpoint()`.

<!-- check: expect=^append: ok \(unsigned entries: 0\) -->
```python
from my_two_key import load_key, make_two_key

tk = make_two_key("howto-12.jsonl", head_signing="append", ledger_fsync=False)
tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "Search.", {})
print(f"append: {tk.ledger.verify(load_key().public_key()).reason} (unsigned entries: {tk.ledger.unsigned_entries})")
```

### Anchoring (stub)

Publishing the signed head to a public log on a schedule isn't implemented.
The hook exists: `ledger.anchor(anchor)` publishes the signed head through
an `Anchor` and logs an `anchored` entry. `LocalFileAnchor` only appends
to a local file. Its receipt's `size` is the number of entries the
anchored signed head covers.

<!-- check: expect=^\{'anchor': 'local-file', 'published': False -->
<!-- check: expect='size': \d+ -->
```python
from pathlib import Path
from two_key.anchoring import LocalFileAnchor
from my_two_key import make_two_key

tk = make_two_key("howto-12b.jsonl")
print(tk.ledger.anchor(LocalFileAnchor(Path.home() / ".two-key" / "anchors.jsonl")))
tk.ledger.checkpoint()
```

### Deployment mode and permissioned anchoring

`deployment_mode` is `personal` (the default: the ledger stays local) or
`enterprise` (every signed head is anchored to a permissioned blockchain).
Set it with `TwoKey(deployment_mode=...)`, the `TWOKEY_DEPLOYMENT_MODE`
environment variable, or `deployment_mode:` in a file passed as
`deployment_config=`. If more than one is set, they must agree. The mode
is fixed for a ledger once it is set. Enterprise mode also needs
`siem_host` (RFC 5424 syslog over TLS, port 6514). See
[DEPLOYMENT_MODES.md](DEPLOYMENT_MODES.md) for the receipts, the Fabric
chaincode contract, and the open questions.

<!-- check: expect=^OK: deployment_mode=enterprise source=environment -->
```bash
TWOKEY_DEPLOYMENT_MODE=enterprise python -m two_key deployment-mode
```

Enterprise mode refuses to start without a permissioned anchor. Below,
`DemoGateway` is an in-memory stand-in for a Fabric client bridge. Swap
in your own bridge, or use `FabricAnchor.from_fabric_sdk_py(...)`.

<!-- check: expect=^refused: deployment_mode 'enterprise' requires a permissioned-ledger anchor -->
<!-- check: expect=^anchors: \['ok', 'ok' -->
<!-- check: expect=^mode: enterprise -->
```python
from two_key.anchoring import FabricAnchor, check_anchored_entries
from two_key.core import TwoKeyConfigError
from two_key.pki_testing import TestPki
from my_two_key import load_key, make_two_key

try:
    make_two_key("howto-12c.jsonl", deployment_mode="enterprise")
except TwoKeyConfigError as e:
    print("refused:", e)


class DemoGateway:  # in-memory stand-in; a real one talks to Fabric peers
    def __init__(self):
        self.state, self.txs = {}, {}

    def submit_transaction(self, channel, chaincode, function, args):
        key, record_json = args
        if key in self.state:
            raise RuntimeError("PutAnchor: key already exists")
        self.state[key] = record_json
        tx = {"tx_id": f"tx{len(self.txs) + 1}", "block_number": len(self.txs) + 1,
              "validation_code": "VALID", "endorsing_orgs": ["Org1MSP", "Org2MSP"]}
        self.txs[tx["tx_id"]] = tx
        return tx

    def evaluate_transaction(self, channel, chaincode, function, args):
        return self.state.get(args[0], "")

    def get_transaction(self, channel, tx_id):
        return self.txs.get(tx_id)


# Enterprise mode also needs PKI identities (next section). A throwaway test CA stands in for yours here,
# and agent assertions are switched off to keep this example about anchoring.
test_ca = TestPki()
cert, _ = test_ca.issue("Principal", email="principal@example.com", key=load_key())
identity = {"pki": test_ca.config({"email:principal@example.com": ["principal"]}, require_agent_identity=False),
            "principal_credential": test_ca.credential(cert)}
anchor = FabricAnchor(DemoGateway(), channel="audit", chaincode="twokey-anchor", min_endorsing_orgs=2)
tk = make_two_key("howto-12c.jsonl", deployment_mode="enterprise", anchor=anchor, siem_host="127.0.0.1", **identity)
tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "Search.", {})
print("anchors:", [c.reason for c in check_anchored_entries(tk.ledger, load_key().public_key(), anchor)])
print("mode:", tk.deployment.mode)
```

### Enterprise: PKI identities

In enterprise mode the principal, agents, and judges are X.509
certificate identities. Startup refuses without `pki` and a principal
certificate that chains to a trust anchor, isn't revoked, maps to the
role `principal`, and certifies the principal key. By default, each
`authorize` call needs an agent assertion, which the agent signs with its
certified key; it may be held on a PKCS#11 token. When revocation status
can't be obtained, the certificate is rejected
(`revocation_unreachable="fail_closed"`, a placeholder default). See
[KEYS_AND_PKI.md](KEYS_AND_PKI.md) for every check, the ML-DSA-65 binding
extension, and the `pki:` config-file section.

Below, `TestPki` is a throwaway CA with an in-memory OCSP responder, and
`SoftwareToken` is a fake PKCS#11 token. Use your CA and
`pki.PythonPkcs11Token(module, token_label, pin)` for real.

<!-- check: expect=^refused: .*requires PKI identities -->
<!-- check: expect=^no assertion: agent_identity_required -->
<!-- check: expect=^agent on token: dual_path_pass CN=Ops Agent -->
<!-- check: expect=^replayed: agent_identity_rejected:assertion_replay -->
<!-- check: expect=^revoked: agent_identity_rejected:revoked -->
<!-- check: expect=^unreachable: revocation_unreachable -->
```python
from two_key import pki
from two_key.anchoring import FabricAnchor
from two_key.core import TwoKeyConfigError
from two_key.e2e_demo import InMemoryFabric
from two_key.pki_testing import SoftwareToken, TestPki
from my_two_key import load_key, make_two_key

ca = TestPki()
roles = {"email:principal@example.com": ["principal"], "uri:spiffe://example.com/agent/ops": ["agent"]}
cert, _ = ca.issue("Principal", email="principal@example.com", key=load_key())


def anchor():
    return FabricAnchor(InMemoryFabric(), channel="audit", chaincode="twokey-anchor")


try:
    make_two_key("howto-12d.jsonl", deployment_mode="enterprise", anchor=anchor(), siem_host="127.0.0.1")
except TwoKeyConfigError as e:
    print("refused:", e)
tk = make_two_key("howto-12d.jsonl", deployment_mode="enterprise", anchor=anchor(), siem_host="127.0.0.1",
                  pki=ca.config(roles, ocsp=True), principal_credential=ca.credential(cert))

token = SoftwareToken()                                   # stands in for an HSM or smart card
agent, agent_key = ca.identity("Ops Agent", uri="spiffe://example.com/agent/ops", key=token.generate("ops"))
action = {"tool": "search", "data_class": "public", "irreversible": False}
print("no assertion:", tk.authorize(action, "Search.", {}).reason)
a = pki.sign_agent_request(agent, agent_key, action, "Search.", {})
d = tk.authorize(action, "Search.", {}, agent_assertion=a)
print("agent on token:", d.reason, [e for e in tk.ledger.entries if e.kind == "agent_identity"][-1].body["identity"]["subject"])
print("replayed:", tk.authorize(action, "Search.", {}, agent_assertion=a).reason)
ca.revoke(agent.certificate)                               # the OCSP responder now says "revoked"
print("revoked:", tk.authorize(action, "Search.", {},
                               agent_assertion=pki.sign_agent_request(agent, agent_key, action, "Search.", {})).reason)
try:
    pki.PkiVerifier(ca.config(roles, crl=False)).verify(ca.credential(cert), "principal")
except pki.CertificateRejected as e:
    print("unreachable:", e.reason)
```

## 13. Crypto: FIPS mode, classic and hybrid keys, token modes

**FIPS-approved algorithms, validated module required for compliance.**
This code is not FIPS certified or validated. Every algorithm goes through
one `CryptoProvider`, so it can run on a validated module. Hashes and MACs
default to SHA-384 and HMAC-SHA-384 for every key suite. Ledgers written
with the earlier SHA-256 default still verify (to keep appending to one,
pass `digest_alg="sha256"`). Details are in [CRYPTO.md](CRYPTO.md).

### Self-test

Two-Key runs known-answer and pairwise tests before it starts. You can
run them yourself:

<!-- check: expect="ok": true -->
<!-- check: expect="fips_mode": true -->
```bash
python -m two_key --fips selftest --require-pq
```

### `fips_mode` and `require_fips_module`

`fips_mode=True` (CLI `--fips`) refuses non-approved algorithms and the
liboqs backend. `require_fips_module=True` also refuses to start unless
both OpenSSL instances in use (CPython's `hashlib` and pyca
`cryptography`) report an active FIPS provider. On a machine without one,
like the one these docs were checked on, it refuses:

<!-- check: expect=^md5 refused: sha256 ok -->
<!-- check: expect=^liboqs refused in fips_mode -->
<!-- check: expect=^require_fips_module: refused -->
```python
from two_key.crypto import CryptoPolicyError, CryptoProvider

p = CryptoProvider(fips_mode=True)
try:
    p.check("hash", "md5")
except CryptoPolicyError:
    print("md5 refused:", p.check("hash", "sha256"), "ok")
try:
    CryptoProvider(fips_mode=True, pq_backend="liboqs")
except CryptoPolicyError:
    print("liboqs refused in fips_mode")
try:
    CryptoProvider(fips_mode=True, require_fips_module=True)
    print("require_fips_module: FIPS provider active")
except CryptoPolicyError:
    print("require_fips_module: refused (no active FIPS provider on this machine)")
```

Pass the provider to Two-Key with `TwoKey(..., crypto=provider)`,
or set it process-wide with
`two_key.crypto.set_default_provider(provider)`.

### Hybrid post-quantum key and `require_pq`

Two-Key uses SHA-384 digests and signed tokens (`tk1-sig`) by
default with every key suite, including a hybrid key. Both signature halves must verify, and nothing falls
back to classical-only. `require_pq=True` refuses to start without a
hybrid key and a working ML-DSA backend.

<!-- check: expect=^OK: principal=did:twokey:alice .*signer=hybrid-mldsa65-ed25519: -->
```bash
python -m two_key sign-constitution --document my-constitution.md --principal did:twokey:alice \
    --key ~/.two-key-pq/principal.keys.json --passphrase-env TWOKEY_KEY_PASSPHRASE --out pq-constitution.signed.json
python -m two_key verify-constitution --signed pq-constitution.signed.json --pub ~/.two-key-pq/principal.pub.json
```

<!-- check: expect='signature_suite': 'hybrid-mldsa65-ed25519', 'digest_alg': 'sha384', 'token_mode': 'tk1-sig' -->
<!-- check: expect=^ed25519 key with require_pq: refused -->
<!-- check: expect=^invoke: executed -->
```python
import os
from pathlib import Path
from two_key import keys
from two_key.constitution import load_envelope
from two_key.crypto import CryptoProvider
from two_key.judges.config import load_config_file
from two_key.core import TwoKey, TwoKeyConfigError
from my_two_key import make_two_key

pq = Path.home() / ".two-key-pq"
key = keys.load_private_any(pq / "principal.keys.json", os.environ["TWOKEY_KEY_PASSPHRASE"].encode())
judges, quorum = load_config_file(Path("judges.yaml"))
tk = TwoKey(load_envelope(Path("pq-constitution.signed.json")), keys.load_public_any(pq / "principal.pub.json"),
                  pq / "ledger.jsonl", judges, ledger_signing_key=key, quorum_policy=quorum,
                  crypto=CryptoProvider(fips_mode=True), require_pq=True,
                  agent_session_env="TWOKEY_AGENT_SESSION")
print(tk.crypto_profile())
gw = tk.gateway(tools={"search": lambda q: "ok"})
d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "Search.", {"q": "x"})
print("invoke:", gw.invoke(d.capability, "search", {"q": "x"}, {"data_class": "public"}).reason)
try:
    make_two_key("howto-13.jsonl", require_pq=True)
except TwoKeyConfigError:
    print("ed25519 key with require_pq: refused")
```

Without an ML-DSA backend (simulated here with `--pq-backend none`), hybrid
operations fail with a clear error instead of downgrading:

<!-- check: expect=cannot generate hybrid-mldsa65-ed25519 -->
<!-- check: expect-fail -->
```bash
python -m two_key --pq-backend none keygen --out /tmp/no-pq --suite hybrid-mldsa65-ed25519 --no-passphrase
```

### ECDSA P-384

Use `ecdsa-p384` (classical) or `hybrid-mldsa65-p384` on FIPS modules where
Ed25519 isn't approved, such as the OpenSSL 3.1.2 FIPS provider, cert
#4985. That module has no ML-DSA, so a hybrid key's ML-DSA half would run
outside it.

<!-- check: expect=^OK: .*signer=ecdsa-p384: -->
```bash
python -m two_key keygen --out ~/.two-key-p384 --suite ecdsa-p384 --passphrase-env TWOKEY_KEY_PASSPHRASE
python -m two_key sign-constitution --document my-constitution.md --principal did:twokey:alice \
    --key ~/.two-key-p384/principal.keys.json --passphrase-env TWOKEY_KEY_PASSPHRASE --out p384.signed.json
python -m two_key --fips verify-constitution --signed p384.signed.json --pub ~/.two-key-p384/principal.pub.json
```

### Token modes

| `token_mode` | Tag | Notes |
|---|---|---|
| `tk1-sig` | Signature by the principal key, or `token_signing_key` | Default. The gateway holds only the public key |
| `tk1` | HMAC-SHA-256, key ≥ 256 bits | Legacy (the Ed25519 default before the F_REVIEW fixes); only if chosen |
| `tk1-hs384` | HMAC-SHA-384, 384-bit key (≥ 256 bits) | Only if chosen. The verifier holds the minting secret |

HMAC with a key of 256 bits or more is quantum-resistant in the Grover sense, but it is not the default: a verifier that can check an HMAC token can also mint one. A token of any other mode than Two-Key's is refused (`unsupported_token_version`), so there's no downgrade.

<!-- check: expect=^tk1-sig executed token length \d{4} -->
```python
from two_key.crypto import PrivateKeySet
from my_two_key import make_two_key

tk = make_two_key("howto-13b.jsonl", token_mode="tk1-sig",
                token_signing_key=PrivateKeySet.generate("hybrid-mldsa65-ed25519"))
gw = tk.gateway(tools={"search": lambda q: "ok"})
d = tk.authorize({"tool": "search", "data_class": "public", "irreversible": False}, "Search.", {"q": "x"})
print("tk1-sig", gw.invoke(d.capability, "search", {"q": "x"}, {"data_class": "public"}).reason,
      "token length", len(d.capability))
```

## 14. Performance and tests

<!-- check: expect=^\| Path A \| PolicyVM\.eval -->
<!-- check: expect=^\| Authorize \| authorize \(A \+ B -->
```bash
python bench.py --quick > bench.txt          # about 15 s; prints latency and memory tables
grep -E "PolicyVM\.eval|authorize \(A \+ B|invoke \(all checks" bench.txt
```

The full run (`python bench.py`, about 40 s) prints the tables in
[PERFORMANCE.md](PERFORMANCE.md); `--json results.json` saves them. On the
development VM, Path A takes about 7–12 µs, a full `authorize` with local
test judges about 1.1 ms (Ed25519) or 2.1 ms (hybrid), and a gateway
`invoke` about 0.3 ms (Ed25519) or 1.0 ms (hybrid). Real judge latency
dominates all of these.

The end-to-end demo exercises every capability offline, one check per
line: seed backup, signing, hybrid signatures, both paths, tokens, the
gateway, scanning, the ledger, anchoring, and PKI. Exit status 0 means
every check passed. the README section "Security model and limitations"
maps each check to the feature it shows.

<!-- check: expect=^e2e summary: \d+ passed, 0 failed, 0 skipped -->
```bash
python -m two_key e2e-demo | tail -n 1
```

The test suite makes no network calls:

<!-- check: expect=^OK -->
```bash
python -m unittest discover -s tests 2>&1 | tail -n 3
```

To check this guide and the README yourself (this needs network access for
`pip install`):

<!-- check: skip this is the checker itself; running it here would recurse -->
```bash
python3 tools/doccheck.py README.md docs/HOWTO.md
```

# Two-Key how-to

A step-by-step guide to every part of the prototype. For the short
version, see the [README](../README.md#quick-start); for every option in one
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
git clone https://github.com/sbusch305-collab/two-key.git
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

The principal key signs your constitution and your ledger head. Choose a
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
PBKDF2-HMAC-SHA-256 (600,000 iterations) and AES-256-GCM. Load either kind
in Python with `keys.load_private_any` / `keys.load_public_any`.

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
  - {id: local, type: ollama, provider: local, model: "<ollama-model-name>"}
```

<!-- check: expect=^loaded two-key-constitution/2 -->
```bash
read -rsp "xAI API key: " XAI_API_KEY; echo; export XAI_API_KEY
read -rsp "Anthropic API key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
python - <<'PY'
from my_two_key import make_two_key
tk = make_two_key("howto-4.jsonl")
print("loaded", tk.compiled.source_format, "bytecode_hash", tk.compiled.bytecode_hash[:16],
      "nl_hash", tk.compiled.nl_hash[:16])
PY
```

**Reloading.** `reload_constitution` accepts only a document signed by the
same trusted key and naming the same principal. After a successful
reload, tokens issued earlier are refused by the gateway. A refused reload
leaves the active constitution in place and is logged as
`constitution_reload_refused`.

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
tk.reload_constitution(sign_document(build_source_document("did:twokey:alice", src), load_key()))
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
  a remote or cloud model.
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
    """callback hook: return a current bearer token from your SSO/OAuth client.
    Replace this with a call to your identity provider's SDK or token cache."""
    return os.environ["MY_SSO_TOKEN"]


def gateway_login(username, password):
    """username_password hook: log in to YOUR model gateway and return its session token.
    Model vendors don't offer password logins for their APIs, so nothing is built in."""
    raise NotImplementedError("implement the login for your gateway here")
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
  - id: password           # STUB unless the login hook implements your gateway's login
    type: openai_compatible
    base_url: https://llm-gateway.example.com/v1
    model: <model-name>
    auth: {type: username_password, username: me, password_env: MY_GATEWAY_PASSWORD,
           login: "my_hooks:gateway_login"}
  - id: device-code        # STUB: OAuth 2.0 device authorization grant (RFC 8628) needs fetch_token
    type: openai_compatible
    base_url: https://llm-gateway.example.com/v1
    model: <model-name>
    auth: {type: oauth_device_code, client_id: my-client,
           device_authorization_endpoint: https://idp.example.com/device,
           token_endpoint: https://idp.example.com/token}
```

<!-- check: expect=^OK: 5 judges -->
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
<!-- check: expect=^password: abstain credential: login failed -->
<!-- check: expect=^device-code: abstain credential: OAuthDeviceCodeProvider is an interface stub -->
<!-- check: expect=^keyring-key: abstain credential: -->
```bash
MY_SSO_TOKEN=example-token MY_GATEWAY_PASSWORD=example-password python - <<'PY'
from pathlib import Path
from two_key.action import normalize_action
from two_key.judges.config import load_config_file

judges, _ = load_config_file(Path("judges-auth.yaml"))
action = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
for j in judges:
    b = j.score("Searching the web is fine.", action, "")
    print(f"{j.judge_id}: {b.vote} {b.error or ''}"[:110])
PY
```

The username/password provider reads the password from `password_env` when
it's needed and calls your `login(username, password)` hook; a hook that
raises is reported as `login failed`. The device-code provider calls
`fetch_token(provider)`, which should run the RFC 8628 flow (steps in
`two_key/judges/credentials.py`) and return an access token. In
Python you can pass hooks directly:
`OAuthDeviceCodeProvider(..., fetch_token=my_flow, prompt_user=show_code)`.

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
and `require_path_a_first=True`. These are the mechanisms Stephan selected
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
instance's token key and ledger:

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
| single use, shared by every gateway on the ledger | `replayed`; across processes also `ledger_concurrent_writer` |

On success the gateway logs `capability_redeemed` before the tool runs, so
a crashing tool can't be retried with the same token. It then logs
`tool_executed` with a hash of the result (the result itself isn't stored),
or `tool_error`. Both entries link to the token's `capability_issued`
entry. A tool that raises gives `allowed=True, reason="tool_error:<Type>"`,
meaning authorized but failed. A tool with no registered executor gives
`authorized_no_executor`, for when your own code performs the call after
the gateway approves it.

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
  `replayed` (the other writer already redeemed this token) or
  `ledger_concurrent_writer` (the file changed in some other way). The
  refusal isn't logged, because that instance's view is stale and
  appending would fork the chain. That instance then refuses all further
  writes until it's reopened. This is a fail-closed guard, not
  multi-process support: the ledger still has one owning process.
- Tokens are bearer secrets. Pass them straight from `authorize` to
  `invoke`; don't log or store them.
- A restarted TwoKey instance gets a new random HMAC key (`capability_secret`), so
  tokens from before the restart stop working. Replay protection survives
  restarts: the ledger rebuilds its used-token record from its
  `capability_redeemed` entries when it's opened.

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

## 10. Ordering and short-circuit

By default (`short_circuit_path_b=True`) Two-Key doesn't convene
Path B when Path A denies, so a forbidden proposal is never sent to any
external judge. The ledger records `quorum_skipped`. With
`short_circuit_path_b=False` both paths always run, which is useful for
auditing how the judges would have voted, but either path can still deny.
`require_path_a_first: true` makes that option an error.

<!-- check: expect=^default: path_a_denied:rule_denied:tool-allowlist quorum=None -->
<!-- check: expect=^both paths: path_a_denied:rule_denied:tool-allowlist quorum=\{'yes': 0, 'no': 3 -->
<!-- check: expect=^refused: quorum policy requires Path B only after Path A passes -->
```python
from two_key.core import TwoKeyConfigError
from two_key.quorum import QuorumPolicy
from my_two_key import make_two_key

wire = {"tool": "wire_transfer", "amount_usd": 10, "counterparty": "bank.example", "data_class": "financial"}
d = make_two_key("howto-10a.jsonl").authorize(wire, "Wire $10.", {})
print("default:", d.reason, "quorum=" + str(d.quorum))
d = make_two_key("howto-10b.jsonl", short_circuit_path_b=False).authorize(wire, "Wire $10.", {})
print("both paths:", d.reason, "quorum=" + str(d.quorum))
try:
    make_two_key("howto-10c.jsonl", short_circuit_path_b=False,
                quorum_policy=QuorumPolicy(required_yes=2, require_path_a_first=True))
except TwoKeyConfigError as e:
    print("refused:", e)
```

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
- `capability_redeemed`, `tool_executed`, `tool_error`, `gateway_denied`
- `revocation`, `anchored`

The ledger isn't encrypted; see [Limitations](../README.md#limitations).

### Verify

<!-- check: expect=^OK: ok \(entries= -->
```bash
python -m two_key verify-ledger --ledger ~/.two-key/howto-8.jsonl \
    --pub ~/.two-key/principal.pub.pem
```

Changing any line breaks the chain. Rewriting the whole file fails too,
because the head signature can't be forged without your key.

<!-- check: expect=^REJECTED: hash_chain_broken -->
<!-- check: expect-fail -->
```bash
mkdir -p /tmp/two-key-tamper && cp ~/.two-key/howto-8.jsonl* /tmp/two-key-tamper/
python -c "import pathlib; p = pathlib.Path('/tmp/two-key-tamper/howto-8.jsonl'); \
p.write_text(p.read_text().replace('\"allowed\": false', '\"allowed\": true', 1))"   # turn a deny into an allow
python -m two_key verify-ledger --ledger /tmp/two-key-tamper/howto-8.jsonl --pub ~/.two-key/principal.pub.pem
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

led = PersonalLedger(Path.home() / ".two-key" / "howto-8.jsonl")
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

## 13. Crypto: FIPS mode, classic and hybrid keys, token modes

**This code is not FIPS certified or validated.** It uses only
FIPS-approved algorithms, routed through one `CryptoProvider`, so it can
run on a validated module. Details are in [CRYPTO.md](CRYPTO.md).

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

With a hybrid key, Two-Key defaults to SHA-384 digests and HMAC-SHA-384
tokens (`tk1-hs384`). Both signature halves must verify, and nothing falls
back to classical-only. `require_pq=True` refuses to start without a
hybrid key and a working ML-DSA backend.

<!-- check: expect=^OK: principal=did:twokey:alice .*signer=hybrid-mldsa65-ed25519: -->
```bash
python -m two_key sign-constitution --document my-constitution.md --principal did:twokey:alice \
    --key ~/.two-key-pq/principal.keys.json --passphrase-env TWOKEY_KEY_PASSPHRASE --out pq-constitution.signed.json
python -m two_key verify-constitution --signed pq-constitution.signed.json --pub ~/.two-key-pq/principal.pub.json
```

<!-- check: expect='signature_suite': 'hybrid-mldsa65-ed25519', 'digest_alg': 'sha384', 'token_mode': 'tk1-hs384' -->
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
                  crypto=CryptoProvider(fips_mode=True), require_pq=True)
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
| `tk1` | HMAC-SHA-256, key ≥ 256 bits | Default for Ed25519 keys |
| `tk1-hs384` | HMAC-SHA-384 | Default for other suites |
| `tk1-sig` | Signature by a separate token key (`token_signing_key`, e.g. a hybrid `PrivateKeySet`) | The verifier needs no secret that could also mint tokens. About 7 KB per hybrid token, and slower |

HMAC with a key of 256 bits or more is considered quantum-resistant, so the
HMAC modes are the recommended default. A token of any other mode than Two-Key's is refused (`unsupported_token_version`), so there's no downgrade.

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

<!-- check: expect=^\s+Path A\s+PolicyVM.eval -->
<!-- check: expect=^\s+Authorize\s+authorize \(A \+ B -->
```bash
python bench.py --quick > bench.txt          # about 15 s; prints latency and memory tables
grep -E "PolicyVM.eval|^  Authorize|invoke \(all checks" bench.txt
```

The full run (`python bench.py`, about 40 s) prints the tables in
[PERFORMANCE.md](PERFORMANCE.md); `--json results.json` saves them. On the
development VM, Path A takes about 7–12 µs, a full `authorize` with local
test judges about 1.1 ms (Ed25519) or 2.1 ms (hybrid), and a gateway
`invoke` about 0.3 ms (Ed25519) or 1.0 ms (hybrid). Real judge latency
dominates all of these.

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

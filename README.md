# Compact Kernel (two-key)

Dual-path constitutional enforcement for personal AI agents.
**Prototype. Not production cryptography. Not FIPS validated.**

A language model may *propose* an action. Compact Kernel decides whether
the action may touch the real world, and it allows the action only when two
independent paths agree. You write the rules (your "constitution"), you
choose the AI models that review proposals, and every decision is written
to a tamper-evident ledger signed with your key.

## Contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [The full how-to (docs/HOWTO.md)](#the-full-how-to)
- [Configuration reference](#configuration-reference)
- [Best practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Limitations](#limitations)
- [Repository layout and further docs](#repository-layout-and-further-docs)
- [Patent posture](#patent-posture)

## How it works

```text
 any LLM ──proposal──▶ Compact Kernel ──single-use token──▶ Tool gateway ──▶ tool
                           │                                     │
                           ├─ Path A: Policy VM over compiled    ├─ checks token, args, scope,
                           │  hard rules (never reads English)   │  ledger root, constitution hashes,
                           ├─ Path B: quorum of AI judges you    │  revocation, single use
                           │  choose, reading your constitution  │
                           └────────── Personal ledger: hash chain + Merkle tree, head signed by your key
```

1. **Constitution.** You write one document: plain-language prose plus a
   block of structured hard rules. You sign it with your key. The kernel
   refuses anything that is unsigned, modified, or signed by any other key,
   including a model vendor's.
2. **Path A (deterministic).** The hard rules are compiled to bytecode for a
   small stack VM. The VM reads only structured fields of a normalized action
   record (`tool`, `amount_usd`, `counterparty`, `data_class`,
   `irreversible`, …), never the prose, so prompt injection has nothing to
   work on. Any fault is a deny.
3. **Path B (judgment).** A quorum of judges runs on the AI providers you
   pick: xAI, OpenAI, Anthropic, Gemini, a local Ollama model, or any
   OpenAI-compatible server. Each judge checks the action against your prose
   and returns a strict JSON ballot. The kernel counts booleans against an
   approval threshold **T**, after an availability floor **K** and optional
   vendor-diversity floors. A malformed, late, or failed ballot is an
   abstention, never a yes.
4. **Both must agree.** Only if Path A *and* Path B pass does the kernel
   issue a capability token. By default Path B isn't consulted when Path A
   already denies, so forbidden proposals never leave the machine.
5. **Capability token.** The token is short-lived (30 s by default) and
   single-use. It is bound to the tool, the exact arguments (hash), the
   amount/counterparty/data-class scope, the ledger's Merkle root, and the
   hashes of both compiled forms of your constitution.
6. **Tool gateway.** The gateway is the only component that runs tools.
   Before a tool runs it checks the token, the literal arguments, and the
   scope. It uses a Merkle consistency proof to check that the token's
   ledger root is an ancestor of the ledger it knows. It also checks that
   the constitution hasn't been reloaded and the token hasn't been revoked
   since issuance, and that the token is used only once.
7. **Personal ledger.** Every proposal, VM result, ballot, token, and tool
   execution is appended to a JSONL hash chain with a Merkle tree. The chain
   head is signed with your key, so rewriting, truncating, or appending
   without your key is detected.

Diagrams: [architecture](docs/figures/architecture.svg),
[authorize flow](docs/figures/authorize_flow.svg),
[token and gateway](docs/figures/token_gateway_sequence.svg),
[ledger](docs/figures/ledger_structure.svg),
[ledger-root-bound token](docs/figures/ledger_root_token.svg),
[one constitution, two compilations](docs/figures/two_compilations.svg),
[quorum protocol](docs/figures/quorum_protocol.svg)
(index: [docs/figures/README.md](docs/figures/README.md)).

## Quick start

Requires Python ≥ 3.10. Every command below is run from the repository root
and has been checked with `tools/doccheck.py` (see [FAQ](#faq)).

**1. Install**

<!-- check: skip the checker runs in a copy of this repository instead of cloning it -->
```bash
git clone https://github.com/sbusch305-collab/two-key.git
cd two-key
```

<!-- check: expect=^OK -->
<!-- check: expect="ok": true -->
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -q -e ".[yaml,pq]"      # pq = cryptography>=50 for ML-DSA-65 (hybrid post-quantum)
python -m unittest discover -s tests 2>&1 | tail -1
python -m compact_kernel selftest    # crypto known-answer self-test
```

**2. Create your key**

The passphrase is read from an environment variable, so it doesn't end up
in your shell history or on the command line.

<!-- check: expect=^fingerprint: -->
```bash
read -rsp "New key passphrase: " CK_KEY_PASSPHRASE; echo; export CK_KEY_PASSPHRASE
python -m compact_kernel keygen --out ~/.compact-kernel --passphrase-env CK_KEY_PASSPHRASE
```

This writes `~/.compact-kernel/principal.pem` (private, mode 0600, encrypted)
and `principal.pub.pem`. For a post-quantum hybrid key add
`--suite hybrid-mldsa65-ed25519`; see [HOWTO §2](docs/HOWTO.md#2-keys).

**3. Write and sign your constitution**

Start from the example. It is Markdown prose with exactly one
```` ```ck-rules ```` JSON block holding the hard rules for Path A.

<!-- check: expect=^OK: principal=did:ck:alice -->
```bash
cp examples/constitution_single_source.md my-constitution.md     # then edit it
python -m compact_kernel sign-constitution --document my-constitution.md \
    --principal did:ck:alice --key ~/.compact-kernel/principal.pem \
    --passphrase-env CK_KEY_PASSPHRASE --out my-constitution.signed.json
python -m compact_kernel verify-constitution \
    --signed my-constitution.signed.json --pub ~/.compact-kernel/principal.pub.pem
```

**4. Configure your judges**

Write `judges.yaml`. It names the environment variables that hold your API
keys; the keys themselves never go in the file. Replace each `<…>` model
name with a model your account can use.

<!-- check: file=judges.yaml -->
```yaml
quorum:
  required_yes: 2        # T: yes votes needed
  min_responding: 2      # K: valid ballots needed before anything is counted
  timeout_seconds: 45    # judges run in parallel; late judges abstain
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
  - id: local
    type: ollama               # local weights via Ollama at http://localhost:11434, no key
    provider: local
    model: <ollama-model-name>
```

<!-- check: expect=^OK: 3 judges -->
```bash
python -m compact_kernel check-judges --config judges.yaml    # validates only; no API calls
read -rsp "xAI API key: " XAI_API_KEY; echo; export XAI_API_KEY
read -rsp "Anthropic API key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
```

**5. Run the offline demo** (test-double judges, temporary files, no network)

<!-- check: expect=verify: ok -->
```bash
python -m compact_kernel demo
```

**6. Authorize an action and run it through the gateway**

<!-- check: file=my_agent.py -->
```python
import os
from pathlib import Path

from compact_kernel import keys
from compact_kernel.constitution import load_envelope
from compact_kernel.judges.config import load_config_file
from compact_kernel.kernel import CompactKernel

home = Path.home() / ".compact-kernel"
key = keys.load_private_any(home / "principal.pem", os.environ["CK_KEY_PASSPHRASE"].encode())
judges, quorum = load_config_file(Path("judges.yaml"))
kernel = CompactKernel(load_envelope(Path("my-constitution.signed.json")),
                       keys.load_public_any(home / "principal.pub.pem"),
                       home / "ledger.jsonl", judges,
                       ledger_signing_key=key, quorum_policy=quorum)


def pay_bill(payee, amount):          # your real tool; only the gateway calls it
    return f"paid {amount} to {payee}"


gateway = kernel.gateway(tools={"pay_bill": pay_bill})
args = {"payee": "power-co.example", "amount": 42.5}           # the literal tool-call arguments
action = {"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example",
          "data_class": "financial", "irreversible": False}    # the normalized action record
decision = kernel.authorize(action, "Pay the electric bill.", args)
print("decision:", decision.allowed, decision.reason, decision.quorum)
if decision.allowed:
    result = gateway.invoke(decision.capability, "pay_bill", args,
                            {"amount_usd": 42.5, "counterparty": "power-co.example",
                             "data_class": "financial"})
    print("gateway:", result.reason, result.result)
```

<!-- check: expect=^decision: True dual_path_pass -->
<!-- check: expect=^gateway: executed paid 42.5 to power-co.example -->
<!-- check: expect=^OK: ok \(entries=9\) -->
```bash
python my_agent.py
python -m compact_kernel verify-ledger --ledger ~/.compact-kernel/ledger.jsonl \
    --pub ~/.compact-kernel/principal.pub.pem
```

Expected output with working judges (the quorum counts will vary):

```text
decision: True dual_path_pass {'yes': 3, 'no': 0, 'abstain': 0, 'reason': 'quorum_pass'}
gateway: executed paid 42.5 to power-co.example
OK: ok (entries=9)
```

If Ollama isn't running, the local judge abstains and the other two still
meet K = 2 and T = 2. If a judge can't be reached, see
[Troubleshooting](#troubleshooting).

## The full how-to

[docs/HOWTO.md](docs/HOWTO.md) walks through every piece with commands and
code that were run to check them:

1. Install · 2. Keys (Ed25519, ECDSA P-384, hybrid ML-DSA-65) · 3. Writing a
constitution (prose, the `ck-rules` block, rule types, action fields) ·
4. Signing, verifying, loading, and reloading · 5. Judges for each provider
(OpenAI-compatible/xAI, local servers, Ollama, Anthropic, Gemini) · 6. Auth
modes (env, keyring, SSO callback, and the username/password and
device-code stubs) · 7. Quorum settings (T, K, `min_vendors`,
`min_local_judges`, `section4()`, timeouts, parallelism, ballot binding) ·
8. Authorizing actions · 9. Gateway integration · 10. Ordering and
short-circuit · 11. Revocation · 12. The ledger (verify, Merkle proofs,
head signing, fsync, anchoring stub) · 13. Crypto (`fips_mode`, classic vs
hybrid, P-384, `require_pq`, token modes, self-test) · 14. Performance and
tests

## Configuration reference

Every option below is taken from the code (`compact_kernel/`). Defaults are
the values used when the option is omitted.

### Command line: `python -m compact_kernel [global options] <command>`

The installed console script `compact-kernel` is the same program.

| Option / command | Default | Allowed values | What it does |
|---|---|---|---|
| `--fips` (global) | off | flag | `fips_mode`: refuse non-approved algorithms and the liboqs backend |
| `--pq-backend` (global) | `auto` | `auto`, `pyca`, `liboqs`, `none` | ML-DSA backend. `auto` = pyca if its OpenSSL has ML-DSA, else liboqs (not in FIPS mode), else none |
| `keygen --out DIR` | required | directory | Writes `principal.pem`/`principal.pub.pem` (ed25519) or `principal.keys.json`/`principal.pub.json` (other suites). Refuses to overwrite |
| `keygen --suite` | `ed25519` | `ed25519`, `ecdsa-p384`, `hybrid-mldsa65-ed25519`, `hybrid-mldsa65-p384` | Signature suite of the principal key |
| `--passphrase-env VAR` (keygen, sign-constitution) | prompt | env var name | Read the key passphrase from `VAR`. Without it and without `--no-passphrase` you are prompted (empty = none) |
| `--no-passphrase` (keygen, sign-constitution) | off | flag | Unencrypted private key (testing only) |
| `sign-constitution --document FILE` | — | `.md`/`.markdown`/`.txt` with one `ck-rules` block | Sign a single-source constitution (format `/2`) |
| `sign-constitution --text FILE --rules FILE` | — | text: `.txt`/`.md`/`.markdown` (≤ 1 MB); rules: `.json`/`.yaml`/`.yml` | Sign prose and rules as separate fields (format `/1`). Use either this or `--document` |
| `sign-constitution --principal ID --key FILE --out FILE` | required | any non-empty id; PEM or `.keys.json` | Principal id, private key, output envelope |
| `verify-constitution --signed FILE --pub FILE` | required | | Verify signature, hashes, and rules; exit 1 on failure |
| `verify-ledger --ledger FILE --pub FILE` | required | | Verify hash chain, signed head, size, Merkle root; exit 1 on failure |
| `check-judges --config FILE` | required | `.yaml`/`.yml` or `.json` | Validate a judge config without network calls |
| `selftest [--require-pq]` | | flag | Run the crypto self-test and print the provider; `--require-pq` fails without ML-DSA |
| `demo` | | | Offline demo with test-double judges |
| `python bench.py [--quick] [--json FILE]` | full run | | Latency and memory benchmark (`docs/PERFORMANCE.md`) |

### `judges.yaml`: `quorum:` section (`QuorumPolicy`)

Omitting the whole section gives `required_yes = min(2, number of judges)`
with every other key at its default.

| Key | Default | Allowed values | What it does |
|---|---|---|---|
| `required_yes` | `2` | integer ≥ 1, ≤ number of judges | **T**, the approval threshold: yes votes needed |
| `min_responding` | = `required_yes` | integer ≥ 1 | **K**, the availability floor: with fewer valid ballots the result is deny *without counting* (`counted: false`) |
| `min_distinct_providers` | `1` (off) | integer ≥ 1 | Distinct `provider` labels needed among valid ballots |
| `min_vendors` | `1` (off) | integer ≥ 1 | Distinct `vendor`s required in the judge set; the kernel refuses to start below it |
| `min_local_judges` | `0` (off) | integer ≥ 0 | Judges with `local_weights: true` required in the judge set |
| `heterogeneity_scope` | `selection` | `selection`, `responding` | `responding` also applies the two floors above to the judges that returned valid ballots |
| `judge_inputs` | `record_only` | `record_only`, `record_and_proposal` | What judges see besides the prose: only the normalized action record, or also the proposal text |
| `ballot_binding` | `stamp` | `stamp`, `echo` | `echo`: every judge must echo H(action record) and H(constitution) (needs `echo_binding: true` on LLM judges) |
| `require_path_a_first` | `false` | boolean | Kernel refuses `short_circuit_path_b=False` |
| `timeout_seconds` | `45` | number > 0, or `null` (no deadline) | Overall deadline for all judges; late judges abstain |
| `parallel` | `true` | boolean | Run judges in parallel threads (sequential still honors the deadline) |

In Python, `QuorumPolicy.section4(required_yes=2, min_responding=None, **overrides)`
returns the stricter profile: `min_vendors=2`, `min_local_judges=1`,
`judge_inputs="record_only"`, `require_path_a_first=True`. In YAML, set
those four keys explicitly.

### `judges.yaml`: each entry under `judges:`

| Key | Default | Allowed values | What it does |
|---|---|---|---|
| `id` | required | unique string | Judge id in ballots and the ledger |
| `type` | required | `openai_compatible`, `anthropic`, `gemini`, `ollama` | Adapter |
| `model` | required | model name (`REPLACE_…` is rejected) | Model to call; not validated offline |
| `provider` | per type: `openai-compatible`, `anthropic`, `google`, `ollama-local` | string | Label used by `min_distinct_providers`, and the default `vendor` |
| `base_url` | required for `openai_compatible`; `https://api.anthropic.com`; `https://generativelanguage.googleapis.com`; `http://localhost:11434` | `https://…`, or `http://` to loopback | API root. Plain HTTP to a non-loopback host needs `allow_insecure_http` |
| `auth` | none | see the next table | Where the credential comes from |
| `timeout` | `30` | seconds | Per-request HTTP timeout |
| `auth_header` | per type: `bearer`, `x-api-key`, `x-goog-api-key`, `none` (ollama) | `bearer`, `x-api-key`, `x-goog-api-key`, `none` | How the credential is sent |
| `allow_insecure_http` | `false` | boolean | Allow `http://` to a LAN host |
| `json_mode` | `true` | boolean (`openai_compatible` only) | Send `response_format: json_object` |
| `max_tokens` | `300` | integer (`openai_compatible`, `anthropic`) | Response token cap |
| `vendor` | = `provider` | string | Vendor used by `min_vendors` |
| `local_weights` | `false` (`true` for `ollama`) | boolean | Counts toward `min_local_judges`. A declaration, not an attestation |
| `weights_sha256` | none | string | Recorded in the ledger's judge list; not verified |
| `echo_binding` | `false` | boolean | Ask the model to echo the ballot hashes (strict 5-key JSON) |

### `auth:` types

A secret written in the file (`key`, `api_key`, `password`, `token`, or
`secret`) is refused. Hooks are `"module:function"` strings, imported when
the file is loaded.

| `type` | Fields | Status |
|---|---|---|
| `none` | | No credential (the default) |
| `env` | `var` | API key from an environment variable at call time. Working |
| `keyring` | `service`, `username` | API key from the OS keyring (`pip install keyring`). Working |
| `callback` | `callback` | `fn() -> token`; your SSO/OAuth/session code. Working hook |
| `username_password` | `username`, `password_env`, `login` | **Stub** unless you supply `login(username, password) -> token`; no vendor login is built in |
| `oauth_device_code` | `client_id`, `device_authorization_endpoint`, `token_endpoint`, `scope`, `fetch_token` | **Stub** unless you supply `fetch_token(provider) -> token` (RFC 8628) |

### `CompactKernel(signed_constitution, trusted_public_key, ledger_path, judges, **options)`

| Option | Default | Allowed values | What it does |
|---|---|---|---|
| `ledger_signing_key` | none (required) | the principal's private key | Signs the ledger head; must match `trusted_public_key` |
| `allow_unsigned_ledger` | `False` | bool | Permit no `ledger_signing_key` (testing only) |
| `quorum_policy` | `QuorumPolicy(required_yes=min(2, n))` | `QuorumPolicy` | Path B rules (table above) |
| `ttl_seconds` | `30` | positive int | Token lifetime |
| `max_steps` | `4096` | int ≥ 1 | Path A step limit, checked at compile time |
| `capability_secret` | random per process | bytes, ≥ 32 | HMAC key for tokens |
| `token_mode` | `ck1` (ed25519) / `ck1-hs384` (other suites) | `ck1`, `ck1-hs384`, `ck1-sig` | HMAC-SHA-256, HMAC-SHA-384, or signed tokens |
| `token_signing_key` | none | a `PrivateKeySet` | Required for `ck1-sig` |
| `digest_alg` | `sha256` (ed25519) / `sha384` (other suites) | `sha256`, `sha384` (tested); other approved SHA-2/SHA-3 names pass the policy check but are untested | Ledger, Merkle, args, and constitution hashes |
| `head_signing` | `decision` | `decision`, `append` | Sign the ledger head once per decision, or after every append |
| `ledger_fsync` | `True` | bool | fsync every ledger write |
| `short_circuit_path_b` | `True` | bool | Skip Path B when Path A denies |
| `crypto` | process default provider | `CryptoProvider` | Algorithm policy, FIPS mode, PQ backend |
| `require_pq` | `False` | bool | Refuse to start without a hybrid ML-DSA key and a working backend |
| `allow_test_doubles` | `False` | bool | Permit `compact_kernel.testing` judges (demos and tests only) |
| `clock` | `time.time` | callable | Clock for token issue and expiry (tests) |

Methods: `authorize(action, proposal, tool_args)`, `gateway(tools=None,
extractors=None, checkpoint_every=1, view_refresh="token")`,
`reload_constitution(envelope)`, `revoke(jti=None, reason="")`,
`crypto_profile()`.

### Gateway, ledger, and crypto provider

| Option | Default | Allowed values | What it does |
|---|---|---|---|
| `gateway(tools=)` | `{}` | `{name: callable(**args)}` | Executors. A tool with no executor returns `authorized_no_executor` |
| `gateway(extractors=)` | `{}` | `{name: fn(args) -> fields}` | Derive `amount_usd`/`counterparty`/`data_class` from the literal args |
| `gateway(checkpoint_every=)` | `1` | int ≥ 0 | Sign the ledger head every N calls; `0` = you call `kernel.ledger.checkpoint()` |
| `gateway(view_refresh=)` | `token` | `token`, `every_call` | Advance the gateway's ledger view from verified tokens, or also on every call |
| `PersonalLedger(auto_sign_every=)` | `1` | int ≥ 0 | Direct ledger use: sign after every N appends; `0` = only on `checkpoint()` |
| `PersonalLedger(digest_alg=, fsync=)` | from key / `True` | as above | Same meaning as the kernel options |
| `CryptoProvider(fips_mode=)` | `False` | bool | Refuse non-approved algorithms (`CryptoPolicyError`) and liboqs |
| `CryptoProvider(require_fips_module=)` | `False` | bool | Refuse to start unless both OpenSSL instances report FIPS mode |
| `CryptoProvider(pq_backend=)` | `auto` | `auto`, `pyca`, `liboqs`, `none` | ML-DSA backend |

### Constitution rules and action fields

| Rule type (in `ck-rules`) | Value | Denies when |
|---|---|---|
| `allow_only_tools` | non-empty list of tool names | the tool is not listed. **At least one such rule is required** |
| `deny_counterparties` | non-empty list | the counterparty is listed |
| `deny_if` | mapping of `tool`, `amount_usd_gt`, `data_class_in`, `irreversible` | **all** given conditions hold |
| `deny_if_irreversible_over` | number ≥ 0 | `irreversible` and `amount_usd` > the number |
| `id` (optional on any rule) | unique string | names the rule in deny reasons |

| Action field | Default if missing | Allowed values |
|---|---|---|
| `tool` | required | non-empty string (trimmed, case-folded) |
| `amount_usd` | `0` | number 0 … 1e12 |
| `counterparty`, `destination`, `currency` | `""`, `""`, `usd` | strings (trimmed, case-folded) |
| `data_class` | **`classified`** | `public`, `personal`, `medical`, `financial`, `classified` |
| `irreversible` | **`true`** | boolean |
| `duration_hours` | `0` | number 0 … 1e6 |
| `tags`, `raw` | `[]`, `{}` | list of strings; mapping (logged, never read by Path A) |

Environment variables: the package reads only the variables you name
(`auth.var`, `auth.password_env`, `--passphrase-env`).

## Best practices

**Recommended production profile** (the prototype's limits still apply; see
[Limitations](#limitations)):

- Key: `hybrid-mldsa65-p384`, or `hybrid-mldsa65-ed25519` where Ed25519 is
  approved in your module. Passphrase-encrypted, with `require_pq=True`.
- Crypto: `CryptoProvider(fips_mode=True, require_fips_module=True)` on a
  validated module (below).
- Quorum: `QuorumPolicy.section4(required_yes=2, min_responding=3)` with at
  least three judges from at least two vendors, at least one of them on local
  weights, `heterogeneity_scope="responding"`, and `ballot_binding="echo"`
  with `echo_binding: true` on every LLM judge.
- Kernel: `short_circuit_path_b=True` (the default), `head_signing="decision"`,
  `ledger_fsync=True`, and `ttl_seconds` as short as your tools allow.
- Gateway: one instance from `kernel.gateway()`, in the same process as the
  kernel, with extractors for every money-moving tool and
  `checkpoint_every=1`.
- Verify: run `verify-ledger` on a schedule, and keep a copy of the signed
  head somewhere the agent can't write.

**Security hardening**
- Only the gateway may hold real tool credentials. Give the agent the
  kernel and the gateway, never the tools.
- Always put an `allow_only_tools` rule first, so unknown tools fail closed.
- Keep the constitution's rules strict and its prose specific. The prose is
  what the judges read, so vague prose gives vague ballots.
- Register gateway extractors, so the scope fields are derived from the
  literal arguments rather than trusted from the caller.
- Never set `allow_test_doubles`, `allow_unsigned_ledger`, or
  `allow_insecure_http` outside tests and a trusted LAN.

**Key handling**
- Keep private keys out of the repository and off shared disks. Keygen
  writes mode 0600 and refuses to overwrite.
- Use a passphrase, supplied with `--passphrase-env` from `read -rs` or a
  secret manager, never on the command line.
- Back up the private key offline. Losing it means you can't sign a new
  constitution or ledger head, and the kernel won't start on a ledger whose
  head it can't verify.
- Production should hold the principal key in a TEE/HSM. That isn't
  implemented; keys are files.
- `capability_secret` is random per process by default. Pass your own only
  if something else must verify tokens, and then protect it like a key.

**Judge diversity**
- Use different vendors, plus at least one local model, so one vendor's
  outage, policy change, or compromise can't pass or block everything.
- Set K (`min_responding`) above T only if you accept more denials during
  outages. K = T is the fail-closed minimum.
- `vendor` and `local_weights` are self-declared. Label them honestly;
  nothing verifies them.

**FIPS deployment**
- This code is **not** FIPS certified or validated. Compliance comes only
  from running it on a CMVP-validated module in approved mode.
- The OpenSSL 3.1.2 FIPS provider (cert #4985) has no ML-DSA, and Ed25519
  isn't approved there, so use the `ecdsa-p384` suite (hybrid ML-DSA would
  then run outside the module).
- pyca `cryptography` must be built against the FIPS-enabled system OpenSSL
  (the wheel bundles its own).
- See [docs/CRYPTO.md](docs/CRYPTO.md) for candidate modules and the
  algorithm map.

**Performance tuning** (numbers in [docs/PERFORMANCE.md](docs/PERFORMANCE.md))
- Real judge latency (network, model) dominates; the kernel adds about 1 ms
  per decision. Keep `parallel: true` and set `timeout_seconds` to what you
  can tolerate.
- Signing the ledger head is the largest local cost, especially with hybrid
  keys. `head_signing="decision"` (the default) and `checkpoint_every=N` or
  `0` with a timer reduce it; unsigned entries show as `size_mismatch` until
  the next checkpoint.
- `ledger_fsync=False` is faster but can lose recent entries on power
  failure.

**What not to do**
- Don't put API keys, passwords, or tokens in `judges.yaml` (the loader
  refuses them) or in the constitution.
- Don't let the proposing model write the action record unchecked. Who
  produces that record is an open design question (problem F); until it's
  settled, derive fields from the literal arguments wherever you can.
- Don't run the gateway in a separate process that opens the same ledger
  file, and don't create two gateways for one kernel. One process owns the
  ledger, and each gateway instance tracks used tokens on its own.
- Don't reuse a token, extend its TTL to minutes, or log it; it's a bearer
  secret until it expires.
- Don't treat `weights_sha256` or `local_weights` as verified.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `constitution rejected: no allow_only_tools rule` | Path A requires an allow-list | Add an `allow_only_tools` rule |
| `expected exactly one ```ck-rules block, found 0` | Missing, misspelled, or duplicated rules fence | Exactly one block whose opening line is ```` ```ck-rules ```` |
| `REJECTED: signature does not match` | The constitution changed after signing | Re-sign it |
| `downgrade refused` / `signed by a key other than the principal's` | Wrong public key or suite | Use the public key that matches the signing key |
| `INVALID: … set 'model' to a model you have access to` | A `REPLACE_…` placeholder is still in the file | Set the model name |
| `INVALID: secrets must not be written in judges config` | `key`/`token`/… in `auth` | Use `env` or `keyring` |
| `refusing plain-HTTP judge endpoint` | `http://` to a non-loopback host | Use HTTPS, or `allow_insecure_http: true` on a trusted LAN |
| `judge set is not heterogeneous enough: insufficient_vendors:1<2` | `min_vendors`/`min_local_judges` not met | Add judges from another vendor or a local model |
| Deny `path_b_denied:insufficient_responses:1<2` | Fewer than K judges answered | See `decision.quorum` and the ledger's `quorum_result` ballots (`error` says why: `credential: …`, `http 401`, `transport: …`, `timeout …`, `malformed_ballot …`) |
| Ballot error `credential: environment variable X is not set` | API key not exported | `export X=…` in the process that runs the kernel |
| Ballot error `http 404` / `http 400` | Wrong model name or endpoint | Check `model` and `base_url` |
| Deny `invalid_action:…` | The action record failed validation (unknown field, bad type, unknown data class) | Fix the record; see the field table |
| Gateway `args_mismatch` | The arguments at invoke differ from those authorized | Pass exactly the same `args` mapping |
| Gateway `replayed` | Tokens are single-use | Authorize again |
| Gateway `expired` | TTL passed | Authorize closer to execution |
| Gateway `constitution_hash_mismatch` / `constitution_changed_since_issue` / `revoked` | The constitution was reloaded, or the token revoked, after issuance | Authorize again under the current constitution |
| Gateway `ledger_root_not_ancestor` / `ledger_fork_detected` | The ledger was rewritten or truncated, or the token comes from another ledger | Run `verify-ledger`; investigate before continuing |
| `verify-ledger` says `size_mismatch:head=N,file=M` | Entries appended after the last signed head (a crash, or `checkpoint_every=0`) | Run the kernel (it checkpoints), or investigate if unexpected |
| `LedgerError: existing ledger failed verification` at start | Ledger or head file tampered, or a different key | Restore from backup, or start a new ledger file |
| `PQUnavailableError` | Hybrid key without an ML-DSA backend | `pip install "cryptography>=50"` or use a classical suite |
| `CryptoPolicyError: require_fips_module=True but no active FIPS provider` | No validated module active | Deploy on a FIPS-enabled OpenSSL, or drop `require_fips_module` for development |
| `KernelConfigError: test-double judges supplied` | `compact_kernel.testing` judges in production code | Use real judges (or `allow_test_doubles=True` in tests) |

## FAQ

**Does the kernel call any network service by itself?** Only the judge
connectors you configure call out. Path A, the tokens, the gateway, and the
ledger are local. The tests and the demo make no network calls.

**Can a model vendor change my constitution?** No. Loading and reloading
require a signature under your trusted key. A refused reload is logged as
`constitution_reload_refused`, and tokens issued before a successful reload
stop working.

**What do the judges see?** Your prose and the normalized action record,
marked as untrusted data. The proposal text is included only with
`judge_inputs: record_and_proposal`. The rules block is never sent.

**Why did my allowed-looking action get denied?** Read `decision.reason`:
`path_a_denied:rule_denied:<id>` names the rule, and `path_b_denied:…` gives
the quorum reason. The ledger has every ballot's rationale.

**How were the snippets in these docs checked?** `python3 tools/doccheck.py
README.md docs/HOWTO.md` runs every command and code block in a copy of the
repository with a fresh virtualenv and HOME. Judge HTTP calls go to a local
fake that answers in each provider's format, so no real model was contacted.

**Is it FIPS compliant or quantum-safe?** It uses only FIPS-approved
algorithms and can sign with hybrid ML-DSA-65, but it isn't validated. See
[docs/CRYPTO.md](docs/CRYPTO.md).

## Limitations

- **Prototype.** It has not been security-reviewed or deployed.
- **Not FIPS validated.** The development machine had no FIPS provider, and
  ML-DSA came from pyca `cryptography` 50.0.1 with its bundled OpenSSL 4.0.2,
  which is not a validated module.
- **Action-record normalization (problem F) is open.** The caller supplies
  the record, and extractors are an optional hook. Path A is only as good
  as the fields it's given. See `DESIGN_OPTIONS.md` §1.
- **Real model connectors are tested only against mocked HTTP.** No live API
  call has been made.
- **The username/password and OAuth device-code auth modes are stubs.**
  They work only with a hook you supply.
- **Public anchoring is a stub.** `LocalFileAnchor` writes a local file;
  nothing is published.
- **Keys are files, not TEE/HSM-held.** Tokens use an HMAC secret shared by
  issuer and gateway by default.
- **Storage.** The ledger isn't encrypted, and one process must own it.
- **Defaults are permissive.** The §4 (iii) quorum floors are off by
  default (`section4()` turns them on); which default to use is open
  (`DESIGN_OPTIONS.md` §7).
- **liboqs is untested.** The backend adapter has been tested only against
  a fake module.

## Repository layout and further docs

| Path | What |
|---|---|
| `compact_kernel/kernel.py` | `CompactKernel`: load, authorize, reload, revoke |
| `compact_kernel/policy_vm.py`, `compiler.py` | Path A compiler and VM; one signed source compiled to bytecode and prose, with hashes |
| `compact_kernel/quorum.py`, `judges/` | Path B quorum; judge adapters, credentials, config loader |
| `compact_kernel/capability.py`, `gateway.py` | Tokens and the tool gateway |
| `compact_kernel/ledger.py`, `merkle.py`, `anchoring.py` | Signed ledger, Merkle proofs, anchoring stub |
| `compact_kernel/crypto/`, `keys.py`, `constitution.py` | Crypto provider and suites, key files, constitution signing |
| `compact_kernel/testing.py` | Offline test-double judges (not for deployment) |
| `examples/` | Example constitutions (one-file and two-file), hard rules, `judges.yaml` |
| `tools/doccheck.py` | Runs every snippet in this README and `docs/HOWTO.md` |
| [docs/HOWTO.md](docs/HOWTO.md) | Step-by-step guide |
| [docs/CRYPTO.md](docs/CRYPTO.md), [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | FIPS posture and algorithms; measured performance |
| [docs/SPEC_DRAFT.md](docs/SPEC_DRAFT.md), `docs/INVENTION_DISCLOSURE.md` (unchanged) | Working specification draft; original disclosure |
| `CONCEPTION_NOTES.md`, `DESIGN_OPTIONS.md`, `CHANGES.md` | Inventor's dated notes; open design questions; every change and who decided it |

## Patent posture

This repository contains an invention disclosure and a working prototype. AI
cannot be named as an inventor. Read `CONCEPTION_NOTES.md`,
`docs/SPEC_DRAFT.md`, and `DESIGN_OPTIONS.md` with a registered patent
attorney. This is not legal advice.

<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# The tool check: a tool that checks its own calls

This guide is for operators who run an MCP server behind `two-key mcp-proxy`,
and for anyone who writes such a server, in Python or any other language.
It describes the tool check added in 0.9.0 (#28). Two-Key is beta and not
independently audited. If this guide disagrees with the code, the code wins.

## Contents

<!-- toc -->
- [In plain words](#in-plain-words)
- [Turn it on](#turn-it-on)
- [The Python helper](#the-python-helper)
- [The wire format](#the-wire-format)
- [The checks, in order](#the-checks-in-order)
- [What Two-Key does with the receipt](#what-two-key-does-with-the-receipt)
- [Write the check in another language](#write-the-check-in-another-language)
- [Test vectors](#test-vectors)
- [What it does not cover](#what-it-does-not-cover)
<!-- /toc -->

## In plain words

Without the check, the MCP server trusts whoever calls it. Two-Key only
protects the server if every call goes through `two-key mcp-proxy`. Anything
that can reach the server another way, such as a second MCP host or a
script, skips both keys.

With the check, the server asks for proof on every call. The proxy sends the
spent capability token and a **redeem stamp** with the call. The stamp is
Two-Key's signed statement that the token was spent at a given ledger
position. The server checks both, runs the call only if they hold, and
signs a **receipt** over the result. Two-Key checks the receipt and records
it in the ledger.

So a call that did not come through both keys is refused by the server
itself, and the ledger shows which result the server actually returned.

- It is per tool and off by default. It is turned on in the tool's
  **signed** spec, so only the principal key can turn it on, off, or change
  the tool's key.
- Under `high_assurance`, every tool behind the proxy needs it, or must be
  marked `exempt`. An exemption is a weaker setting: it needs
  `--confirm-weaker` and a typed yes, and the ledger records it.
- It is for tools behind `two-key mcp-proxy` only. In the library and guard
  routes the tool runs inside Two-Key's own process, where a check adds no
  isolation. A checked tool there is refused (`tool_check_needs_proxy`).

## Turn it on

1. Make the tool's receipt key, as the account the server runs as:

   ```sh
   two-key tool-key new --out /srv/billing/two-key/tool.pem
   ```

   It prints the key's fingerprint (`hybrid-sha256:` and 64 hex digits). The
   key is a hybrid Ed25519 + ML-DSA-65 key, like every key Two-Key makes from
   0.9.0. The key file is readable by its owner only, and it is never
   overwritten.

2. Sign the fingerprint into the tool's spec, as Two-Key's own account:

   ```sh
   two-key config set --config proxy.yaml --key principal.pem --rules hard_rules.yaml \
       tool_specs.pay_vendor.tool_check '{"key": "hybrid-sha256:..."}'
   ```

   `two-key setup` asks for it too (a tool's "tool check" question, or the
   column of that name in the setup window). Turning the check on is
   stronger, so it needs no `--confirm-weaker`; like every signed change,
   `config set` shows the new constitution and asks you to type `yes` before
   it signs. `exempt`, removing it, or a different key is weaker: it also
   needs `--confirm-weaker`, and the refusal without it says which
   (`tool_check: exempt (the check is turned off)`, `turned off`, or
   `another receipt key`). `--rules` is the source the constitution was
   signed from, `hard_rules.yaml` in a folder `two-key setup` made, not the
   rules file setup read.

3. Start Two-Key once (`two-key mcp-proxy`). Its first start with a checked
   tool makes the gateway's **stamp key**, beside the capability key, and
   records both public keys' fingerprints in `constitution_loaded`.

4. Give the server Two-Key's two public keys, checked against what the ledger
   pins:

   ```sh
   two-key tool-key trust --key principal.pem --ledger ledger --out /srv/billing/two-key
   ```

   It writes `two-key-capability.pub.pem` and `two-key-stamp.pub.pem` and
   prints both fingerprints.

5. Write the server's check config, a JSON file. Relative paths are relative
   to the file:

   ```json
   {
     "tool": "pay_vendor",
     "capability_public_key": "two-key-capability.pub.pem",
     "capability_key_fingerprint": "hybrid-sha256:...",
     "stamp_public_key": "two-key-stamp.pub.pem",
     "stamp_key_fingerprint": "hybrid-sha256:...",
     "tool_private_key": "tool.pem",
     "seen_record": "seen.sqlite"
   }
   ```

   `tool` is the tool's signed id. Loading refuses a public key whose
   fingerprint is not the one written here.

6. Wrap the tool (next section), restart the server, and run
   `two-key config check --config proxy.yaml`. It lists each tool's check:
   on, exempt, or off. If the server finds its check config through a
   variable, pass it in `upstream.env` as a name read from the proxy's own
   environment, `{"env": "NAME"}`, or from a file with `--value-file`: a
   literal `upstream.env` value on the command line is refused
   (`secret_on_command_line`), since such a value can be a secret.

   ```sh
   two-key config set --config proxy.yaml upstream.env.BILLING_CHECK_CONFIG '{"env": "BILLING_CHECK_CONFIG"}'
   ```

## The Python helper

`two_key.toolcheck` has both sides. A server on the MCP Python SDK's
low-level `Server` wraps its tool like this:

```python
from two_key.toolcheck import ToolCheckConfig, ToolChecker

checker = ToolChecker(ToolCheckConfig.load("/srv/billing/two-key/check.json"))

async def call_tool(ctx, params):
    if params.name == "pay_vendor":
        return await checker.mcp_call(params.arguments, params.meta, lambda arguments: pay(arguments))
    ...
```

`mcp_call` runs the checks before `pay` and never calls it when one fails.
It then returns the tool's result with the receipt added to the result's
`_meta`. A refused call returns an error result whose text names the reason,
with a refusal receipt. The tool's own code is never reached on a refusal,
and an error inside the helper, such as an unreadable key file, is a
refusal too. Only use the helper this way: a pattern that catches the
refusal and runs the tool anyway turns the check off.

For another framework, call `checker.check(arguments, meta)` (it raises
`ToolCheckError` with the reason), run the tool, then
`checker.receipt(call, result)` with the result in MCP wire form. On a
refusal, send `checker.refusal(reason, meta)`.

## The wire format

The proxy puts one key in the `tools/call` request's `_meta`:

```json
{"_meta": {"io.github.insomniac-vibelabs/two-key": {"token": "tk2....", "stamp": "tks1...."}}}
```

The server returns the receipt under the same key in the result's `_meta`:

```json
{"_meta": {"io.github.insomniac-vibelabs/two-key": {"receipt": "tkr1...."}}}
```

The proxy removes the result's `_meta` before the agent sees the result, so
the agent never sees the receipt. The token and stamp leave Two-Key only
after the gateway has written `redemption_started`, so the token is already
spent when the server sees it.

The three objects hold ids, hashes, a ledger position and times. They never
hold an argument value, a result, or a secret.

### Hashes and signatures

- **Canonical JSON** is JSON with sorted keys, no whitespace, and no
  non-finite numbers, in UTF-8 (`two_key.canonical.canonical_bytes`).
- A **hash** is `sha256:` and the hex digest. `tool_args_hash` is the hash of
  the canonical JSON of the arguments as the tool receives them. A token,
  stamp or receipt is hashed as its ASCII text.
- `result_hash` is the hash of the canonical JSON of the MCP result in wire
  form (camelCase keys, fields that are not set left out), without `_meta`.
- A **stamp** or **receipt** is `<prefix>.<body>.<signature>`. The body is
  the canonical JSON in base64url without padding. The signed message is the
  purpose label, one zero byte, and the body text. The label means a
  signature made for one purpose fails for any other.
- The **token** is Two-Key's `tk2.<body>.<signature>`. Its signed message is
  the body text, with no label, and the capability key signs it. Its payload
  has `"v": 2` and `"alg": "ed25519+ml-dsa-65"`.
- Every **signature** is hybrid, and the check takes no other kind: the
  64-byte Ed25519 signature then the 3,309-byte ML-DSA-65 (FIPS 204)
  signature, 3,373 bytes in standard base64. Both sign the same bytes:
  `two-key-hybrid/1`, a zero byte, `ed25519+ml-dsa-65`, a zero byte, then
  the signed message above. ML-DSA-65 signs with the context string
  `two-key`. Verify both halves; refuse a signature of any other length.
- A **public key** in raw form is the 32-byte Ed25519 key then the
  1,952-byte ML-DSA-65 key, in standard base64. Its **fingerprint** is
  `hybrid-sha256:` and the hex SHA-256 of those 1,984 bytes. A key file is
  two PEM blocks, Ed25519 first: PKCS#8 for a private key (ML-DSA-65 in
  seed form), SubjectPublicKeyInfo for a public one.

### The token field

A checked tool's token has one more field, `tool_args_hash`, signed with the
rest. The token's other fields that the check reads are `v`, `alg`, `jti`,
`tool`, `iat` and `exp`.

### The redeem stamp

Prefix `tks1`, label `two-key-redeem-stamp/1`, signed by the gateway's stamp
key. That key signs stamps only, and is a separate key from the capability
key.

| Field | Meaning |
| --- | --- |
| `v`, `alg` | `1` and `ed25519+ml-dsa-65` |
| `jti`, `tool` | The token's |
| `tool_args_hash` | The token's, recomputed by the gateway from the arguments it sends |
| `token_hash` | The hash of the token's text |
| `seq` | The ledger position of the `redemption_started` entry |
| `iat` | When the gateway signed it, in Unix seconds |

### The receipt

Prefix `tkr1`, label `two-key-tool-receipt/1`, signed by the tool's key.

| Field | Meaning |
| --- | --- |
| `v`, `alg` | `1` and `ed25519+ml-dsa-65` |
| `key` | The tool's public key, raw (both halves), in standard base64. Two-Key accepts it only if its fingerprint is the one in the signed spec |
| `jti`, `tool` | The token's. `jti` is `null` on a refusal whose token could not be read |
| `stamp_hash` | The hash of the stamp's text |
| `result_hash` | The hash of the result, or `null` on a refusal |
| `outcome` | `ran`, or `refused:<reason>` |
| `iat` | When the tool signed it |

## The checks, in order

The tool runs these before its own code and stops at the first that fails.
A failure means the tool does not run.

| # | Check | Refused as |
| --- | --- | --- |
| 1 | The request carries a token and a stamp. There is no "check only if present" | `check_missing` |
| 2 | The stamp's signature, with the pinned stamp key and the stamp label | `stamp_invalid` |
| 3 | The token's signature, with the pinned capability key | `token_invalid` |
| 4 | They belong together: the stamp's `token_hash` is this token's hash, and its `jti` and `tool` are the token's | `stamp_mismatch` |
| 5 | The token's `tool` is the name this tool is configured with | `tool_mismatch` |
| 6 | The hash of the arguments the tool received equals the token's and the stamp's `tool_args_hash` | `args_mismatch` |
| 7 | `exp` has not passed and `iat` is not ahead, with a fixed 5-second allowance for clock difference, and the token lives at most 300 seconds | `expired` |
| 8 | The `jti` is added to the seen record in one atomic step; one already there is refused | `replayed` |

Anything else that goes wrong inside the helper is `check_failed`.

Check 8 also refuses a retry after the tool failed. That matches the gateway
from 0.9.0, where a tool error spends the token: the agent asks again and
gets a new token.

### The seen record

The helper keeps the jtis it has accepted in a small SQLite file, readable
by its owner only. It uses Python's standard `sqlite3` module, which the
official Python builds for Linux, macOS and Windows include. On a Python
built without it, the helper refuses every call rather than skipping the
check. An entry is removed once its token could no longer be valid, so the
file holds a few minutes of ids. Copies of one server that share the
record refuse each other's replays: point them all at the same file.

A server that cannot keep a file can still run checks 1 to 7, but then it
has **no replay protection**.

## What Two-Key does with the receipt

The gateway checks the receipt against the tool key pinned in the signed
spec, and that it names this jti, tool, stamp and result, with `outcome:
ran`. Then it writes `redemption` with `stamp_hash`, `receipt_hash` and
`receipt_outcome: ran`.

A receipt that is missing, signed by another key, for another call or
result, or a refusal, is written as `tool_receipt_invalid` with why
(`missing`, `bad_signature`, `mismatch`, `refused:<reason>`), and sent to
the SIEM at once. The tool did run (or refused), so the token stays spent.

- **Default profile:** the agent still gets the output.
- **`high_assurance`:** the agent gets `tool_receipt_invalid:<why>` instead of
  the output, so it cannot act on a result Two-Key cannot vouch for. The tool
  is then **held** (`tool_held`): every later call to it is refused
  `tool_held`, also after a restart, until the operator runs:

  ```sh
  two-key tool release pay_vendor --key principal.pem --ledger ledger --reason "clock fixed on the billing host"
  ```

  The release is ledgered as `tool_released` with its reason. Under
  `high_assurance`, a refusal receipt most likely means a wrong key or a
  wrong clock, and the operator should look before releasing.

Other refusals at the gateway, before anything is ledgered as started:
`tool_args_mismatch` (the token's `tool_args_hash` is not the hash of what
the gateway would send), `tool_check_needs_proxy`, `stamp_key_missing`.

A changed or missing stamp key refuses to start (`stamp_key_changed`,
`stamp_key_missing`), as a changed capability key does: the tools pin it.

## Write the check in another language

Follow [The wire format](#the-wire-format) and [The checks, in
order](#the-checks-in-order), and check your code against the test vectors
below. Two details matter most:

- Verify the stamp with its label: the signed message is
  `two-key-redeem-stamp/1`, one zero byte, then the body text. A signature
  over the body alone must fail.
- Hash the arguments exactly as received, in canonical JSON. A reordered key
  or a reformatted number gives another hash, and the check refuses.

## Test vectors

Hybrid keys made from fixed 32-byte seeds (the capability key's Ed25519 half
from 32 bytes of `0x01` and its ML-DSA-65 half from `0x11`, the stamp key from
`0x02` and `0x12`, the tool key from `0x03` and `0x13`), with fixed times.
ML-DSA-65 signs with fresh randomness, so a signature made again differs:
`tests/test_toolcheck_vectors.py` makes the keys, hashes and bodies again and
fails if they differ, and checks that each signature here verifies and that
this token and stamp pass the tool's checks. The token, the stamp and the
receipt are each shown as their three parts; on the wire they are one string,
the parts joined with dots (`prefix.body.signature`).

<!-- vectors -->
```json
{
  "capability_public_key": "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",
  "capability_key_fingerprint": "hybrid-sha256:4c545d70d1b6ac6cea54ea9a2e88562ce29104d616c19bc4504ae1496dfd0e45",
  "stamp_public_key": "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",
  "stamp_key_fingerprint": "hybrid-sha256:41a7a08e9bd213af172bec38150f00bc6ab4c5b1a742dac3cb255fda41281816",
  "tool_public_key": "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",
  "tool_key_fingerprint": "hybrid-sha256:e2bf83175f3a35ff2f147e7c52e3f8bb65d89a4f64d29e4e4c3dca6e2aa6e452",
  "arguments": {
    "amount": 12.5,
    "vendor": "ada"
  },
  "tool_args_hash": "sha256:e8046316d49bd6332578496f57866f74525954ac5c330a19cc29349819e0d11a",
  "token": {
    "prefix": "tk2",
    "body": "eyJhbGciOiJlZDI1NTE5K21sLWRzYS02NSIsImFyZ3NfaGFzaCI6InNoYTI1NjowMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiYnl0ZWNvZGVfaGFzaCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJleHAiOjE4MDAwMDAxMjAsImlhdCI6MTgwMDAwMDAwMCwianRpIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJsZWRnZXJfcm9vdCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJsZWRnZXJfc2l6ZSI6NywibmxfaGFzaCI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJzcGVjX2hhc2giOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwidG9vbCI6InBheV92ZW5kb3IiLCJ0b29sX2FyZ3NfaGFzaCI6InNoYTI1NjplODA0NjMxNmQ0OWJkNjMzMjU3ODQ5NmY1Nzg2NmY3NDUyNTk1NGFjNWMzMzBhMTljYzI5MzQ5ODE5ZTBkMTFhIiwidiI6Mn0",
    "signature": "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"
  },
  "stamp": {
    "prefix": "tks1",
    "body": "eyJhbGciOiJlZDI1NTE5K21sLWRzYS02NSIsImlhdCI6MTgwMDAwMDAwMSwianRpIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJzZXEiOjgsInRva2VuX2hhc2giOiJzaGEyNTY6MzVlOTllZGYyNTE0OGQwZjkzYTg4MmMwNzg4YTNlMWVmNjNhNzZhMzllZmMyYzVhNGE5ZDk0NzE3NTIwZDgyNiIsInRvb2wiOiJwYXlfdmVuZG9yIiwidG9vbF9hcmdzX2hhc2giOiJzaGEyNTY6ZTgwNDYzMTZkNDliZDYzMzI1Nzg0OTZmNTc4NjZmNzQ1MjU5NTRhYzVjMzMwYTE5Y2MyOTM0OTgxOWUwZDExYSIsInYiOjF9",
    "signature": "fAPBKtZShbusiGTod8iaBFSHzXF1tlpiJTBDnTlje84/Jap2Y9iPht+bk23bHr/9uKOxFXJ7aRnqBiJ2VvGXCBbVz8Y25CSSRibKcWuSDhRolrNVnPuLiEUdi5/GXf/YVW2yhVVYXdfwxhymCXgPoJssr2BdFlUjI8bCETl0C2ucMFUdbIaqe+vhuLfkVw9MTnBZItxAueojJqZ0nuT8qixQLrALZWIaPmRbkMXC5riCRyQl/bsblsRVUywdwjG3QSCQpCdXT37jQ1C7P6S21+gNIZ5VD2uOXmH0GkHKQqp3qCg2716sBWpu5nAUVpGPXgs4QQSQhqBJZG/wGt2f0Is5m4xeAIUy2OQh6wiPzt9/Nj56QuNDkgsRYAEopIO+xvtcRjiH5A5QEVu9RvGEU8uyE0jYMTDo+z6X5JhHjPCFDjQ7Gj7JTpKCTddUY2WX89DRwBVwzSZX571OghmDx99jROZVtSLhgRa3kVSgKlj6YOAk/y2Na1gK6u+ZvvfVaV+UkSeCcijY/q22zu+7Wlkh2StAJBJ8YC94T12+heQCDT8HBSOvduKxp6kCsHTFeSiXhNNkW4421lvMOHApngwyYp9YdrWWi8bjp3AZYfLBMlQF0N0hf+oLSywh2rhKSqq0Z0hFsb7XvAkjhg5j2k6j6JhZHNXmGcdGigi5b50YQ9JydnvyRj4xyYyBAFVA4jHFNdAwp+vTJ9J1Mz4+spSvquo5dsYaTtfDfXtubv6+G5cpcu2HFMKcIElx26jsuA7wwR9ngMH6kAVOEQa7JlmuPVhbsQ5WOXVJhkIlQ65g3CXiu8BGG0ntB7kRopM+/xCvTKyquaTXudCsoSvVR2Oq4Ykp3D+W9IaeALqVKfn9oEyopYCMSAUQ16g2pmpFgkOtrZE0lJzwjLprJescStjneg9PZDjDhU5hqYiNFqUiZrBIZf92hNy6EeeUS+SxFcfKRUWh9TmHlgaAyfAh+DaPSczjfkoi6nORWPYj49ZZJUVRxPpNJqa2dJefFPVhNRnv+yOhN/LzW+0dak9TkyMyzz6LJ8FCZZXDcJevdt1h7x/sRJYbwxN4m3J5f7GHW+YPPuiVQqRu1QcgE5EtvYobk0w3VDAk8s476Jp91INCbDoC/z0zqaRNZVVyh3m12V/nXB8d9YF47G/8IqZlfhnmXfPepxssNBxVIaQkrm2QwhTU6Uico7z5A08UJXECdvImxsp3NJR7NUE8oZBA1ib3utfoqGa43K+m2N31IF8oxPj8epwkLMj6LL5yiHGnifmddo9BdRFF3+7ALUv9Um3rWALGW9UC9eCZWjpPS3odZrsURgoEthhhQI3u6kpWMDeovAmXTXEZiLR5dhrWwUj+TZ9+r6vVLSy7roufWOPV95nREmAs7DJe0Q9OqKbnQRsE0RbHLhlo+3lhR4sCwV8N1YbJYZ9b5W7WnsdMRUTI4oed9m9RRZjZQPVpqDJbDmOBc6B7YSLV74YcJWKngh5AYlUvJI2iIinFabAQa8+TShAFZGJpQqbO+ijE0VwfjG2CBrocJmmVX4tbF4t+PDRktNzKnzAOhxWP8o2YkQ1sbg6wU1EBsiQhFmjazofd/rYHmYatH+/0cRU14+Tms3bHGpJePziph9QLdX1WRpow5kgmxncEttCvnubcMg02t9Ye1LrpD/3PzSadauSrbQsY2gTztwIPGKkdEn+U97SKB016/w/le7RUFcDKpb28nocgXMA1Z/ascGLFcTy4sgAcrkvbwtuvDMmDf6XRnCxYGA2vqWqQnWOOppiH22nx/KyIyjXX1OkuifVZ4EK6o32S9raoDKAonN36Ho0LZtXq3t1QQ1AQiGOxB3mQTLWRSaRaHdN4ReM3WmBw9iQXLh6E2/BNhj0YGTCYrjn46jwU78xSVTdulTAWjxYrmnLndaVtsccjZS2JqHwXcFWdi5PNRCu+9E+GD7q22C7n/Ha8hvJLy/Mb49sh9jsvmtnwmyncrNkwHPTC+b6KvkQlhhBgGpp9XiFIoqjqBSN/CQ2jjyGuwyUJfIBDFc8j+lguA5FyvKMek625eckVhwcGmRTEzt9MOSopCVF/FrRZd1CxmzVXEuD82rVRy4sHUA4Taovl9PkFfs+fZRpjFu/JECrGeWlclCsEQWiPDjX4lo+56sQ+iMfmcwNSY8/Kuv0l+zq3cuyjBTPlYJs+8wb54tcrn6HOvB5LKaCshOKHcsBIXSIJ6gORActscYECx/25SRImedos1PBh2D9Uw8oevd07LvqPBF6YCOrVWsla80PcZ3pGYTCTe+0VqeEMPbflBUZko1RSo7M3Y5Fz1kN1/PM5rcl33RsYtzi5kPRfm55VX4BLruyiS+dbr2nCzrGwvIh61HiLEOWyGtLmIU04UKe6A2N03bXXp+KpkHF3vCZ6FAj232wUmwTptFeQBjFQ2bva3BRqlo7SE8izvtFSnUpHOAJASRC/gMkBr5jxcWqFpHNKxc+1L2tJP0To5FFo5lWMCyubH2s2kQF2MMgRcIybyqAhOJphruR+efyM4nAhdF7UXvsbTHAw05SxoB1TCi+8rOqFA53e0/vGaoPpU7wgcODbVxCpnvXWBilgPIHkbjUy0zmR9UUaMIOMop7B6xHtAv98KbtcXic4ixK306FUnSWs0Czj71ZrPGKsYDhvxS1iaKHRRrsMTiHm8t+zrYWWw2si8RRdm93T4F7X+Aemj5zEk3KbieXklCLY4H8sXUNujclEpcwYvAQue6B00fzGhkvwvRbvrKc+hMLikU9CxeM5VIgJKUltVi4A6iQ5c92tQkdR5Z1CC60L9cvP7Td7HXUWvKhAgmdz6TUVJUE15EE0u+WdviPTyoIBz3Rk82U/w+gQu6QfpN+i1lWn+eOlsIijhuZ0n3Lon4y8XoYxn4aRiQGncFHH47jNs+nGxVNHNsC/XhQ3/PujMIHrR9Uiz/fdM49iyMcUHahn0skFeq/bAMOAVUI1BRBlWrwWB8MprkYFoSfHIFenanDNDA1wrz87Mjfp2BnmiPgH+U6MRBzevhW/9GoyQU5Sw9YpyrZ1CZkaL1n50TuIU/dnIoCW0u/YKR4yYY3WW6H+EbewEU/iyrzKUEvaan/Sf8jHWlFVwgveWWjf8gtxoPHUWoDd843JLq/FzWi9dmKJ/UAXXXGiZW7w3xJufGhJojI0cilt2w2T3AR6z+bRdy75H+ixTctGp61NVYCBvO8so9r4OYGwntudcjTAeiuEBkRzqWx2FOmlQANizr58Zmr3GmUZa1dwA3AMMj6PqaAZDYkbRRzZNy7JtYP+WxiU+dnBe5+gHmi9SKfTVJsNYRkmJm1knNThxQ7OIeX/PD4a7jkQGksLSGliOV4hTXRRx5k12GuS0jZJqY4/VoimsXtj/xzww/GQugQk0eiZDdNWiQssKpMBzw2D6om7KsQEUWy9GPLh2MMC+KezMLzTuSEaPULOiEy9eHE3I9XeUXNFCMJV73jS/HYOh9Q4i1vHPK4jeXXHMSgsJVNyOoNMAvnPjAOMhOktwWW12/OMLkyC1AaEZbK2G8VvN+8CzT/+uJ57F0Ga0sD+sgkTuf6X78NioLhDUZ/+70myjRPSE9ThN8IarYVZnaXnK6zANLWp0UIURPxQT8cX1E6wyVSdaJzJHhY/xyvkibszhHiBsUFat5v1ozQTGMgK10XnI/h2XkU2IbAoffquyLS79y1yapSbzv8QsngIDxANNg8VykrJQrOWeyI7nUiBixEmHIrK2BhNgca9vW9J+eqbuDoyaKQSIlZdts5Q8bzPfFIg+XHLg0Km12EpVY7az0jXp56DgiO1VtjmqQLvqrjFcwM0fotI82xMYkGufPqKcYoCDIkTKUusumzlORqCj1EBBqNz73lH4raHXEk44Bne7ldObbBddp6vvVR/UE8xN7YowYOwyO+SvsWYACqJ64DoyR4hCHlpOeRKoQ4/3Hm0YoshnMlnWgsO6nJRRy6PA9EWZkOrvRQjboo06iKABCYxg64WfGSQT91EJuBtuzSrxTB7dp+ad+3gEy/O1CgEkVneGQFZk0MKq+o5Ao/KCWmsWfsSwgNBrjEGazNOYihG4fa6XuinoTfLdGWyA3rwFGen5UGhOXqzVeke92jzQukCSViAtZApOl3pNquvwVJJteCJDN6m4l+7YMvanyQLy7oNSaqKZUN+qDd1xW31drfHf66qcL/LfSofv4jOHSsaHBEiVxTbpYl3ZNyV1cbsrxHOXYymqvufzUxX1iHsePIuVpkY3oT1/DjP8xRWE68aAKoxlwOH7ofeJ26g4q890Cf+L3Q58QRqr3XSLb5E2Y47ZhD5jjBt1kaN1WQfa4gdJMdZkFqbtP2kchncwK64M/JTkHvb/3/aOesPRYn2nfyNHlrKhsQ7bEYpKk83kNPHd52lD/dzERY0Z4SJlam10Nj6QrHRCh5YXel9maW5zuDkSIq8/SI8QGx6i6XAxwAAAAAAAAAAAAAAAAAAAAwPFBsfKA=="
  },
  "result": {
    "content": [
      {
        "type": "text",
        "text": "paid"
      }
    ],
    "isError": false
  },
  "result_hash": "sha256:074e0d712bbc1ee9bf10563f081f744cd480c5dcae9763feaf8b47dd887799c6",
  "receipt": {
    "prefix": "tkr1",
    "body": "eyJhbGciOiJlZDI1NTE5K21sLWRzYS02NSIsImlhdCI6MTgwMDAwMDAwMiwianRpIjoiMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJrZXkiOiI3VWtveGlqUndzYnE2UU00a0ZtVllTbFpKenBjWS9rMk5zRkdGS3lITjlFU2ZyR3RTakR1OU1lQzFYbHIrOCtEQXJERGRSdXVCZW13Wm5kWVUyVm1Qb05tVTYzSEplZkdtbVlLV01pVXRqOTNjTTl3QjBvOHRIMzhMdGFjM1d0QzBWSUR4Y0gvUlFJM2dCMWhHOWIydy9IVzNDS05zUGN4VEZTaWZRZzF3Wlpsb3JYVFk2MFdPOVlqc1BIZ1RFa3YwWGh3Tk9QSC9yT0E3bVhZWFFPTm5QZHA1MG1pdWlkV2VUWXQ1SHowWVZjNnA3VmxMdkVTbWtwUUY5TDh5ZWlCZWJFdCtJWHJvUVZuRm5acTc3bnA5QTJMYkorR3FsZHlibUlFYmRzNVJSMUZOcHQyODNmVlZVR0tRLzJCRVpwbzg5OHVmSHMwcm5JRk54WjBKOWVxMmYvQTRFQzZqMWNobWZ1eCtNSnFzMGFqQXNEdktGU3JEVTdQT3hvbHg1Q0xNNkp0blhUajR4dWx1RXRtS3ZsZE9UQXdwQWtrVTJwSG4yQ2VHaXZ1cDVpdUYrd0hhaTh5WUpTT3RPaTBGUFhnNGVsOVQxVUxaNlZMaE1ZNmJWMFpaai9sSVgrcncraHAxRmdtUVZ5clFEUkhPekxvNWVIMWhRQ3NVU3VaTmFnRXBiUm5Sd0Y5b3oyemhOTzU4Y1BUc0Nnc3B3bEJWS0tnbGdKZDFURGd6QUgxN1MwWlJsbnE0MFhiVk85R21RVFN4YWRQMWprdHdPWFZVUm43ZWk5SjM3UVhLa1VaTFJyU0VMMldCcmpsWHl1T2VaM3dpYndDby9LRzM1clg1V3dJaWhjSnd0OE5qamI4M1N6MVhXdnEyWUVDZHZ2Tk9DekpRdHFiNHBac1E0bXFkRjJwdkdHMVdNNjR4RStBanV2TDFvMWVsRGJwMm5qU0xLSTQwZ2NSTG1CVzhyNlF5elFRSTB6M2NpaUZxVVkxak90eGFWY3E0MmZvamNxUUZ5RmpWaXg1d05SMmNUREpOc2Q1SzdvZi9kNkVyL3R2MzkzWnBUbkNGeWY5czUvbE5RYlljVUhteEx2SFpFcnh0NERDTmtmV3ZXaXRXaDVtSG15MHQxT2ZxeFcxc1V6NVYrbVFtNWhMaFljakVjb0plYWtZOFo1MStxeExGZzVtc0c1U3VyOTJ6eEIvSFMwcWYvdHJWWUxSdGxRQU5NQ2YrK1FZRnNydXRRZ2hBd3RlQlU3YVhTSDJ0c3duNWVTMUxBR0NuL2sycWZ0R0tKVUZYMWUvZ3IvYWkwbjJ2S2JJMEN3YzFpbEJBSDhoQlZmNHo2ZWRUSDMrSDhrZVExbGNBeGlhNTZXdHo3K0oxMjUvOUVNS2dlSFE0Z1U2SGlSajl5MFVsS1llcTl1RDJMeEZDMG14OE1XVWcvTitudDJBTTVNYUZqeVdWeGhlcW5oZWNmRjdTQlYzOHpENmNpVkp3MmtId1gySFdkemM5b3FnVyt5TXpEcG5FWDVCZmRBdFZ1aUMvQXZnQ2owRGVtRlRDUUZiL0dNc0djZ1hDU1g4VEVkL0NPWTdMRW1aWThUUExiK3NVUWdOV1dnMmIzdFVFUWJCKzY3WDRPSWdVSHVxNG5udE8zbkpvaTVGMWlORjhqanFSQU8vRVFSNmw2Yzg2RnRxQ2toTlJKQnV4MDVjYXE4UHhNZHZROHZ2Wm9TZGxTWWd4ek9pMm5waTAyeThRWlFBV1FLMVdZYkowMkt5TTBPNTNuSU9lL0RoeFduY1l4bkZRdUtjWGt3T1RDcWhSdDlIcm40WVZBRS9QZ2I2bWZINXMxV1JVYUx4MGt0UXhqNkpLMTRwZzlaMkFUNktoZERqUnFiRUwrV1p0N1dGRm45MllSTGZaL3dnekwzaTk4bmJ6cXFybldTMWZ6V1VPaE9kRWtSbitoVm1pYUJDYXN3NXR3MUpreUY0cFB5dUN3bmRDZzZzN0kxaThRa3M3Zml4bW94NGRPV2VoSmdadVRZRjgxQ1Z2SURQeXZ2MjI4bkVDTUpNRTM4aTZuSFJKYjBHRXF6ZGxIZkFGNUE1bzV1blphVUJlRHJkSlFKWStBSzhwbHNhNWZwVm84QTZETWh2U1B6Mm8wenM0MDZjYkcrY0J5M2Z3Y0ZucUtLMjNBWTFQY2hyejVUR1FMd0Z2R2JhLytNbmVMTmVwSERZUFJwZmdaZDVtdzNFTktmQ29XOWR0OEpwaTZrUmp0cTRIaEdnTmcrVjljNmVaendaNysvTndySUxTNHFWeG1neG5peE9Va3N5UjY4bnpjQytlcnl5czNydSt1enBqb1hJajdkODRwdEVpOEZnUlNPTWdrREJkdWtOZXR2WlpVUnhvenlHMGlzb1JpNzB4WUJyeXEwZmtkNExIbjhEKzhIMzlSTGdBU3RRUWY0RW1FSzJpay9TNXVBRncwWkJXQjlYRlYxYXpTdGUveXBuMUVPZmVjWXBZdzcrNGZaQVJLQzJZbk5FS2pYRnFSQ3N2WVlQRXU5SmJaN0JwK1pEQmJOUjVFaUNacGtmNzV6MG5qN3I4RXdrclByUGppc21rM0F0VVM2Rm4wY3VxaTU1K2VTUlNqeWpSM0lwdDZqVjNZclFuS2JzVmV0SytrSzhvM2d3czFiV090bWx0aFkrby9XckQ1ZzdyNjYwcEtualo1enNiVWlyT0kxZGZSS3g0YXN3N0xOTTN3bDdFU1VwTCt4RHV5RWJIQW5zL2Uzd2tLMDZNOXM0eDR1QzI0WFRueXdoNUUrVTZmTHhWRDdjTXI1NzhwVDZ3LzVnWEdVRVhiN1kxRDNTSGtHVDZuWldTbkNpbjlYUmhRSmVNZlR5d0RMTjBVcHdmaVhrRW5iS1BUNnBKSVJkaEQ2MmdsS2JGZUx1ejBnM1RJRFk1cWtyQytrL1BibnBVWEQ5Vkh4UW92WGNSUHRVZ1llTFFmakhrMWxmSWcyR0Iva2EzQmZrVUl1b2lKOTEvalRoTEdVVlJpMHJlZG85VmZUc3BlOThDSFVpTUwzK3h0dkRCbXd6Sk02c2ZUcU1VT2lRSUh2MCtFak0zRGVlczBtTlhtT2Q0dkFzaWY1Z3ZKMjREUndOaVZENStPVVhoRC94MUNDVUNLeWw1V0F3a3Z6TU1mMXR2THA3dXNoSFc2QU5XMjIvM0cvZEtlYWd1MG5NRFZzREpyeDdlMnNMRHlBZy9TNmYvczdkTVowYU1QdzEycGk5Q0VmTUt6R1ladFBQUlB0NGdTdXl0Nkt4WkJPM0pKelU5TEM3OW9yWGJEVWFqbk5SdGpVSnRXUjVYM2czZHVOZWFRRlFxZzRZTXhGQ3d4M1hwTG4rWjZzQks5cnhyRHZsd2kvVWlLalRoWnk1VzRDcEVVaUVvTTBjQThXeWZrd204c00vTmhtVmNVVy9mdVZQQXNiVWxhbnJVSk55U3hNbFhzaytVV0pzUENtZTV3d2JPL2UremM5TVZZc2NveVpjMGVKeC9EK2hYMUtzNHc9PSIsIm91dGNvbWUiOiJyYW4iLCJyZXN1bHRfaGFzaCI6InNoYTI1NjowNzRlMGQ3MTJiYmMxZWU5YmYxMDU2M2YwODFmNzQ0Y2Q0ODBjNWRjYWU5NzYzZmVhZjhiNDdkZDg4Nzc5OWM2Iiwic3RhbXBfaGFzaCI6InNoYTI1Njo4NThkMmVhZTk4NWRiMmY1NjU3ZGQxODllZmRiZWYwY2VmNzUwNTQ4NzEwMjc2OTkyZjc4MGEzY2UwZDgwYTI0IiwidG9vbCI6InBheV92ZW5kb3IiLCJ2IjoxfQ",
    "signature": "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"
  },
  "checked_at": 1800000002
}
```
<!-- /vectors -->

## What it does not cover

- An attacker who controls the `TwoKey` process, or who holds both a valid,
  unspent token and the stamp key.
- A tool that does not use the check, or a server that catches the refusal
  and runs the tool anyway.
- A server without the seen record has no replay protection.
- The receipt proves which result the server signed. It does not prove the
  server did what the result says.

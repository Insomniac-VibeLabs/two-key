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

   It prints the key's fingerprint (`sha256:` and 64 hex digits). The key
   file is readable by its owner only, and it is never overwritten.

2. Sign the fingerprint into the tool's spec, as Two-Key's own account:

   ```sh
   two-key config set --config proxy.yaml --key principal.pem --rules hard_rules.yaml \
       tool_specs.pay_vendor.tool_check '{"key": "sha256:..."}'
   ```

   `two-key setup` asks for it too (a tool's "tool check" question, or the
   column of that name in the setup window). Turning the check on is
   stronger, so it needs no typed yes. `exempt`, removing it, or a different
   key is weaker.

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
     "capability_key_fingerprint": "sha256:...",
     "stamp_public_key": "two-key-stamp.pub.pem",
     "stamp_key_fingerprint": "sha256:...",
     "tool_private_key": "tool.pem",
     "seen_record": "seen.sqlite"
   }
   ```

   `tool` is the tool's signed id. Loading refuses a public key whose
   fingerprint is not the one written here.

6. Wrap the tool (next section), restart the server, and run
   `two-key config check --config proxy.yaml`. It lists each tool's check:
   on, exempt, or off.

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
{"_meta": {"io.github.insomniac-vibelabs/two-key": {"token": "tk1....", "stamp": "tks1...."}}}
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
  the canonical JSON in base64url without padding. The signature is Ed25519,
  in standard base64, over the purpose label, one zero byte, and the body
  text. The label means a signature made for one purpose fails for any
  other.
- The **token** is Two-Key's existing `tk1.<body>.<signature>`. Its signature
  is Ed25519 over the body text with no label, made by the capability key.

### The token field

A checked tool's token has one more field, `tool_args_hash`, signed with the
rest. Other tokens are byte for byte as in 0.8.0. The token's other fields
that the check reads are `jti`, `tool`, `iat` and `exp`.

### The redeem stamp

Prefix `tks1`, label `two-key-redeem-stamp/1`, signed by the gateway's stamp
key. That key signs stamps only, and is a separate key from the capability
key.

| Field | Meaning |
| --- | --- |
| `v`, `alg` | `1` and `ed25519` |
| `jti`, `tool` | The token's |
| `tool_args_hash` | The token's, recomputed by the gateway from the arguments it sends |
| `token_hash` | The hash of the token's text |
| `seq` | The ledger position of the `redemption_started` entry |
| `iat` | When the gateway signed it, in Unix seconds |

### The receipt

Prefix `tkr1`, label `two-key-tool-receipt/1`, signed by the tool's key.

| Field | Meaning |
| --- | --- |
| `v`, `alg` | `1` and `ed25519` |
| `key` | The tool's public key, raw, in standard base64. Two-Key accepts it only if its fingerprint is the one in the signed spec |
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

Keys made from fixed 32-byte seeds (the capability key from 32 bytes of
`0x01`, the stamp key from `0x02`, the tool key from `0x03`), with fixed
times. `tests/test_toolcheck_vectors.py` makes these again and fails if this
block differs. The token, the stamp and the receipt are each shown as their
three parts; on the wire they are one string, the parts joined with dots
(`prefix.body.signature`).

<!-- vectors -->
```json
{
  "capability_public_key": "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=",
  "capability_key_fingerprint": "sha256:34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e",
  "stamp_public_key": "gTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=",
  "stamp_key_fingerprint": "sha256:6a3803d5f059902a1c6dafbc9ba4729212f7caac08634cc3ae76b27529f03827",
  "tool_public_key": "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=",
  "tool_key_fingerprint": "sha256:b62e867fa2f33afe62d5d6b1642e1621d543307846b2a57b897e710919b76709",
  "arguments": {
    "amount": 12.5,
    "vendor": "ada"
  },
  "tool_args_hash": "sha256:e8046316d49bd6332578496f57866f74525954ac5c330a19cc29349819e0d11a",
  "token": {
    "prefix": "tk1",
    "body": "eyJhcmdzX2hhc2giOiJzaGEyNTY6MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsImJ5dGVjb2RlX2hhc2giOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwiZXhwIjoxODAwMDAwMTIwLCJpYXQiOjE4MDAwMDAwMDAsImp0aSI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwibGVkZ2VyX3Jvb3QiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwibGVkZ2VyX3NpemUiOjcsIm5sX2hhc2giOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwIiwic3BlY19oYXNoIjoiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsInRvb2wiOiJwYXlfdmVuZG9yIiwidG9vbF9hcmdzX2hhc2giOiJzaGEyNTY6ZTgwNDYzMTZkNDliZDYzMzI1Nzg0OTZmNTc4NjZmNzQ1MjU5NTRhYzVjMzMwYTE5Y2MyOTM0OTgxOWUwZDExYSIsInYiOjF9",
    "signature": "ULUdKjoUTNSUkNl1zbfj9s5N/w5mQTUo4u9G2Yvo7HN0MeyHdho6dEHdEHLao+fK+QIQzGSGVn8I32UIT4zBCw=="
  },
  "stamp": {
    "prefix": "tks1",
    "body": "eyJhbGciOiJlZDI1NTE5IiwiaWF0IjoxODAwMDAwMDAxLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsInNlcSI6OCwidG9rZW5faGFzaCI6InNoYTI1Njo5OGQxZTg2ZDIxMTAzZDBiNTVjZDA1OWFhZjhhYmRlMDkzZjc4MGZkZWIwZjhkOGNkN2U1MTQwM2IyZWE4YmRhIiwidG9vbCI6InBheV92ZW5kb3IiLCJ0b29sX2FyZ3NfaGFzaCI6InNoYTI1NjplODA0NjMxNmQ0OWJkNjMzMjU3ODQ5NmY1Nzg2NmY3NDUyNTk1NGFjNWMzMzBhMTljYzI5MzQ5ODE5ZTBkMTFhIiwidiI6MX0",
    "signature": "Aze4Zki8rOQMCAW12GgzLk8T7r0olwLMjZwqOoxtGpudnvCMO5SkYPjDfcytGQA1YugU4zfn+5jdHBWyuE0uAw=="
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
    "body": "eyJhbGciOiJlZDI1NTE5IiwiaWF0IjoxODAwMDAwMDAyLCJqdGkiOiIwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZiIsImtleSI6IjdVa294aWpSd3NicTZRTTRrRm1WWVNsWkp6cGNZL2syTnNGR0ZLeUhOOUU9Iiwib3V0Y29tZSI6InJhbiIsInJlc3VsdF9oYXNoIjoic2hhMjU2OjA3NGUwZDcxMmJiYzFlZTliZjEwNTYzZjA4MWY3NDRjZDQ4MGM1ZGNhZTk3NjNmZWFmOGI0N2RkODg3Nzk5YzYiLCJzdGFtcF9oYXNoIjoic2hhMjU2OjU5Yzg5NGQ4OWRjNGE3Y2EyNTc2OTAyZjU5NzQwNDU2YjBlYWE1OGU5MjA5YjZlOTZlNjMzMGI0Nzk0ODgxMTgiLCJ0b29sIjoicGF5X3ZlbmRvciIsInYiOjF9",
    "signature": "AjBuRrBdhptlW2H/5tQlt/EMcK2q+I5Ws1Gvcx9+IO0rPTc/i3xgygqgQ1muvcI57xUGbibMmTV8Cqlf1JYKAQ=="
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

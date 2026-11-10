<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# @insomniac-vibelabs/two-key-toolcheck

The tool check of [Two-Key](https://github.com/Insomniac-VibeLabs/two-key) for MCP servers written in TypeScript.

Two-Key stands between an AI agent and its tools: every call needs a signed token from Two-Key's gateway before it
runs. With the tool check, the tool proves this for itself. Before its own code runs, the tool checks Two-Key's token
and redeem stamp, refuses a call it has seen before, and then signs a receipt that Two-Key verifies and records. A
call sent to the server directly, around Two-Key, is refused.

This package is the TypeScript side of
[docs/TOOL_CHECK.md](https://github.com/Insomniac-VibeLabs/two-key/blob/main/docs/TOOL_CHECK.md). It makes the same
checks, in the same order, with the same refusals and the same receipt as the Python helper
(`two_key.toolcheck`), and it reads the same `check.json`. One file works for either helper.

## Install

```sh
npm install @insomniac-vibelabs/two-key-toolcheck
```

Node 22.13 or later, or Node 24. The only dependency is
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (ML-DSA-65, FIPS 204). Ed25519 and SQLite
are Node's own (`node:crypto`, `node:sqlite`). Node may print an `ExperimentalWarning` for `node:sqlite`; the helper
works the same.

## Use it in an MCP server

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { ToolChecker } from "@insomniac-vibelabs/two-key-toolcheck";

const checker = await ToolChecker.load("/srv/billing/two-key/check.json");

server.registerTool("pay_vendor", { inputSchema }, (args, extra) =>
  checker.mcpCall(args, extra._meta, (checked) => pay(checked)));
```

`mcpCall(args, meta, run)` runs the eight checks and calls `run` only when all pass. It returns the result with the
receipt in its `_meta`. A refused call returns an error result naming the reason, with a signed refusal receipt, and
`run` is never called. When `run` throws, the result is `tool failed: <error class>` with an ordinary receipt (never
the error's message), so Two-Key sees a signed failure rather than an unanswered call.

Use the helper only this way. A server that catches the refusal and runs the tool anyway turns the check off.

For another framework: `checker.check(args, meta)` throws `ToolCheckError` (with `reason`) or returns the checked
call; then send `wireResult(result)` and sign it with `checker.receipt(call, wireResult(result))`. On a refusal, send
`checker.refusal(reason, meta)`. `wireResult` writes out `isError` and `resultType`, which Two-Key's MCP SDK fills in
when they are missing, so both sides hash the same result.

## check.json

Two-Key's operator makes the tool key and the file (`two-key tool-key new`, docs/TOOL_CHECK.md "Turn it on"):

```json
{
  "tool": "pay_vendor",
  "capability_public_key": "cap.pub.pem",
  "capability_key_fingerprint": "hybrid-sha256:...",
  "stamp_public_key": "stamp.pub.pem",
  "stamp_key_fingerprint": "hybrid-sha256:...",
  "tool_private_key": "tool.pem",
  "seen_record": "seen.sqlite"
}
```

Relative paths are read from the folder of `check.json`. Each public key must have its pinned fingerprint. The tool
key must be unencrypted, and readable and writable by the tool's account only (mode 0600); a key others can read, a
symbolic link, or an encrypted key is refused.

## The checks, in order

| # | Check | Refused as |
| --- | --- | --- |
| 1 | The request carries a token and a stamp | `check_missing` |
| 2 | The stamp's signature, with the pinned stamp key and the stamp label | `stamp_invalid` |
| 3 | The token's signature, with the pinned capability key | `token_invalid` |
| 4 | The stamp belongs to this token: its hash, `jti` and `tool` | `stamp_mismatch` |
| 5 | The token is for this tool | `tool_mismatch` |
| 6 | The arguments hash to the token's and the stamp's `tool_args_hash` | `args_mismatch` |
| 7 | Not expired, not from the future (5 seconds allowed), at most 300 seconds long | `expired` |
| 8 | The `jti` is new to the seen record | `replayed` |

Anything else that goes wrong inside the helper is `check_failed`. Every signature is hybrid Ed25519 + ML-DSA-65;
a classical signature or key is refused.

## Numbers in the arguments

The arguments are hashed as Two-Key's Python side hashes them, byte for byte. One case cannot match: JavaScript
reads Python's `12.0` as `12`, and an integer above 2^53 loses digits. Such a call is refused `args_mismatch`. It
fails closed: the tool never runs on a hash the helper could not reproduce. Declare such inputs as integers within
2^53, as non-whole decimals, or as strings.

## The seen record

The jtis the tool has accepted are kept in a SQLite file (`seen (jti TEXT PRIMARY KEY, until REAL NOT NULL)`), the
same table the Python helper keeps. Copies of one server, in either language, that share the file refuse each
other's replays. Entries are removed once their token can no longer be valid.

## Windows

On Linux and macOS the helper refuses a key file or seen record that the group or others can read. On Windows it
does not read access lists. Keep `check.json`, the tool key and the seen record in a folder only the tool's account
can open.

## What it does not cover

An attacker who controls the Two-Key process, or who holds both an unspent token and the stamp key; a server that
catches the refusal and runs the tool anyway; a tool process that another account can change. The receipt proves
which result the server signed, not that the server did what the result says.

## Versions

| Helper | Two-Key |
| --- | --- |
| 0.9.1 | 0.9.0 and later (the tool check's wire format is unchanged since 0.9.0) |

## License

Apache-2.0. Copyright 2026 Insomniac-VibeLabs.

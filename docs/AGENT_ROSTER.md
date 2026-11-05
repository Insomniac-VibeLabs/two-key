<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Telling agents apart: the signed agent roster

This guide is for operators who connect more than one agent to Two-Key, or who want the ledger to say which
account a call really came from. It describes the signed agent roster added in 0.9.0. Two-Key is beta and not
independently audited. If this guide disagrees with the code, the code wins.

## Contents

<!-- toc -->
- [In plain words](#in-plain-words)
- [Before 0.9.0](#before-090)
- [Write the roster](#write-the-roster)
- [Which tools each agent may use](#which-tools-each-agent-may-use)
- [What the proxy does at start](#what-the-proxy-does-at-start)
- [Shared groups](#shared-groups)
- [What the ledger and the SIEM record](#what-the-ledger-and-the-siem-record)
- [Judges from another maker](#judges-from-another-maker)
- [High assurance](#high-assurance)
- [Check it](#check-it)
- [What it does not cover](#what-it-does-not-cover)
<!-- /toc -->

## In plain words

An agent is not its model. Two agents can run on the same model with different API keys, and one agent can
switch models. What does tell two agents apart on one machine is the operating-system account each one runs
as, because one account cannot start a process as another without a password or a sudo rule.

So the roster ties each agent to an account. It is part of the constitution and is signed with the principal
key, so an agent cannot add itself to it or change its own account. When the MCP proxy starts, it reads the
account that started it, finds the roster entry for that account, and serves that agent and no other.

## Before 0.9.0

`agent_id` in `proxy.yaml` was a label the operator wrote. Two-Key checked that the agent's account was not
root or its own, but not that the account belonged to the agent the label named. Two proxies with different
labels could run as the same account, and the ledger could not tell their calls apart. Without a roster that
is still how it works, so nothing changes for a deployment that does not add one.

## Write the roster

The roster is `agents:` in the rules file (`hard_rules.yaml`), beside `hard_rules` and `tool_specs`:

```yaml
serial: 4
agents:
  - id: coder
    account: tk-coder
    hosting: build machine, local
  - id: billing
    account: tk-billing
  - id: public
    account: tk-gateway
    shared: true
    hosting: public callers through one gateway
hard_rules:
  - id: tools
    allow_only_tools: [search, pay_vendor]
tool_specs:
  search: {irreversible: false, data_class_floor: public}
  pay_vendor:
    irreversible: true
    data_class_floor: financial
    agents: [billing]
```

Each entry has:

| Key | Meaning |
| --- | --- |
| `id` | The agent's name in the ledger, to the judges, and in `ledger-view`. Letters, digits, `.`, `_` and `-`, at most 128. `unnamed` and `any` are reserved. |
| `account` | The account the agent runs as: a local account, or the SSH login account for an agent on another machine. No two entries may share one. |
| `shared` | Optional, `true` for a group of callers Two-Key cannot tell apart ([Shared groups](#shared-groups)). |
| `hosting` | Optional, where the agent runs, as a note in the ledger. |

Sign it as usual with `two-key sign-constitution`, the [constitution editor](CONSTITUTION_EDITOR.md) (its
Agents tab), or `two-key setup`, which asks for the account each agent runs as. A constitution with a roster
signs as v3, and an install older than 0.9.0 refuses it. The signed roster is sorted by id, so it hashes the
same however it was written.

Give each agent its own account first ([CONNECTING](CONNECTING.md)): the roster records which account is
which, it does not make one.

## Which tools each agent may use

Each tool spec may name the agents that may call it, with `agents:`:

- `agents: any`, or no `agents` key: every agent may call it. This is the default.
- `agents: [billing, coder]`: only those roster ids.

A tool that names agents needs a roster. The proxy does not list a tool to an agent that may not use it, and a
call to it anyway is denied `tool_not_for_agent` before any judge is asked. The list is part of the tool's spec,
so it is in the spec hash and the policy digest.

## What the proxy does at start

With a roster, the MCP proxy:

1. Reads the account of the process that started it, as it has since 0.7.0 (`on_agent_access`), and still
   refuses root, Two-Key's own account, and an account that can change Two-Key's files.
2. Finds the roster entry whose account has the same number (uid). Each roster name is looked up when the proxy
   starts, and the numbers are compared. After you rename an account, put the new name in the roster and sign it
   again; until then that agent's proxy refuses to start (`agent_account_unlisted`).
3. Refuses to start when no entry has that account (`agent_account_unlisted`), or when `proxy.yaml` sets an
   `agent_id` that names another entry (`agent_account_mismatch`). Each refusal is recorded in the ledger as
   `agent_refused` with its reason, and goes to the SIEM.
4. Serves that entry: its `id` is the agent's id, and its `hosting`, when set, replaces `proxy.yaml`'s.

With a roster, leave `agent_id` out of `proxy.yaml`; one `proxy.yaml` then serves every agent, each from its
own account. `one_proxy_per_agent` still holds: a second proxy for the same agent on one ledger refuses to
start (`agent_already_connected`).

## Shared groups

Some callers cannot be told apart, for example agents from the internet that reach Two-Key through one
gateway account. List them once, as one entry with `shared: true`. Two-Key judges them as one agent: they share
one id, one judge history, and one set of tools. Give a shared group only the tools you would give any of its
callers, and judge it as untrusted. `one_proxy_per_agent` does not apply to a shared group, so each of its
callers can have a proxy at the same time.

## What the ledger and the SIEM record

- `mcp_proxy_started` records `account` (`uid` and `name`) and `agent_source`: `roster` when the roster chose
  the agent, `proxy_yaml` when `proxy.yaml` did.
- Each decision's `agent` gains `account`, the account that started the proxy. `ledger-view` shows it as
  `agent.account.name`.
- `agent_refused` records a proxy that refused to start, with its `reason`.

The SIEM gets `agent_source` and the refusal reasons. It does not get account names or numbers, which stay in
the ledger.

## Judges from another maker

A judge that runs on the same model as the monitored agent can be fooled the same way. `require_other_maker:
true` under `quorum:` in `judges.yaml` makes an allow need a yes from at least one judge whose maker is not a
monitored agent's:

- Makers are compared by each judge's `maker` label (its provider by default) and the maker its model id
  names, against each declared agent's provider and model maker.
- When no judge is from another maker, Two-Key does not start (`judge_diversity_unmet`).
- When none of the judges from another maker votes yes, the call is denied (`other_maker_yes_required`).

It is off by default, and `high_assurance` does not turn it on. `monitored_agent` in `judges.yaml` may be a
list, one declaration per agent, each with its own `id`, so that no judge may be any of them.

## High assurance

Under `high_assurance`:

- The roster is required. Without one, the proxy refuses to start (`agent_roster_required`), and `two-key
  setup` refuses a proxy setup with no account (`agent_account_required`).
- Every tool names its agents; `any` is refused (`agent_list_required`). `two-key setup` fills each tool's list
  with every agent on the roster, for you to narrow.

## Check it

`two-key config check --config proxy.yaml` lists each roster entry with the tools it may use, and:

- warns when an entry's account does not exist on this machine (an SSH login account may live elsewhere), or
  has no `monitored_agent` declaration with its id;
- fails when an entry's account is root or Two-Key's own, when `proxy.yaml`'s `agent_id` is not on the roster,
  and, under `high_assurance`, when there is no roster or a tool is open to `any`.

## What it does not cover

- The roster tells accounts apart, not people or models. Two agents on one account are one agent to Two-Key;
  that is why signing refuses two entries with one account.
- An account that can start a process as another account (root, a broad sudo rule) can be any agent. Keep the
  sudo rule to the proxy wrapper ([CONNECTING](CONNECTING.md)).
- An agent on another machine is known by the SSH login it uses. Whoever holds that login's key is that
  agent.
- Judge makers come from labels and model ids the operator writes. They are not checked against the vendor.

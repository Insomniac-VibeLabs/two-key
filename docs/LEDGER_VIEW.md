<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Search the ledger for an audit (0.8.0)

The ledger records every step Two-Key takes: each proposal, both paths' results, each judge's ballot, each
decision, each token issued and redeemed, and each refusal. `two-key ledger-view` opens it in a window as a
table, one row per entry, so an auditor can find and compare those steps without reading JSON by hand.

Every field of every entry can be searched, filtered, and sorted, one at a time or together. The viewer only
reads: it never adds an entry, and it writes no file.

## Contents

<!-- toc -->
- [Open the window](#open-the-window)
- [What a row holds](#what-a-row-holds)
- [Search, filter, and sort](#search-filter-and-sort)
- [The tests a filter can use](#the-tests-a-filter-can-use)
- [Without a window: --print and --fields](#without-a-window---print-and---fields)
- [Audit recipes](#audit-recipes)
- [What it checks, and what it shows](#what-it-checks-and-what-it-shows)
- [What it does not do](#what-it-does-not-do)
<!-- /toc -->

## Open the window

```bash
two-key ledger-view --key keys/principal.pem --ledger ledger \
  --witness-public-key /etc/two-key/witness.pub.pem
```

It takes the same `--key`, `--key-passphrase-file`, `--witness-public-key`, and `--head-anchor` as
`two-key audit`, and it opens the ledger the same way: the hash chain, the signed head, both witness pins,
and the head anchor are checked first, and a ledger that does not pass is not shown. Run it as the account
that can read the principal key and the ledger key, as you would `two-key audit`.

The window is built with tkinter, which comes with Python on Windows and macOS. On Debian and Ubuntu it is a
separate package (`apt install python3-tk`); without it, the command says so and `--print` still works.

The options that narrow the table can also be given on the command line, and the window opens with them
filled in:

```bash
two-key ledger-view --key keys/principal.pem --ledger ledger \
  --where kind equals decision --where allowed equals false --sort at:desc
```

## What a row holds

Each row is one ledger entry. Its fields are:

- `seq`, `kind`, `prev` and `entry_hash`, from the entry itself.
- Every value in the entry's body, under a dotted path: `reason`, `subject.tool`, `history_basis.ledger_size`,
  `quorum_policy.judge_history.window_days`.
- A list adds `[]` to the path and keeps every element. `ballots[].judge_id` holds each judge's id and
  `ballots[].vote` each vote, in the same order; `subject.counterparties[]` holds each counterparty. The
  table joins them with commas, and a filter matches the row when any one element passes.
- A body key with the same name as one of the four entry fields is shown as `body.<key>`.

Different kinds of entry have different fields: a `decision` has `allowed`, `reason`, `agent.id`, `at`,
`subject.*`, `history_digest` and `history_basis.*`; a `path_b` has `passed`, `yes`, `no`, `abstain` and
`ballots[].*`; a `gateway_denied` has `jti`, `reason` and `tool_args_digest`. A row with no value for a field
shows an empty cell.

The table starts with the fields most audits need (`seq`, `kind`, `at`, `agent.id`, `tool`, `subject.tool`,
`allowed`, `passed`, `reason`, `ballots[].judge_id`, `ballots[].vote`, `jti`, where the ledger has them).
**Columns** picks others: the columns already shown keep their place, and new ones follow. **Defaults** puts
back the starting columns. Every field can be searched and filtered whether or not it is a column.

Select a row to see all of its fields, and the whole entry as JSON, below the table.

## Search, filter, and sort

- **Search all fields** keeps the rows that contain the text in any field. It ignores case.
- **Add filter** adds a line: a field (or `*` for any field), a test, and a value. A line with no value yet
  does nothing, so the table does not empty while you type.
- **Match all filters** keeps a row only when every filter line passes; **Match any filter** keeps a row when
  at least one does. The search applies either way.
- **Remove** takes one filter line away; **Clear** removes every filter line and empties the search.
- **Right-click a cell** to add "show only this value" or "hide this value" as a filter, or to copy the
  value. A cell with several values (a list) offers each one.
- **Click a column heading** to sort by it, and again to reverse it. **Shift-click** another heading to add
  it as the next sort key; the headings number the keys (▲1, ▼2). Numbers sort as numbers, text ignores
  case, and a row with no value for a sort field goes last whichever way it is sorted.
- **Reload** opens and checks the ledger again, so entries written since the window opened appear. The
  search, filters, sort, and columns stay. If the ledger does not open again (it fails a check, or a file
  cannot be read), the line above the table turns red and says why, and the table keeps the entries from
  when it last opened.
- The line at the bottom says how many entries match, of how many, and the sort. The window lists at most
  `--max-rows` matching entries (10000 unless you say otherwise); the count is always of all of them.

## The tests a filter can use

| Test | On the command line | Keeps a row when |
| --- | --- | --- |
| contains | `contains`, `~` | a value contains the text |
| not-contains | `not-contains`, `!~` | no value contains the text (a row without the field passes) |
| equals | `equals`, `=`, `==` | a value is the text |
| not-equals | `not-equals`, `!=` | no value is the text (a row without the field passes) |
| starts-with | `starts-with` | a value starts with the text |
| ends-with | `ends-with` | a value ends with the text |
| regex | `regex` | a Python regular expression finds a match in a value (at most 500 characters) |
| gt, ge, lt, le | `gt` `>`, `ge` `>=`, `lt` `<`, `le` `<=` | a value is greater than, at least, less than, or at most the text |
| empty | `empty` | the field is missing, empty, or null |
| not-empty | `not-empty` | the field has a value that is not empty or null |

Every text test ignores case. `null`, `true` and `false` are spelled as in JSON, so `allowed equals false`
finds denied decisions. `gt`, `ge`, `lt` and `le` compare as numbers when both sides are numbers, and as text
otherwise, which puts ISO times such as `at` in time order (`at ge 2026-10-27T00:00:00Z`). A null value is
never greater or smaller than anything.

## Without a window: --print and --fields

`--print` applies the same search, filters, and sort and writes each matching entry to standard output as one
line of JSON, in the order chosen. It needs no display and no tkinter, and it writes no file of its own.

```bash
two-key ledger-view --key keys/principal.pem --ledger ledger --print \
  --where kind equals path_b --where 'ballots[].vote' equals no --sort seq:desc
```

`--fields` lists every field name the ledger's entries have, which is what `--where` and `--sort` take.

| Option | What it does |
| --- | --- |
| `--search TEXT` | keep entries with TEXT in any field |
| `--where FIELD OP [VALUE]` | keep entries where FIELD passes the test; repeat it for more filters; FIELD `*` is any field; the value's words are joined with spaces |
| `--any` | keep entries that pass any `--where`, instead of all of them |
| `--sort FIELD[:desc]` | sort by FIELD (`:asc` is the default); repeat it for more keys, the first deciding first; without it, ledger order (`seq`) |
| `--print` | write the matching entries as JSON Lines instead of opening a window |
| `--fields` | list the field names and stop |
| `--max-rows N` | list at most N matching entries in the window |

Quote a field name that has `[]` in it, and the any-field name `*`, so the shell does not expand them.

## Audit recipes

| Question | Filters |
| --- | --- |
| Which calls were denied, and why? | `kind equals decision`, `allowed equals false`; sort by `reason` |
| What did one agent do? | `agent.id equals buyer` (decisions and proposals carry the agent's id) |
| Every step of one call | sort by `seq`, then find the `proposal` and read on to its `decision`; a call's entries are next to each other unless two proxies share the ledger |
| Where did judge `c` vote no? | `kind equals path_b`, `ballots[].judge_id equals c`, `ballots[].vote equals no` (the second and third match the row if any ballot passes each; read the row's ballots to pair them) |
| Calls a rule refused | `reason starts-with rule_denied:` |
| What happened to one token? | `jti equals <id>`: its `capability_issued`, `redemption_started`, `redemption`, and any `gateway_denied` |
| Decisions in a time window | `at ge 2026-10-27T00:00:00Z`, `at lt 2026-10-28T00:00:00Z` |
| Configuration changes | `kind equals config_changed` |
| Every constitution the ledger ran under | `kind equals constitution_loaded`; sort by `seq` |

## What it checks, and what it shows

- **Checked when it opens, and on Reload:** everything `two-key audit` checks when it opens the ledger, and
  `check_decision_digests`: each decision's `identities_digest` and `policy_digest` against the
  `constitution_loaded` before it. The line above the table says the result in words, in green when every
  check passes and in red with the first problem when one does not (**Show problems** lists them all). For
  the judge history digests, run `two-key audit --check-history`.
- **Shown:** every field of every entry, decrypted, including the proposal text, the normalized action
  (amount and counterparties), and custom field values. That is the point of an audit, and it is more than
  the SIEM export sends (docs/SIEM.md). A judge's rationale is never in the ledger, only its keyed digest, so
  the viewer cannot show it either.

## What it does not do

- It does not write. It adds no ledger entry, changes no file, and has no export button; the window's only
  way out for data is copying a cell, and `--print` writes to standard output only. For a file to hand on,
  use `two-key siem-export`, which leaves argument values out.
- It opens no network port and starts no server. It is a window of the process you started.
- It does not run a call, judge one, or change a setting. It is not the configuration GUI on the roadmap.
- It holds the principal private key in memory while the window is open, as `two-key audit` does for its
  run, because opening the ledger needs it. Close the window when the audit is done.
- Anyone who can see the screen sees the decrypted entries. Treat the window as you would the ledger key.

<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Quickstart

About ten minutes from `pip install` to two decisions: one call Two-Key allows and one it refuses, both signed
into the ledger, and a look at them in the ledger view. Everything runs on your machine. The judge is a local
model, so no API key is needed.

You play the agent here: you ask for each call yourself with `two-key authorize`, which runs both keys and
issues a token for an allowed call, but never runs a tool. To put Two-Key in front of a real agent's tools, read
[HOWTO "Put Two-Key in front of an MCP server"](HOWTO.md#put-two-key-in-front-of-an-mcp-server-two-key-mcp-proxy)
next.

You need Linux or macOS, Python 3.10 or later, and [Ollama](https://ollama.com) for the judge. On Windows the
`two-key` commands are the same; the shell lines around them need PowerShell's syntax instead.

You can set up, and look at the ledger, on the command line or in a window; the page shows both ways.

Every terminal command on this page runs in CI on each change
([tests/quickstart_run.py](../tests/quickstart_run.py)), except the ones marked below: CI installs from the
checkout, it has no display for the windows, and it answers for the judge with a stand-in that always votes yes,
so the result there doesn't depend on a model.

## 1. Install

<!-- quickstart: skip (CI installs the checkout) -->
```bash
python3 -m venv ~/two-key-quickstart
. ~/two-key-quickstart/bin/activate
pip install "two-key[yaml]==0.9.0"
```

## 2. Start a local judge

A judge is an AI that reads a summary of each call and votes on whether it fits your rules. Here it is
Qwen2.5-7B, run by Ollama on `127.0.0.1:11434`, the model this repository recommends for a local judge. The
download is about 5 GB.

<!-- quickstart: skip (CI answers for the judge with a stand-in) -->
```bash
ollama pull qwen2.5:7b
ollama serve      # skip this if Ollama is already running
```

Leave it running, and use a second terminal for the rest.

## 3. Set up a deployment

`two-key setup` asks its questions on the terminal or in a window, and either can start from a file of answers.
This file sets up the guard route (you call Two-Key yourself), one local judge, the agent you will be playing,
and one allowed tool, `pay_vendor`. The agent is declared by you, never by the agent; Two-Key refuses to start
if a judge could be the agent ([SETUP](SETUP.md#the-questions) has every answer key).

```bash
cat > answers.yaml <<'EOF'
route: guard
judges:
  - type: ollama
    id: local-qwen
    model: qwen2.5:7b
    base_url: http://127.0.0.1:11434
monitored_agent:
  id: my-agent
  model: gpt-5
  provider: openai
  base_url: http://127.0.0.1:8080/v1
  upstream: api.openai.com
  credential: none
tools:
  - id: pay_vendor
EOF
```

Then set up from it, in the terminal or in the setup window. Both hand the same answers to the same code and
write the same files.

**In the terminal:**

```bash
two-key setup --dir quickstart --answers answers.yaml
```

Its last lines list what to do next.

**Or in the setup window**, which opens with every page filled in from the file:

<!-- quickstart: skip (CI has no display; tests/test_setup_gui.py sets up from this same file in the window) -->
```bash
two-key setup --dir quickstart --window --answers answers.yaml
```

Look through the pages: Deployment, Judges, Quorum, Agent and history, Rules and prose. The Proxy page is turned
off, because the guard route has no proxy. The status line under the pages says `Ready to set up`. On **Review
and set up**, press **Set up**. Without `--answers`, the window opens empty and you fill in the same answers
yourself ([SETUP](SETUP.md#the-setup-window-two-key-setup---window)). The window needs tkinter; without it, or
without a display, it says so and points back to the terminal.

Either way you now have the folder `quickstart`: a new principal key, the rules signed with it, the judges file,
and a new ledger. Nothing in it is shared with anyone.

## 4. A call Two-Key allows

Ask to pay a vendor. Path A checks the call against the signed rules, and the judge votes on it. Both must
agree.

<!-- quickstart: expect=both_paths_allow -->
```bash
cd quickstart
two-key authorize --key principal.pem --ledger ledger --constitution constitution.signed.json \
  --judges judges.yaml --tool pay_vendor --args '{"vendor": "ada", "amount": 12.5}' \
  --proposal "Pay Ada for invoice 42"
```

It prints the decision: `"allowed": true`, `"reason": "both_paths_allow"`, the judge's vote, and the token's id
and digest. The token itself is never printed (`--emit-token FILE` writes it to a file only you can read), and
nothing is paid: `authorize` decides, and a tool runs only when the gateway redeems the token.

A real model reads the call and may vote no. Then the decision is `quorum_denied` instead, which is Two-Key
working as meant: both keys must turn.

## 5. A call Two-Key refuses

Now ask for a tool the signed rules don't allow. Path A refuses it, whatever the judge says, and `authorize`
exits with code 2.

<!-- quickstart: exit=2 expect=rule_denied:tools -->
```bash
two-key authorize --key principal.pem --ledger ledger --constitution constitution.signed.json \
  --judges judges.yaml --tool wire_funds --args '{"to": "unknown"}' \
  --proposal "Wire the funds"
```

The decision says `"allowed": false` and `"reason": "rule_denied:tools"`, and no token is issued.

## 6. Look at both in the ledger

Every step of both calls is in the ledger, hash-chained and signed. Open it in the ledger view, a window to
search, filter and sort its entries:

<!-- quickstart: skip (CI has no display; it runs the next command) -->
```bash
two-key ledger-view --key principal.pem --ledger ledger
```

If you set up in the window, its **Open the ledger view** button opens the same window. Type
`decision` in the search box to see the two decisions. Without a display (or without tkinter), print the same
entries instead, one JSON line each:

<!-- quickstart: expect=rule_denied:tools -->
```bash
two-key ledger-view --key principal.pem --ledger ledger --where kind = decision --print
```

The ledger view never changes the ledger. [LEDGER_VIEW](LEDGER_VIEW.md) shows what else it can do.

## Next

- Put Two-Key in front of an MCP server, so the agent's tool calls go through both keys:
  [HOWTO](HOWTO.md#put-two-key-in-front-of-an-mcp-server-two-key-mcp-proxy).
- Close every way around Two-Key before a real agent runs: [CONNECTING](CONNECTING.md).
- Add judges from other makers, or choose the `high_assurance` profile:
  [JUDGES_AND_QUORUM](JUDGES_AND_QUORUM.md).
- Write real rules, such as amount limits and allowed vendors, with the
  [constitution editor](CONSTITUTION_EDITOR.md).
- When you are done here, delete the `quickstart` folder and `answers.yaml`. They hold a private key that
  nothing else uses.

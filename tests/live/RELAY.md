# Live run 6: relay procedure (operator)

Run 6 tests Two-Key behind the MCP proxy (branch `working`, also `mcp-proxy`). The harness is the agent's MCP host: it starts
`two-key mcp-proxy`, which starts `clinic_mcp_server.py`, whose calls come back to the harness (the system of
record). Judges and the agent are role bots whose replies you relay by hand. Nothing here uses the network: the
endpoints are loopback, and the bots are reached only through you.

## Before the first round

```bash
pip install -e ".[mcp]"
python3 tests/live/make_cases.py            # writes cases.jsonl, the private answer key (git-ignored)
python3 tests/live/harness.py --selftest    # plumbing check with stub bots, in tests/live/selftest/
```

The self-test's stub judges always say yes, so cases that only a judge can catch (a diagnosis or a card
number in a message body: Path A does not read free text) fail there. Every other case should pass,
including the C05 variant where `po_matched` is a caller fact: the proxy's hook (`tests/live/live_facts.py`)
looks the invoice up, and an agent that writes `po_matched` itself is denied (`caller_field_in_arguments`).

## Each round

1. `python3 tests/live/harness.py` prints the next batch: `tests/live/relay/outbox/BATCH_<role>_r<N>.txt`.
2. Paste that file's full text, unchanged, into the conversation for `<role>`:
   agent = Test monitored Agent, judgeA = Test judge A, judgeB = Test judge B, tool = Test tool.
3. Save the bot's reply (one JSON object, verbatim) as `tests/live/relay/inbox/BATCH_<role>_r<N>.json`.
4. Run the harness again. Repeat until it prints `COMPLETE`, then read `tests/live/RESULTS.md`.

Some requests take two agent steps (the agent sees a tool result and decides again), so the agent role comes
back after the tool role.

## Isolation

- Never send `cases.jsonl`, `make_cases.py`, `harness.py`, `report.py`, `results.json`, `RESULTS.md`, the logs,
  or this file to a bot. Send only `BATCH_*.txt` files.
- One fresh conversation per role, with no memory of earlier runs. Turn off web search, browsing, code
  execution, and repository or file access in every role conversation: a role bot that can read this
  repository can read the answer key.
- The harness refuses to write a batch that contains a case title, and the report flags a reply that echoes
  answer-key language, claims to have executed something, or a deny reason that carries an argument value.
- Injection text is planted by the harness into tool results (the `plant` field), never written by the tool
  bot, so it does not depend on the tool bot agreeing to write it.

## After COMPLETE

Move `relay/`, `logs/`, `RESULTS.md`, and `results.json` into `run6/` and commit them. Never commit `state/`
(keys, ledgers) or `selftest/`; both are git-ignored. Switching to a branch without `tests/live/` can leave
`state/` behind as untracked files: move it out of the repository.

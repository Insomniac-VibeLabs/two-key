# Two-Key run 9: prep findings (for Claude's handoff)

Prep ran on working at dd07b42 (includes 511d903 "Live harness: run 9"), as uid 1000 (non-root).
- Selftest: 115/115 PASS on Python 3.14.8, and the same on 3.12.15.
- Sabotage: SABOTAGE: ok, and every row matches section 2.
  - siem_passes_arguments was caught only by the referee incident, with no case failing. Consider adding a case that fails on it.

## Finding 1: `config check` and setup report the environment as set when it isn't
- Both print "ok environment: every variable the config names is set".
- At the time, neither judge's API-key variable nor the agent credential variable was set.
- Impact: an operator trusts a green check, then the judges fail at runtime.
- Also, `config show` doesn't show judge type, base URL or the API-key variable name.
- Suggested fix:
  - Check every variable the config names (judges[].api_key_env, the agent credential, upstream.env), and report any that are missing by name, never by value.
  - Add those three fields to `config show`.

## Finding 2: a secret from `config set --prompt` is written in plain text to proxy.yaml
- proxy.yaml is mode 0600, and the value would also be left in proxy.yaml.prev after a later set.
- SETUP.md says this is intended, but the brief's section 7 expects the value to be "in no file".
- The value was absent from ps, the environment, shell history, the ledger (decrypted export checked), /tmp and .venv.
- Suggested fix, one of:
  - Store an `{"env": NAME}` reference by default, or
  - Make SETUP.md recommend that, warn that the literal is kept in proxy.yaml and .prev, and adjust the brief's wording.

## Setup usability nits (from interactive `two-key setup`)
- "Can a call not be undone? [yes]" is a double negative. Rephrase it as "Is this call irreversible? [yes]".
- Every tool's data class defaults to `classified`, even a read-only tool.
- Adding a second judge defaults to "no". Check whether that's intended under the one-judge rule.
- `ledger/` is created 0755 with 0644 files; it's only safe because the parent folder was 0700. Consider creating it 0700/0600.
- The next steps it prints were enough to reach a passing `config check`.

## Environment notes
- No second account exists on the machine, so the three second-account cases stay unit-test only.
- uid 1000 has passwordless sudo, which was never used.

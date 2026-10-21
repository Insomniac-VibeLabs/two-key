<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# What a live pass covers

Every fail-closed default in [AGENTS.md](../../AGENTS.md) ("Fail-closed defaults to preserve") has a row: the unit
tests that prove it, whether a live case exercises it, and, when none does, why. `RESULTS.md` prints this table with
the pass's verdicts, so a reader sees what a PASS does and does not cover. A live case tagged with a row's id in
`make_cases.py` (`COVERS`) is what "live" means; `tests/test_live_harness.py` fails when this file and `COVERS` disagree
or a unit test file named here does not exist.

"Live" is one of `yes` (the default is exercised end to end), `partly` (some of it), or `no`. `no` and `partly` say what
is left to the unit tests. A pass also checks things that are not defaults here: the SIEM copy's count and its argument
values, the persona ladder, and credentials in the run files. The sabotage pass (`harness.py --sabotage all`) shows
which weakenings of Two-Key the harness would notice at all; it is a different question and has its own table.

| Id | Default | Unit tests | Live | Left to the unit tests, and why |
| --- | --- | --- | --- | --- |
| F01 | A missing ballot is not a yes | tests/test_fail_closed.py | yes | |
| F02 | A call that cannot be read under its spec is denied without asking the judges | tests/test_derive_robustness.py, tests/test_field_decisions.py | yes | |
| F03 | `authorize_from_agent` does not execute a tool | tests/test_in_process_agent.py | no | The library route; the proxy always runs a call through the gateway |
| F04 | A decline is not a call | tests/test_agent_decline.py | no | Through the proxy a decline is no `tools/call` at all, so there is nothing to deny |
| F05 | `require_path_a_first` is not a skip | tests/test_two_key.py | no | A library option the proxy does not set |
| F06 | Oversized or malformed calls deny before either path | tests/test_strict_parsing.py, tests/test_args_size.py, tests/test_deep_args.py | partly | Duplicate keys and YAML merge keys are in files and arguments the harness does not send |
| F07 | Quorum defaults and the high_assurance profile | tests/test_lone_judge.py, tests/test_required_yes_default.py | partly | The judge-diversity floors (makers, local judge) need a judge set the pass does not run calls with; only the start-up checks are live |
| F08 | `tool_specs` is required; a tool that is not signed is not offered | tests/test_action_claim.py, tests/test_gateway_boundary.py | partly | A disagreeing claim: the claim is fixed in `proxy.yaml` and the agent cannot write one |
| F09 | An omitted data class is `classified`; classes combine as a set; `@domain` allow entries | tests/test_data_class_sets.py, tests/test_domain_allow.py | no | The proxy takes the claim from `proxy.yaml`, never from the agent, so the live agent cannot omit or choose a class |
| F10 | `agent_vocabulary()` lists syntax, never a value | tests/test_agent_prompt.py | no | The agent's prompt in a pass is the harness's own host prompt, not Two-Key's |
| F11 | Custom and caller-supplied fields; the agent cannot write a caller fact | tests/test_caller_facts.py, tests/test_custom_fields.py, tests/test_case_exact.py, tests/test_fields_compat.py | yes | |
| F12 | Format identifiers are `two-key-...`; legacy formats are refused | tests/test_legacy_formats.py | no | A pass signs and reads current formats only |
| F13 | No judge may be the monitored agent | tests/test_judge_agent_separation.py, tests/test_same_agent_rule.py | yes | |
| F14 | The ledger's witness key is pinned | tests/test_witness_pin.py | no | The pass never replaces the witness key; `two-key audit` after the two-proxies case and the deployment story does verify the chain |
| F15 | The gateway verifies only and never mints; it checks the token's argument hash | tests/test_gateway_boundary.py, tests/test_cli_tokens.py | no | The proxy mints and redeems in one process with the same bytes, so a live call never carries a token for other arguments (`harness.py --sabotage gateway_skips_argument_hash` shows this) |
| F16 | The guard uses a fixed claim and looks facts up twice | tests/test_guard.py | no | The library route |
| F17 | The MCP proxy: only signed tools are shown, others are `tool_not_offered`, a changed schema refuses | tests/test_mcp_proxy.py, tests/test_mcp_proxy_sdk.py | yes | |
| F18 | Every key, lock and permission goes through `_platform.py` | tests/test_platform.py, tests/test_text_io.py | no | A pass runs on one operating system; CI runs the unit tests on all three |
| F19 | Writable paths, including the upstream server's files behind a launcher (#13) | tests/test_writable_paths.py, tests/test_upstream_paths.py | partly | Python 3.15's compiled-file check (#27) needs 3.15, which a pass does not run on yet; group-write bits need a second account |
| F20 | The agent's account: same, root, unknown, or able to write refuses | tests/test_agent_access.py | partly | Root, unknown and `agent_can_write` need a second account; a pass reaches `agent_same_account` and the setting's own checks |
| F21 | Two proxies on one ledger | tests/test_ledger_shared.py | yes | |
| F22 | Content scanning: Two-Key starts every scan; unavailable is never clean; declared files | tests/test_scan.py, tests/test_scanners.py, tests/test_scan_encrypted.py | yes | |
| F23 | The gateway runs in the TwoKey process | tests/test_gateway_locks.py | no | A design decision, not behaviour; there is no remote mode to test |
| F24 | Configuration changes: `setup`, `config set`, `undo`, `key-passphrase`, the `config_changed` entry | tests/test_config_set.py, tests/test_key_passphrase.py, tests/test_config_cmd.py | yes | Needs a non-root account; a pass run as root marks these cases N/A |
| F25 | SIEM export: only the allowlist leaves, a down collector never blocks | tests/test_siem.py, tests/test_siem_export.py, tests/test_siem_sinks.py | partly | The pass checks the copy's count and that no argument value leaves; the other sinks, CEF and the webhook are unit tests |
| F27 | A ledger never goes back to an older constitution (the signed serial) | tests/test_constitution_serial.py, tests/test_config_set.py | no | The run 9x C44 case signed no serials; the harness gets serials and the case is run again in 9y |
| F26 | No call reaches a tool without both keys and a redeemed token, whatever the agent tries | tests/test_two_key.py, tests/test_fail_closed.py | yes | |

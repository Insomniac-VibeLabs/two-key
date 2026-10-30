# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The catalogue of every setting, and ``docs/SETTINGS.md`` generated from it.

One row per key that a loader accepts, in the file that holds it. Each row says what the key does, its
default, what the ``high_assurance`` profile does to it, and which tier it is in:

- ``signed``: part of the signed constitution (``constitution.md`` and ``hard_rules.yaml``). Changing it means
  re-signing with the principal key; an edited file does not load.
- ``operator``: operator configuration (``proxy.yaml``, ``judges.yaml``, ``agents.yaml``). Protected by file
  permissions and the start-up checks, not signed. It takes effect when the proxy restarts.

A key's path is dotted. ``[]`` is an item of a list, ``<id>`` a name the operator chooses (a tool, a field), and
``[syslog]`` or ``[webhook]`` a SIEM sink of that type.

``tests/test_settings_doc.py`` fails when a key the code accepts has no row here, when a row names a key the code
no longer accepts, or when ``docs/SETTINGS.md`` is not what :func:`render_markdown` writes. Regenerate it with
``python tests/test_settings_doc.py --write``. Nothing here changes how any setting is read; the loaders stay
the only authority, and this module only describes them.
"""

from __future__ import annotations

from dataclasses import dataclass

SIGNED, OPERATOR = "signed", "operator"
PROXY_YAML = "proxy.yaml"
JUDGES_YAML = "judges.yaml"
AGENTS_YAML = "agents.yaml"
RULES_YAML = "hard_rules.yaml"
PROSE_MD = "constitution.md"
FILES = (PROXY_YAML, JUDGES_YAML, AGENTS_YAML, PROSE_MD, RULES_YAML)
TIER = {PROXY_YAML: OPERATOR, JUDGES_YAML: OPERATOR, AGENTS_YAML: OPERATOR,
        PROSE_MD: SIGNED, RULES_YAML: SIGNED}
FILE_NOTES = {
    PROXY_YAML: "The MCP proxy's own settings (`two-key mcp-proxy --config proxy.yaml`). Read strictly: a repeated "
                  "key, a YAML merge key and an unknown key are refused. Relative paths are relative to this file.",
    JUDGES_YAML: "The judges, the quorum policy, and the `monitored_agent:` block. `proxy.yaml` names this file. "
                   "Only the top-level keys `judges`, `quorum` and `monitored_agent` are accepted.",
    AGENTS_YAML: "Monitored agents that Two-Key itself calls (`two_key.agents`), for the library and the command "
                   "line. The MCP proxy does not read it, and `two-key config set` does not change it. Only the "
                   "top-level key `agents` is accepted.",
    PROSE_MD: "The prose the judges read.",
    RULES_YAML: "The rules Path A runs, the per-tool specs that say where Path A reads each value, and the "
                       "custom fields. Signed together with `constitution.md`.",
}


# Keys ``two-key config set`` does not change: which files, keys and ledger Two-Key trusts. ``two-key setup``
# writes them; moving one is a change of deployment, made by hand and then checked (docs/SETUP.md).
NOT_SETTABLE = frozenset({(PROXY_YAML, "constitution"), (PROXY_YAML, "keys"), (PROXY_YAML, "keys.principal"),
                          (PROXY_YAML, "keys.passphrase_file"),
                          (PROXY_YAML, "ledger"), (PROXY_YAML, "judges"), (PROXY_YAML, "witness_public_key"),
                          (PROXY_YAML, "head_anchor"), (PROSE_MD, "(the file)")})


@dataclass(frozen=True)
class Setting:
    file: str
    key: str
    default: str            # what applies when the key is absent; "required" when the file must set it
    summary: str
    high_assurance: str = ""    # what the profile does to it, when it does anything
    names_secret: bool = False  # the value is the name or path of a secret, never the secret itself

    @property
    def tier(self) -> str:
        return TIER[self.file]

    @property
    def required(self) -> bool:
        return self.default.startswith("required")

    @property
    def settable(self) -> bool:
        """Whether ``two-key config set`` changes it."""
        return (self.file, self.key) not in NOT_SETTABLE and self.file != AGENTS_YAML


def _rows(file: str, rows: list[tuple]) -> list[Setting]:
    out = []
    for row in rows:
        key, default, summary, *rest = row
        opts = rest[0] if rest else {}
        out.append(Setting(file, key, default, summary, opts.get("ha", ""), opts.get("secret", False)))
    return out


_HA_QUORUM = {"ha": "2"}

PROXY = _rows(PROXY_YAML, [
    ("constitution", "required", "Path to the signed constitution (`constitution.signed.json`)."),
    ("keys", "required", "The key files."),
    ("keys.principal", "required", "Path to the principal private key, which signs the ledger head. Owner-only: a "
     "wider mode refuses to start. Unencrypted, or encrypted with a passphrase (`two-key config "
     "key-passphrase`).", {"secret": True}),
    ("keys.passphrase_file", "none", "Path to a file holding the principal key's passphrase, when the key is "
     "encrypted; the proxy reads it at start and never prompts. Owner-only, like the key. Set by `two-key config "
     "key-passphrase`, not by hand.", {"secret": True}),
    ("ledger", "required", "The ledger directory."),
    ("judges", "required", "Path to `judges.yaml`, which also holds the `monitored_agent:` block."),
    ("witness_public_key", "none", "Path to the witness public key, to pin it outside the ledger (as "
     "`--witness-public-key`)."),
    ("head_anchor", "none", "Path to a head anchor file outside the ledger directory (as `--head-anchor`)."),
    ("ttl_seconds", "120", "Token lifetime in seconds, 1 to 300."),
    ("agent_session_env", "none", "Name of the environment variable that holds the agent's session, read once at "
     "start. Unset or empty refuses to start. Needed when a judge is not on this machine: without it the proxy "
     "refuses to start (`cloud_judge_session_required`).", {"secret": True}),
    ("agent_id", "none", "Ledger metadata, at most 256 characters. Not trust. `two-key setup` writes the monitored "
                 "agent's `id` here."),
    ("hosting", "none", "Ledger metadata, at most 256 characters. Not trust."),
    ("allow_unresolved_identity", "false", "`true` starts despite an `unresolved_identity` warning."),
    ("on_writable_paths", "warn", "`warn` names each file or folder the proxy runs or reads that another account "
     "could change, and starts. `refuse` does not start.", {"ha": "always refuses; `warn` is refused"}),
    ("on_agent_access", "refuse", "`refuse` does not start when the account that started the proxy is Two-Key's own, "
     "is root, cannot be told, or can change a path the proxy runs or reads. `warn` names it and starts, for a test "
     "on one machine.", {"ha": "always refuses; `warn` is refused"}),
    ("one_proxy_per_agent", "true", "`true` lets one running proxy serve this `agent_id` (or, with none, the "
     "`unnamed` agent) on this ledger: a second refuses to start with `agent_already_connected`, ledgered and sent to "
     "the SIEM. `false` lets several run at once and warns at start; it counts as weaker in `config set`. Since 0.8.0."),
    ("upstream", "required", "The MCP server the proxy starts and forwards signed calls to."),
    ("upstream.command", "required", "Program and arguments, as a list. Run without a shell."),
    ("upstream.env", "none", "Variables for the child: a literal, or `{env: NAME}` read from the proxy's "
     "environment (unset refuses to start). No other variable is passed. `config show` never prints a literal."),
    ("upstream.cwd", "the proxy's own folder", "The child's working directory. Under `sudo` the proxy's is the "
     "caller's, so name a folder the agent cannot write."),
    ("upstream.schema_digest", "required", "`sha256:...` of the tools the server lists, from `mcp-draft-specs`. A "
     "server that changed its tools no longer matches."),
    ("upstream.on_schema_change", "refuse", "`refuse` or `warn` when the server's tools no longer match "
     "`schema_digest`."),
    ("upstream.call_timeout_seconds", "60", "Seconds allowed for one upstream call, at most 3600."),
    ("upstream.check_paths", "none", "Absolute paths (on Windows, with the drive) of the server's own files and "
     "folders (package folder, script, config) for the start-up checks, beside each absolute argument of `upstream.command`, which is checked without "
     "being listed. At most 64; one that does not exist refuses to start (`check_path_missing`). A folder is "
     "checked itself, not every file inside it. A launcher (`sudo`, `npx`, ...) as `command[0]` with nothing named "
     "warns `upstream_paths_unchecked`.", {"ha": "a launcher with nothing named refuses"}),
    ("tools", "none", "Per-tool settings, keyed by a signed tool id."),
    ("tools.<id>.claim", "none (read as `classified`)", "What the proxy claims about the data class: `floor` (the "
     "signed `data_class_floor`), a data class, or `none`. The agent writes none of it."),
    ("tools.<id>.proposal", "`MCP tools/call <id>`", "Fixed proposal text, at most 1000 characters. Judges see it "
     "only with `judge_inputs: record_and_proposal`."),
    ("tools.<id>.upstream_name", "the tool id", "The upstream's name for a tool whose name is not a lower-case id."),
    ("tools.<id>.facts", "none", "`{field: {hook: \"module:function\"}}`, one per `source: caller` field the tool "
     "maps. Trusted operator code, imported at start."),
    ("tools.<id>.files", "none", "Arguments that hold a file, for the content scanner. Needs `scan`."),
    ("tools.<id>.files[].path", "required", "The argument that holds the file, for example "
     "`attachments[].content`."),
    ("tools.<id>.files[].kind", "base64", "`base64`, `base64url`, or `path`."),
    ("tools.<id>.files[].max_bytes", "required", "The largest file the tool takes. Base64 at most 196608; a path "
     "at most 100 MiB. A larger file is denied before the scanner and both keys."),
    ("tools.<id>.files[].folder", "required for `path`", "The folder a `path` file must be in: an absolute path to an existing folder. Not valid for another kind."),
    ("scan", "none (no scanner)", "The content scanner: an antivirus or DLP product Two-Key calls."),
    ("scan.type", "required", "`clamd`, `icap`, `command`, or `python`."),
    ("scan.address", "required for `clamd`", "clamd's address: `host:port` or `unix:/path`."),
    ("scan.url", "required for `icap`", "The ICAP service URL (`icap://` or `icaps://`)."),
    ("scan.method", "reqmod", "`reqmod` or `respmod`, for `icap`."),
    ("scan.command", "required for `command`", "Program and arguments, as a list, for `command`."),
    ("scan.env", "none", "Variables for the `command` scanner. `config show` never prints a value."),
    ("scan.hook", "required for `python`", "`module:function` for `python`. Trusted operator code."),
    ("scan.timeout_seconds", "15", "Seconds to wait for the scanner."),
    ("scan.field", "scan", "The name of the signed field that carries the verdict."),
    ("scan.label", "the product's own", "A label recorded with the verdict."),
    ("siem", "none (no copy)", "Send a copy of each ledger entry to a SIEM. Never argument values."),
    ("siem.schema", "native", "`native`, `ecs`, or `ocsf`."),
    ("siem.format", "json", "`json` or `cef`."),
    ("siem.replay_from", "cursor", "`cursor`, `start` (the whole ledger on every start), or `now`."),
    ("siem.sinks", "required", "The collectors, at least one."),
    ("siem.batch_max", "100", "Events per batch, 1 to 1,000,000."),
    ("siem.queue_max", "10000", "Events held while a collector is slow or down, 1 to 1,000,000."),
    ("siem.flush_seconds", "2", "Longest wait before a partial batch goes out."),
    ("siem.refused_token_interval_seconds", "60", "At most one refused-token count is sent in this many seconds."),
    ("siem.sinks[syslog].type", "required", "`syslog`."),
    ("siem.sinks[syslog].host", "required", "The collector's host."),
    ("siem.sinks[syslog].transport", "tls", "`tls`, `tcp`, or `udp`. TLS always checks the certificate and the "
     "hostname.", {"ha": "`tcp` and `udp` are refused"}),
    ("siem.sinks[syslog].port", "6514 for tls, 514 for tcp and udp", "The collector's port."),
    ("siem.sinks[syslog].framing", "octet", "`octet` or `newline`."),
    ("siem.sinks[syslog].facility", "local0", "The syslog facility."),
    ("siem.sinks[syslog].app_name", "two-key", "The syslog app name, at most 48 characters."),
    ("siem.sinks[syslog].hostname", "this host's name", "The hostname in the syslog header."),
    ("siem.sinks[syslog].ca_file", "the system's", "A CA bundle that the collector's certificate must chain to."),
    ("siem.sinks[syslog].cert_file", "none", "A client certificate, for mutual TLS."),
    ("siem.sinks[syslog].key_file", "none", "The client certificate's key. Owner-only.", {"secret": True}),
    ("siem.sinks[syslog].timeout_seconds", "5", "Seconds to wait for the collector."),
    ("siem.sinks[syslog].max_datagram", "2048", "Largest UDP datagram, 480 to 65000. A longer event is sent with "
     "its digests only."),
    ("siem.sinks[syslog].label", "syslog:host:port/transport", "A name for the sink in warnings."),
    ("siem.sinks[webhook].type", "required", "`webhook`."),
    ("siem.sinks[webhook].url", "required", "The collector's URL. `http://` is plaintext.", {"ha": "`http://` is "
     "refused"}),
    ("siem.sinks[webhook].auth_header", "Authorization when `auth_value_file` is set", "The header that carries "
     "the token."),
    ("siem.sinks[webhook].auth_value_file", "none", "A file holding the header's value. Owner-only, read once at "
     "start.", {"secret": True}),
    ("siem.sinks[webhook].hmac_key_file", "none", "A file holding an HMAC key; adds `X-Two-Key-Signature` to each "
     "request. Owner-only.", {"secret": True}),
    ("siem.sinks[webhook].ca_file", "the system's", "A CA bundle that the collector's certificate must chain to."),
    ("siem.sinks[webhook].cert_file", "none", "A client certificate, for mutual TLS."),
    ("siem.sinks[webhook].key_file", "none", "The client certificate's key. Owner-only.", {"secret": True}),
    ("siem.sinks[webhook].timeout_seconds", "5", "Seconds to wait for the collector."),
    ("siem.sinks[webhook].batch_max", "100", "Events per request, 1 to 1000."),
    ("siem.sinks[webhook].label", "webhook:host:port", "A name for the sink in warnings."),
])

# monitored_agent: exactly one of credential_env, credential: none, or username_env with password_env.
_ONE_OF_THREE = "one of three"

JUDGES = _rows(JUDGES_YAML, [
    ("judges", "required", "The Path B judges, at least one. Ids must be unique."),
    ("judges[].id", "required", "The judge's name in ballots and the ledger."),
    ("judges[].type", "required", "`openai_compatible`, `anthropic`, `gemini`, or `ollama`."),
    ("judges[].provider", "the type's own", "Who serves the model (a label, recorded)."),
    ("judges[].base_url", "the type's own (required for `openai_compatible`)", "The API address. Plain `http://` is "
     "allowed only on a loopback host unless `allow_insecure_http` is set."),
    ("judges[].model", "required", "The model name."),
    ("judges[].auth", "none", "How the judge signs in."),
    ("judges[].auth.type", "required with `auth`", "`none`, `env`, `keyring`, `callback`, or `basic`. A secret is "
     "never written in the file."),
    ("judges[].auth.var", "required for `env`", "Name of the environment variable holding the API key.",
     {"secret": True}),
    ("judges[].auth.service", "required for `keyring`", "The OS keyring service.", {"secret": True}),
    ("judges[].auth.username", "required for `keyring`", "The OS keyring user name.", {"secret": True}),
    ("judges[].auth.callback", "required for `callback`", "`module:function` that returns a token. Trusted operator "
     "code: whoever can write this file can run code in the Two-Key process.", {"secret": True}),
    ("judges[].auth.username_env", "required for `basic`", "Name of the environment variable holding the user "
     "name. HTTPS only.", {"secret": True}),
    ("judges[].auth.password_env", "required for `basic`", "Name of the environment variable holding the "
     "password. HTTPS only.", {"secret": True}),
    ("judges[].timeout", "30", "Seconds allowed for one request."),
    ("judges[].json_mode", "true", "Ask an `openai_compatible` judge for JSON."),
    ("judges[].max_tokens", "300", "Reply length for `openai_compatible` and `anthropic` judges."),
    ("judges[].auth_header", "the type's own (`bearer`, `x-api-key`, `x-goog-api-key`, `none` for ollama)",
     "How the credential is sent. `basic` goes only with `auth.type: basic`."),
    ("judges[].allow_insecure_http", "false", "Allow a plain `http://` base URL on a LAN address."),
    ("judges[].maker", "the provider", "Who made the model. Counted by `min_makers`. Not verified."),
    ("judges[].local_weights", "true for `ollama` on a loopback or private host, else false", "That the judge's "
     "weights run on your own hardware. A judge counts as local only when this is true and the host is loopback or "
     "private."),
    ("judges[].weights_sha256", "none", "A hash of the weights, recorded in ballots. Not verified."),
    ("judges[].echo_binding", "false", "The judge repeats the binding hashes in its ballot. Needed for "
     "`ballot_binding: echo`."),
    ("judges[].ballot_key_env", "none", "Name of an environment variable holding a key that signs the judge's "
     "ballot.", {"secret": True}),
    ("judges[].receives_proposal", "false", "Send this judge the proposal text."),
    ("judges[].response_format", "auto", "`auto`, `json_object`, `json_schema`, or `none`, for "
     "`openai_compatible`."),
    ("judges[].reasoning_effort", "none (xAI: low)", "`low`, `medium`, `high`, or `xhigh`, for "
     "`openai_compatible`."),
    ("judges[].tenant", "none", "A mapping of `organization`, `project`, `account`, `deployment`. Changes which "
     "warnings print; never lets the same agent start."),
    ("judges[].tenant.organization", "none", "The tenant's organization id."),
    ("judges[].tenant.project", "none", "The tenant's project id."),
    ("judges[].tenant.account", "none", "The tenant's account id."),
    ("judges[].tenant.deployment", "none", "The tenant's deployment id."),
    ("judges[].upstream", "none", "Where a local proxy forwards the judge's calls. Attested and recorded, not "
     "verified."),
    ("quorum", "none", "The quorum policy."),
    ("quorum.profile", "default", "`default` (one judge is enough) or `high_assurance`.", {"ha": "this is the setting that turns it on"}),
    ("quorum.required_yes", "the smaller of 2 and the number of judges", "Yes ballots needed to pass.",
     {"ha": "2"}),
    ("quorum.min_responding", "the effective `required_yes`", "Valid ballots needed before a round counts.",
     {"ha": "the effective `required_yes`"}),
    ("quorum.min_distinct_providers", "1", "Responding providers needed. 1 is not a floor."),
    ("quorum.timeout_seconds", "45", "The hard deadline for a round. A judge not done by then abstains. `null` is "
     "refused."),
    ("quorum.parallel", "true", "Ask the judges at the same time."),
    ("quorum.min_makers", "1", "Distinct judge model makers needed.", {"ha": "2"}),
    ("quorum.min_local_judges", "0", "Local judges needed.", {"ha": "1"}),
    ("quorum.require_local_yes", "false", "A local judge must itself vote yes.", {"ha": "true"}),
    ("quorum.heterogeneity_scope", "selection", "`selection` applies the maker and local floors to the judges chosen; "
     "`responding` also applies them to the judges that return valid ballots."),
    ("quorum.judge_inputs", "record_only", "`record_only` or `record_and_proposal`: whether judges see the "
     "proposal text."),
    ("quorum.ballot_binding", "stamp", "`stamp` or `echo`."),
    ("quorum.require_path_a_first", "false", "Stored, not enforced: `authorize` runs both paths either way."),
    ("quorum.tool_args_on_derive_deny", "false", "Send the arguments to judges, and ask them, after a derive "
     "deny."),
    ("quorum.tool_args_on_scan_flag", "false", "Send the arguments and the proposal to judges when the scanner "
     "flagged the call."),
    ("quorum.allow_same_provider_judge", "false", "Deprecated and ignored: the same provider is allowed."),
    ("quorum.allow_same_model_distinct_tenant", "false", "Deprecated and ignored."),
    ("quorum.judge_history", "on, with the defaults below", "The decision history summary judges get with each call "
     "(0.8.0): recent decisions for the same signed tool and allow-listed counterparty, counts for all tools, and the "
     "agent's bursts of denied calls. Built from signed names and reason codes only, never from the agent's text."),
    ("quorum.judge_history.enabled", "true", "`false` sends judges exactly the prompt 0.7.3 sent. It warns at start, "
     "is recorded in `quorum_policy`, and counts as weaker in `config set`."),
    ("quorum.judge_history.window_days", "90", "`7`, `30` or `90`: the longest window of allowed totals shown. "
     "Lower warns at start and counts as weaker."),
    ("quorum.judge_history.max_items", "10", "Past decisions (and attempt episodes) shown, 1 to 50. Lower warns at "
     "start and counts as weaker."),
    ("quorum.judge_history.on_failure", "deny", "`deny` or `judge_without_history`: what happens when the summary "
     "cannot be built. Either way a `judge_history_failed` entry is ledgered and sent to the SIEM. "
     "`judge_without_history` counts as weaker."),
    ("quorum.judge_history.burst_denies", "5", "An attempt episode is at least this many denied calls from one agent "
     "(2 to 1000) ..."),
    ("quorum.judge_history.burst_minutes", "10", "... within this many minutes (1 to 1440). Each episode is ledgered "
     "as `attempt_episode` and sent to the SIEM."),
    ("monitored_agent", "none", "The agent you run, declared by you and never by the agent. Judges are checked "
     "against it."),
    ("monitored_agent.id", "monitored-agent", "The agent's name in the ledger."),
    ("monitored_agent.model", "required", "The agent's model."),
    ("monitored_agent.provider", "required", "A label, recorded and never compared."),
    ("monitored_agent.base_url", "required", "The agent's API address."),
    ("monitored_agent.credential_env", _ONE_OF_THREE, "Name of the environment variable holding the agent's key.",
     {"secret": True}),
    ("monitored_agent.credential", _ONE_OF_THREE, "`none`, only for a keyless loopback or private agent."),
    ("monitored_agent.username_env", _ONE_OF_THREE, "With `password_env`, HTTP Basic over HTTPS.",
     {"secret": True}),
    ("monitored_agent.password_env", _ONE_OF_THREE, "With `username_env`.", {"secret": True}),
    ("monitored_agent.tenant", "none", "A mapping of `organization`, `project`, `account`, `deployment`."),
    ("monitored_agent.tenant.organization", "none", "The tenant's organization id."),
    ("monitored_agent.tenant.project", "none", "The tenant's project id."),
    ("monitored_agent.tenant.account", "none", "The tenant's account id."),
    ("monitored_agent.tenant.deployment", "none", "The tenant's deployment id."),
    ("monitored_agent.upstream", "none", "Where a local proxy routes the agent. Attested and recorded, not "
     "verified."),
])

AGENTS = _rows(AGENTS_YAML, [
    ("agents", "required", "The monitored agents, at least one. Ids must be unique."),
    ("agents[].id", "required", "The agent's name."),
    ("agents[].type", "required", "`openai_compatible`, `anthropic`, `gemini`, or `ollama`."),
    ("agents[].provider", "the type", "A label."),
    ("agents[].base_url", "the type's own (required for `openai_compatible`)", "The API address."),
    ("agents[].model", "required", "The model name."),
    ("agents[].auth", "none", "How the agent signs in (the same keys as `judges[].auth`)."),
    ("agents[].timeout", "60", "Seconds allowed for one request."),
    ("agents[].hosting", "from the address (`local` for `ollama`)", "`local` or `cloud`. Not trust."),
    ("agents[].max_tokens", "800", "Reply length."),
])

CONSTITUTION = _rows(PROSE_MD, [
    ("(the file)", "required", "The prose the judges read and Path B votes on. It is signed with the rules."),
])

_ONE_RULE_TYPE = "one rule type per rule"   # a rule has exactly one of these keys

RULES = _rows(RULES_YAML, [
    ("hard_rules", "required", "The rules Path A runs, at least one."),
    ("tool_specs", "required", "Where Path A reads each value, per tool. Every allow-listed tool needs one."),
    ("fields", "none", "The custom Path A fields, up to 64. A rules file with `fields:` signs as a v2 constitution."),
    ("serial", "none", "A positive integer: the principal's order of constitutions. A ledger that has run "
     "serial N refuses a lower one, and N again with other rules (`constitution_rollback`, "
     "`constitution_serial_reused`); once a ledger has run one with a serial, one without is refused too. "
     "Signs as a v3 constitution. `two-key setup` writes `serial: 1`; `config set` on a signed setting raises "
     "it by one."),
    ("hard_rules[].id", "`rule[i]:type`", "The rule's name in the ledger. Unique."),
    ("hard_rules[].allow_only_tools", _ONE_RULE_TYPE, "A list of tool ids; any other tool is denied."),
    ("hard_rules[].deny_counterparties", _ONE_RULE_TYPE, "A list of blocked parties, each exact. No "
     "`@domain` entries."),
    ("hard_rules[].deny_if", _ONE_RULE_TYPE, "A mapping of conditions; the call is denied when all of "
     "them hold."),
    ("hard_rules[].deny_if.tool", "none", "A tool id."),
    ("hard_rules[].deny_if.amount_usd_gt", "none", "A number of US dollars."),
    ("hard_rules[].deny_if.data_class_in", "none", "A list of data classes."),
    ("hard_rules[].deny_if.irreversible", "none", "`true` or `false`."),
    ("hard_rules[].deny_if_irreversible_over", _ONE_RULE_TYPE, "A number: deny an irreversible call "
     "over this amount."),
    ("hard_rules[].deny_if_fields", _ONE_RULE_TYPE, "A condition over custom fields. The scan stance is "
     "one of these, over the `scan` field."),
    ("tool_specs.<tool>.irreversible", "true", "`true` or `false`: whether the tool cannot be undone. Left out, "
     "the tool counts as irreversible."),
    ("tool_specs.<tool>.data_class_floor", "classified", "The lowest data class a call to the tool can claim: "
     "`public`, `personal`, `medical`, `financial`, or `classified`."),
    ("tool_specs.<tool>.amount", "none", "Where Path A reads the amount."),
    ("tool_specs.<tool>.amount.json_path", "required with `amount`", "The argument that holds the amount."),
    ("tool_specs.<tool>.amount.unit", "required with `amount`", "`usd` or `cents`."),
    ("tool_specs.<tool>.amount.currency_path", "none", "The argument that holds the currency, which must be "
     "`usd`."),
    ("tool_specs.<tool>.counterparties", "none", "Arguments that name a party."),
    ("tool_specs.<tool>.counterparties[].json_path", "required", "The argument that holds the party."),
    ("tool_specs.<tool>.counterparties[].allow", "required", "The allowed parties, each exact or an `@domain` "
     "entry. No wildcards."),
    ("tool_specs.<tool>.payload", "none", "Arguments that may be present and are not read."),
    ("tool_specs.<tool>.payload[].json_path", "required", "The argument."),
    ("tool_specs.<tool>.payload[].shape", "none", "`string`, `number`, or `list`."),
    ("tool_specs.<tool>.payload[].max_length", "none", "A positive integer, for a `string` or `list`."),
    ("tool_specs.<tool>.deny_unmapped", "false", "`true` denies an argument the spec does not name, instead of "
     "dropping it."),
    ("tool_specs.<tool>.tool_check", "none (off)", "The tool check (docs/TOOL_CHECK.md), for a tool behind "
     "`two-key mcp-proxy`: `{key: hybrid-sha256:...}` turns it on, `exempt` leaves it off. `high_assurance` refuses to "
     "start with a tool that has neither; `exempt` and turning it off are weaker."),
    ("tool_specs.<tool>.tool_check.key", "required with a mapping", "The fingerprint of the key that signs the "
     "tool's receipts, as `two-key tool-key new` prints it."),
    ("tool_specs.<tool>.fields", "none", "Maps each custom field to an argument, or marks it `not_applicable`."),
    ("tool_specs.<tool>.fields.<name>.json_path", "none", "The argument that holds the field's value."),
    ("tool_specs.<tool>.fields.<name>.source", "the arguments", "`caller` for a fact the proxy's hook supplies."),
    ("tool_specs.<tool>.fields.<name>.encrypted", "none", "`pass`, only on the `scan` field: an encrypted file "
     "reaches the tool without a look inside."),
    ("fields.<name>.type", "required", "`boolean`, `integer`, `enum`, `string`, or `path`."),
    ("fields.<name>.default", "required", "The value a tool that does not map the field gets."),
    ("fields.<name>.description", "none", "Text for the signer and the judges. Never an authorization rule."),
    ("fields.<name>.source", "the arguments", "`caller`: the value comes from the caller (the proxy's fact hook, or `facts=` in code), never "
     "from the agent."),
    ("fields.<name>.min", "required for `integer`", "The lowest value."),
    ("fields.<name>.max", "required for `integer`", "The highest value."),
    ("fields.<name>.values", "required for `enum`", "The allowed values."),
    ("fields.<name>.charset", "ascii", "`ascii` or `unicode`, for `enum` and `string`."),
    ("fields.<name>.scripts", "required with `charset: unicode`", "The one writing system allowed, such as `latin`, `cyrillic` or `arabic`. Not valid with `ascii`."),
    ("fields.<name>.max_length", "required for `string`", "Longest value."),
    ("fields.<name>.case", "case-insensitive for `string`, exact for `path`", "`exact`, for `string`; `insensitive`, for `path`."),
    ("fields.<name>.under", "required for `path`", "The folders a path must be inside, absolute and in clean form; not `/`, and none inside another."),
])

CATALOGUE: tuple[Setting, ...] = tuple(PROXY + JUDGES + AGENTS + CONSTITUTION + RULES)


def by_file(file: str) -> list[Setting]:
    return [s for s in CATALOGUE if s.file == file]


def lookup(file: str, key: str) -> Setting | None:
    return next((s for s in CATALOGUE if s.file == file and s.key == key), None)


# -- docs/SETTINGS.md ------------------------------------------------------------------------------------------

INTRO = """<!--
Copyright 2026 Insomniac-VibeLabs
Author: Stephan Busch
SPDX-License-Identifier: Apache-2.0
-->

# Every setting

Every key that Two-Key reads from a file, where it lives, what it does, its default, and what the
`high_assurance` profile does to it. This page is generated from `two_key/settings.py`, and
`tests/test_settings_doc.py` fails when a key the code accepts is missing from it, so it cannot go stale.
Regenerate it with `python tests/test_settings_doc.py --write`; do not edit it by hand.

To see what a proxy config resolves to, run `two-key config show --config proxy.yaml` (defaults filled in, no
secret values), or `two-key config get --config proxy.yaml NAME` for one setting. To find out whether it would
start, run `two-key config check --config proxy.yaml`. These three are read-only: they write nothing, open no
ledger, and contact no judge, scanner, collector or upstream server. To change one setting, run
`two-key config set --config proxy.yaml NAME VALUE`, named as in the tables below; [SETUP](SETUP.md) says what it
checks and refuses, and how `config undo` puts a change back. A first deployment is `two-key setup`.

## Contents

<!-- toc -->
<!-- /toc -->

## Who can change what

Settings are in two tiers on purpose. Who can change one is part of the security model.

| Tier | Files | Changing it needs | With `two-key config set` | What protects it |
| --- | --- | --- | --- | --- |
| **Signed policy** | `constitution.md`, `hard_rules.yaml`, signed into `constitution.signed.json` | The principal key, to sign again. Any other change refuses to load | `--key` (the principal key) and `--rules` (the file that was signed); shown, confirmed with a typed `yes`, signed and verified. The prose is not changed here: edit it and run `sign-constitution` | The signature |
| **Operator config** | `proxy.yaml`, `judges.yaml`, `agents.yaml` | Write access to the file, and a restart | Two-Key's own account; a weaker value needs `--confirm-weaker` and a typed `yes`. `agents.yaml` is not changed here | File permissions and the start-up checks. Not signed. The quorum policy's digest is ledgered, and so is every `config set` (`config_changed`) |
| **Secrets** | The principal, ledger, witness, capability and fingerprint keys, the head anchor, `proxy.env`, webhook secrets | Nobody edits them by hand | Never: a setting names a secret, and an env literal comes from `--value-file` or `--prompt`, never the command line | Owner-only files, refused if wider |

No setting holds a secret. Where a row says **names a secret**, the value is the name of an environment
variable or the path of an owner-only file; a loader refuses a secret written in the file. Library users
(`TwoKey(...)` and the guard) set the operator tier in Python, not in these files.

A running proxy keeps the settings it started with. A change to an operator file takes effect at the next start,
whether it was made by hand or with `config set`.

`two-key config show` prints the effective value of every `proxy.yaml` setting, with defaults filled in. It
does not say whether a value was set or defaulted. `two-key config get` prints one setting: its value, the file
that holds it, its tier, and its default. `two-key config check` loads the files together and runs the start-up
checks that need no running process; it checks the `on_agent_access` setting, but not which account starts the
proxy, and it does not compare the upstream's tools with `schema_digest`, which only the proxy can do.
A row that says **Not changed by `config set`** names a file, key or ledger Two-Key trusts: `two-key setup`
writes it, and moving it is done by hand, then checked.

## What `high_assurance` changes

`quorum.profile: high_assurance` turns on the diversity floors and makes the deployment checks stricter.
The profile is a setting in `judges.yaml`, so whoever can write that file can turn it off; the signed
constitution does not yet state a minimum profile.

| Setting | Normal default | Under `high_assurance` |
| --- | --- | --- |
| `quorum.required_yes` | the smaller of 2 and the number of judges | 2 |
| `quorum.min_responding` | the effective `required_yes` | the same |
| `quorum.min_makers` | 1 | 2 |
| `quorum.min_local_judges` | 0 | 1 |
| `quorum.require_local_yes` | false | true |
| `on_writable_paths` | `warn` | always refuses; `warn` is refused |
| `on_agent_access` | `refuse` | always refuses; `warn` is refused |
| a plaintext SIEM sink (`udp`, `tcp`, `http://`) | allowed, with a start-up warning | refused (`siem_plaintext_refused`) |
| a tool behind the proxy with no `tool_check` | allowed: the tool check is off | refused (`tool_check_required`); `exempt` is allowed and weaker |
| a scan stance other than `strict` (set by the signed `scan` rule) | allowed | allowed, with a start-up warning |
| one judge with `required_yes: 1` | `lone_judge_warning` | not reachable: two makers are needed |
| a quorum that could be too lenient (one judge, a minority approving, one provider or maker) | a `WARN` in `config check` and `setup` | the same, where it can still apply |
"""


def _cell(text: str) -> str:
    return (text or "").replace("|", "\\|")


def render_markdown() -> str:
    parts = [INTRO]
    for file in FILES:
        rows = by_file(file)
        tier = "signed policy" if TIER[file] == SIGNED else "operator config"
        parts.append(f"## `{file}`\n\nTier: {tier}. {FILE_NOTES[file]}\n")
        parts.append("| Setting | Default | `high_assurance` | What it does |\n| --- | --- | --- | --- |")
        for s in rows:
            summary = s.summary + (" **Names a secret.**" if s.names_secret else "") + (
                "" if s.settable or file == AGENTS_YAML else " **Not changed by `config set`.**")
            key = s.key if s.key.startswith("(") else f"`{s.key}`"
            parts.append(f"| {key} | {_cell(s.default)} | {_cell(s.high_assurance)} | {_cell(summary)} |")
        parts.append("")
    return "\n".join(parts).rstrip("\n") + "\n"

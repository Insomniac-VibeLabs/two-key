"""docs/SETTINGS.md maps every setting, and it cannot go stale.

The page is generated from the catalogue in ``two_key/settings.py``. This test reads the key sets the loaders
use (``proxy.yaml``, ``judges.yaml``, ``agents.yaml``, the rules file, the tool specs, the custom fields) and fails
when a key the code accepts has no row, when a row names a key the code no longer accepts, or when the page is not
what the catalogue renders. After adding a key, add its row to ``two_key/settings.py`` and regenerate the page:

    python tests/test_settings_doc.py --write
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

from test_doc_toc import with_toc  # noqa: E402
from two_key import agents, constitution, fields, identity, policy_vm, scan, scanners, settings, siem_sinks  # noqa: E402
from two_key.judges import config as judges_config  # noqa: E402
from two_key.mcp_proxy import config as proxy_config  # noqa: E402

PAGE = ROOT / "docs" / "SETTINGS.md"


def code_keys() -> set[tuple[str, str]]:
    """(file, key path) for every key the loaders accept, in the notation of ``two_key/settings.py``."""
    found: set[tuple[str, str]] = set()

    def add(file: str, base: str, keys) -> None:
        found.update((file, f"{base}{key}") for key in keys)

    add("proxy.yaml", "", proxy_config._TOP_KEYS)
    add("proxy.yaml", "keys.", proxy_config._KEY_KEYS)
    add("proxy.yaml", "upstream.", proxy_config._UPSTREAM_KEYS)
    add("proxy.yaml", "tools.<id>.", proxy_config._TOOL_KEYS)
    add("proxy.yaml", "tools.<id>.files[].", scan._FILE_KEYS)
    add("proxy.yaml", "scan.", scanners._COMMON | set().union(*scanners._TYPE_KEYS.values()))
    add("proxy.yaml", "siem.", siem_sinks._TOP_KEYS)
    add("proxy.yaml", "siem.sinks[syslog].", siem_sinks._SYSLOG_KEYS)
    add("proxy.yaml", "siem.sinks[webhook].", siem_sinks._WEBHOOK_KEYS)
    add("judges.yaml", "", judges_config.TOP_LEVEL_KEYS)
    add("judges.yaml", "judges[].", judges_config.JUDGE_KEYS)
    add("judges.yaml", "judges[].auth.", set().union(*judges_config.AUTH_KEYS.values()))
    add("judges.yaml", "judges[].tenant.", identity.TENANT_KEYS)
    add("judges.yaml", "quorum.", judges_config.QUORUM_KEYS)
    add("judges.yaml", "monitored_agent.", identity.AGENT_KEYS)
    add("judges.yaml", "monitored_agent.tenant.", identity.TENANT_KEYS)
    add("agents.yaml", "", ("agents",))
    add("agents.yaml", "agents[].", agents.AGENT_KEYS)
    add("constitution.md", "", ("(the file)",))
    add("hard_rules.yaml", "", constitution.RULES_FILE_KEYS)
    add("hard_rules.yaml", "hard_rules[].", set(policy_vm.RULE_TYPES) | set(policy_vm.RULE_META_KEYS))
    add("hard_rules.yaml", "hard_rules[].deny_if.", policy_vm.DENY_IF_KEYS)
    add("hard_rules.yaml", "tool_specs.<tool>.", constitution.TOOL_SPEC_KEYS)
    add("hard_rules.yaml", "tool_specs.<tool>.amount.", constitution.AMOUNT_KEYS)
    add("hard_rules.yaml", "tool_specs.<tool>.counterparties[].", constitution.COUNTERPARTY_KEYS)
    add("hard_rules.yaml", "tool_specs.<tool>.payload[].", constitution.PAYLOAD_KEYS)
    add("hard_rules.yaml", "tool_specs.<tool>.fields.<name>.", constitution.FIELD_MAPPING_KEYS)
    add("hard_rules.yaml", "fields.<name>.", set().union(*fields._TYPE_KEYS.values()))
    return found


def documented() -> set[tuple[str, str]]:
    return {(s.file, s.key) for s in settings.CATALOGUE}


def page_text() -> str:
    return with_toc(settings.render_markdown(), 2)


class SettingsPage(unittest.TestCase):
    def test_every_key_the_code_accepts_has_a_row(self):
        missing = sorted(code_keys() - documented())
        self.assertEqual(missing, [], "add a row for each to CATALOGUE in two_key/settings.py, then run "
                                      "python tests/test_settings_doc.py --write")

    def test_every_row_names_a_key_the_code_accepts(self):
        stale = sorted(documented() - code_keys())
        self.assertEqual(stale, [], "these rows name a key no loader accepts; fix or remove them in "
                                    "two_key/settings.py")

    def test_no_row_appears_twice(self):
        keys = [(s.file, s.key) for s in settings.CATALOGUE]
        self.assertEqual(sorted(k for k in set(keys) if keys.count(k) > 1), [])

    def test_the_page_is_what_the_catalogue_renders(self):
        self.assertEqual(PAGE.read_text(encoding="utf-8"), page_text(),
                         "run python tests/test_settings_doc.py --write")

    def test_a_secret_is_never_a_default(self):
        for s in settings.CATALOGUE:
            if s.names_secret:
                self.assertFalse(any(w in s.default.lower() for w in ("password", "token", "secret")), s.key)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        PAGE.write_text(page_text(), encoding="utf-8", newline="\n")
        print(f"wrote {PAGE.relative_to(ROOT)}")
    else:
        unittest.main()

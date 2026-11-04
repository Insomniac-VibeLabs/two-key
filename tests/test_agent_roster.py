# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The signed agent roster and the account check (0.9.0, two_key/roster.py), and opt-in judge diversity.

Network-free: the judges are test doubles. The account check runs against this process's real account.
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from two_key import roster  # noqa: E402
from two_key.constitution import ConstitutionError, sign_constitution, verify_signed  # noqa: E402
from two_key.core import TwoKey, TwoKeyConfigError  # noqa: E402
from two_key.keys import generate_private_key  # noqa: E402
from two_key.ledger import Ledger  # noqa: E402
from two_key.quorum import QuorumPolicy, agent_makers, other_maker  # noqa: E402
from two_key.siem import project  # noqa: E402
from two_key.testing import TEST_AGENT, FixedJudge  # noqa: E402

POSIX = os.name == "posix"
RULES = [{"id": "tools", "allow_only_tools": ["pay", "note"]}]
SPECS = {"pay": {"irreversible": True, "data_class_floor": "public", "payload": [{"json_path": "memo"}],
                 "agents": ["billing"]},
         "note": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "memo"}]}}


def me() -> tuple[int | None, str | None]:
    uid = os.getuid() if POSIX else None
    return uid, roster.account_name(uid)


def agents(name: str | None = None) -> list:
    return [{"id": "billing", "account": name or "tk-billing", "hosting": "agent-machine over ssh"},
            {"id": "public", "account": "tk-gateway", "shared": True}]


def quiet(fn, *a, **kw):
    with contextlib.redirect_stderr(io.StringIO()) as err:
        result = fn(*a, **kw)
    return result, err.getvalue()


class Validation(unittest.TestCase):
    def test_the_roster_is_canonical(self):
        out = roster.validate_agents([{"account": "b", "id": "zeta", "shared": False},
                                      {"id": "alpha", "account": "a", "hosting": " box "}])
        self.assertEqual(out, [{"id": "alpha", "account": "a", "hosting": "box"}, {"id": "zeta", "account": "b"}])

    def test_bad_rosters_are_refused(self):
        cases = {
            "share the account": [{"id": "a", "account": "x"}, {"id": "b", "account": "x"}],
            "duplicate id": [{"id": "a", "account": "x"}, {"id": "a", "account": "y"}],
            "reserved": [{"id": "unnamed", "account": "x"}],
            "unknown key": [{"id": "a", "account": "x", "model": "gpt"}],
            "account name": [{"id": "a", "account": "bad name"}],
            "shared: expected": [{"id": "a", "account": "x", "shared": "yes"}],
            "non-empty list": [],
        }
        for why, value in cases.items():
            with self.subTest(why), self.assertRaisesRegex(ConstitutionError, why):
                roster.validate_agents(value)

    def test_tool_agents(self):
        self.assertEqual(roster.validate_tool_agents("t", ["b", "a"], ["a", "b"]), ["a", "b"])
        self.assertEqual(roster.validate_tool_agents("t", "any", ["a"]), "any")
        for value, why in ((["c"], "not on the roster"), ([], "non-empty"), (["a", "a"], "twice")):
            with self.subTest(value), self.assertRaisesRegex(ConstitutionError, why):
                roster.validate_tool_agents("t", value, ["a"])
        with self.assertRaisesRegex(ConstitutionError, "needs an agents: roster"):
            roster.validate_tool_agents("t", ["a"], None)


class Signing(unittest.TestCase):
    def setUp(self):
        self.key = generate_private_key()

    def test_a_roster_signs_as_v3_and_verifies(self):
        env = sign_constitution("Pay billing's invoices.", RULES, self.key, SPECS, agents=agents())
        self.assertEqual(env["format"], "two-key-constitution-v3")
        con = verify_signed(env, self.key.public_key())
        self.assertEqual([a.id for a in con.agents], ["billing", "public"])
        self.assertTrue(con.agents[1].shared)
        self.assertEqual(con.tool_specs["pay"]["agents"], ["billing"])
        self.assertNotIn("agents", con.tool_specs["note"])

    def test_tool_agents_need_a_roster_and_v2_is_refused(self):
        with self.assertRaisesRegex(ConstitutionError, "needs an agents: roster"):
            sign_constitution("p", RULES, self.key, SPECS)
        roster_agents = agents()
        with self.assertRaisesRegex(ConstitutionError, "agent roster need a v3"):
            sign_constitution("p", RULES, self.key, SPECS, agents=roster_agents, envelope_format="v2")

    def test_a_non_canonical_signed_roster_is_refused(self):
        from two_key.canonical import canonical_bytes
        from two_key.keys import sign
        env = sign_constitution("p", RULES, self.key, SPECS, agents=agents())
        env["signed"]["agents"] = list(reversed(env["signed"]["agents"]))
        env["signature"] = sign(self.key, canonical_bytes(env["signed"]))
        public = self.key.public_key()
        with self.assertRaisesRegex(ConstitutionError, "canonical"):
            verify_signed(env, public)

    def test_without_a_roster_nothing_changes(self):
        specs = {k: {x: y for x, y in v.items() if x != "agents"} for k, v in SPECS.items()}
        env = sign_constitution("p", RULES, self.key, specs)
        self.assertEqual(env["format"], "two-key-constitution-v1")
        self.assertEqual(verify_signed(env, self.key.public_key()).agents, ())


class Resolve(unittest.TestCase):
    ROSTER = roster.roster_of(roster.validate_agents([{"id": "a", "account": "acct-a"},
                                                      {"id": "b", "account": "acct-b"}]))

    @staticmethod
    def lookup(name):
        return {"acct-a": 1001, "acct-b": 1002}.get(name)

    def test_the_account_picks_the_agent(self):
        self.assertEqual(roster.resolve(self.ROSTER, 1002, "acct-b (uid 1002)", None, lookup=self.lookup).id, "b")
        self.assertEqual(roster.resolve(self.ROSTER, 1001, "x", "a", lookup=self.lookup).id, "a")

    def test_an_unlisted_or_mismatched_account_is_refused(self):
        with self.assertRaises(roster.RosterError) as cm:
            roster.resolve(self.ROSTER, 1003, "other (uid 1003)", None, lookup=self.lookup)
        self.assertEqual(cm.exception.code, "agent_account_unlisted")
        with self.assertRaises(roster.RosterError) as cm:
            roster.resolve(self.ROSTER, None, "unknown", None, lookup=self.lookup)
        self.assertEqual(cm.exception.code, "agent_account_unlisted")
        with self.assertRaises(roster.RosterError) as cm:
            roster.resolve(self.ROSTER, 1001, "acct-a (uid 1001)", "b", lookup=self.lookup)
        self.assertEqual(cm.exception.code, "agent_account_mismatch")


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.key = generate_private_key()

    def start(self, roster_entries=None, specs=SPECS, judges=None, quorum=None, monitored=TEST_AGENT, **kw):
        env = sign_constitution("Pay billing's invoices.", RULES, self.key, specs, agents=roster_entries)
        con = verify_signed(env, self.key.public_key())
        ledger = quiet(Ledger, self.dir / "ledger", self.key)[0]
        tk, _ = quiet(TwoKey, ledger, self.key.public_key(), con, judges or [FixedJudge("j", "yes")],
                      private_key=self.key, quorum=quorum or QuorumPolicy(required_yes=1), allow_test_doubles=True,
                      monitored_agent=monitored, **kw)
        self.addCleanup(tk.close)
        return tk


class ToolAccess(Base):
    CALL = ({"tool": "pay", "data_class": "public"}, {"memo": "x"})

    def test_a_tool_for_other_agents_is_denied_before_the_judges(self):
        judge = FixedJudge("j", "yes")
        tk = self.start(agents(), judges=[judge])
        d = tk.authorize(*self.CALL, "pay it", agent_id="public")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "tool_not_for_agent")
        self.assertFalse(tk.authorize(*self.CALL, "pay it").allowed)        # no agent at all
        d = tk.authorize(*self.CALL, "pay it", agent_id="billing", agent_account="tk-billing")
        self.assertTrue(d.allowed, d.reason)
        decision = [e.body for e in tk.ledger.entries if e.kind == "decision"][-1]
        self.assertEqual(decision["agent"]["account"], "tk-billing")
        self.assertNotIn("agent", project("decision", decision))

    def test_roster_ids_are_named_to_judges(self):
        tk = self.start(agents())
        self.assertIn("billing", tk._history_agent_ids)
        self.assertIn("public", tk._history_agent_ids)


@unittest.skipUnless(POSIX, "the account that started the proxy is read on POSIX only")
class ProxyStart(Base):
    @staticmethod
    def config(agent_id=None, on=True):
        return SimpleNamespace(agent_id=agent_id, one_proxy_per_agent=on, hosting=None)

    def test_the_starting_account_picks_the_roster_entry(self):
        from two_key.mcp_proxy.core import served_agent
        uid, name = me()
        tk = self.start(agents(name))
        served = served_agent(tk, self.config(), False, parent=(uid, f"{name} (uid {uid})"))
        self.assertEqual((served.id, served.uid, served.account, served.source), ("billing", uid, name, "roster"))
        self.assertEqual(served.hosting, "agent-machine over ssh")

    def test_an_unlisted_account_is_refused_and_ledgered(self):
        from two_key.mcp_proxy.config import ProxyConfigError
        from two_key.mcp_proxy.core import refuse_agent, served_agent
        uid, _ = me()
        tk = self.start(agents("tk-nobody"))
        config = self.config()
        with self.assertRaises(roster.RosterError) as cm:
            served_agent(tk, config, False, parent=(uid, "me"))
        ledger = tk.ledger
        with self.assertRaisesRegex(ProxyConfigError, "agent_account_unlisted"):
            refuse_agent(tk, cm.exception, uid)
        refused = [e.body for e in Ledger(ledger.path, self.key).entries if e.kind == "agent_refused"]
        self.assertEqual(refused[0]["reason"], "agent_account_unlisted")
        self.assertEqual(refused[0]["account"]["uid"], uid)
        self.assertEqual(project("agent_refused", refused[0]).get("account"), None)

    def test_agent_id_naming_another_entry_is_refused(self):
        from two_key.mcp_proxy.core import served_agent
        uid, name = me()
        tk = self.start(agents(name))
        config = self.config("public")
        with self.assertRaises(roster.RosterError) as cm:
            served_agent(tk, config, False, parent=(uid, name))
        self.assertEqual(cm.exception.code, "agent_account_mismatch")

    def test_without_a_roster_the_account_is_still_recorded(self):
        from two_key.mcp_proxy.core import served_agent
        uid, name = me()
        specs = {k: {x: y for x, y in v.items() if x != "agents"} for k, v in SPECS.items()}
        tk = self.start(None, specs)
        served = served_agent(tk, self.config("grok"), False, parent=(uid, name))
        self.assertEqual((served.id, served.source, served.account_record()), ("grok", "proxy_yaml",
                                                                             {"uid": uid, "name": name}))

    def test_high_assurance_needs_a_roster_and_named_agents(self):
        from two_key.mcp_proxy.config import ProxyConfigError
        from two_key.mcp_proxy.core import served_agent
        uid, name = me()
        specs = {k: {x: y for x, y in v.items() if x != "agents"} for k, v in SPECS.items()}
        bare, config = self.start(None, specs), self.config()
        with self.assertRaisesRegex(ProxyConfigError, "agent_roster_required"):
            served_agent(bare, config, True, parent=(uid, name))
        listed = self.start(agents(name))
        with self.assertRaisesRegex(ProxyConfigError, r"agent_list_required: .*\['note'\]"):
            served_agent(listed, config, True, parent=(uid, name))

    def test_a_shared_group_takes_no_lock(self):
        from two_key.mcp_proxy.core import hold_agent_lock
        tk = self.start(agents())
        tk.served_agent = roster.ServedAgent("public", 1, "tk-gateway", "roster", shared=True)
        hold_agent_lock(tk, self.config())
        self.assertIsNone(getattr(tk, "agent_lock_fd", None))
        tk.served_agent = roster.ServedAgent("billing", 1, "tk-billing", "roster")
        hold_agent_lock(tk, self.config())
        self.assertIsNotNone(tk.agent_lock_fd)


class Diversity(Base):
    CALL = ({"tool": "note", "data_class": "public"}, {"memo": "x"})
    SPECS = {"pay": {"irreversible": True, "data_class_floor": "public"},
             "note": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "memo"}]}}

    def test_makers(self):
        makers = agent_makers([SimpleNamespace(provider="OpenAI", model="gpt-4o")])
        self.assertIn("openai", makers)
        self.assertFalse(other_maker(FixedJudge("a", "yes", provider="openai"), makers))
        self.assertFalse(other_maker(SimpleNamespace(maker="local", provider="local", model="gpt-4o-mini"), makers))
        self.assertTrue(other_maker(FixedJudge("b", "yes", provider="anthropic"), makers))

    def test_an_allow_needs_a_yes_from_another_maker(self):
        same = FixedJudge("same", "yes", provider=TEST_AGENT["provider"])
        other = FixedJudge("other", "no", provider="other-maker")
        policy = QuorumPolicy(required_yes=1, require_other_maker=True)
        tk = self.start(specs=self.SPECS, judges=[same, other], quorum=policy)
        d = tk.authorize(*self.CALL, "note")
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "other_maker_yes_required")
        self.assertTrue(policy.to_record()["require_other_maker"])
        self.assertNotIn("require_other_maker", QuorumPolicy().to_record())

    def test_off_by_default(self):
        same = FixedJudge("same", "yes", provider=TEST_AGENT["provider"])
        tk = self.start(specs=self.SPECS, judges=[same])
        self.assertTrue(tk.authorize(*self.CALL, "note").allowed)

    def test_no_other_maker_refuses_to_start(self):
        same = FixedJudge("same", "yes", provider=TEST_AGENT["provider"])
        policy = QuorumPolicy(required_yes=1, require_other_maker=True)
        with self.assertRaisesRegex(TwoKeyConfigError, "judge_diversity_unmet"):
            self.start(specs=self.SPECS, judges=[same], quorum=policy)


class ProxyCoreRoster(unittest.TestCase):
    """A proxy serving one roster agent: it lists only that agent's tools, and records the account."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def core(self, served):
        from test_mcp_proxy import RULES as P_RULES, SPECS as P_SPECS, UPSTREAM, config
        from two_key.mcp_proxy.core import ProxyCore, check_tools_signed, select_tools
        specs = dict(P_SPECS, read_report=dict(P_SPECS["read_report"], agents=["billing"]))
        key = generate_private_key()
        env = sign_constitution("Reports are fine.", P_RULES, key, specs, agents=agents())
        con = verify_signed(env, key.public_key())
        ledger = quiet(Ledger, Path(self.tmp, "ledger"), key)[0]
        tk = quiet(TwoKey, ledger, key.public_key(), con,
                   [FixedJudge("a", "yes")], private_key=key, quorum=QuorumPolicy(required_yes=1),
                   allow_test_doubles=True, monitored_agent=TEST_AGENT)[0]
        self.addCleanup(tk.close)
        tk.served_agent = served
        cfg = config()
        check_tools_signed(cfg, tk)
        return ProxyCore(tk, cfg, select_tools(UPSTREAM, tk.compiled.tool_specs, cfg.tools), lambda n, a: {"ran": n})

    def test_another_agents_tool_is_not_listed_and_is_denied(self):
        core = self.core(roster.ServedAgent("public", 1234, "tk-gateway", "roster", shared=True))
        self.assertNotIn("read_report", [t["name"] for t in core.list_tools()])
        out = core.call_tool("read_report", {})
        self.assertEqual((out.allowed, out.reason), (False, "tool_not_for_agent"))
        core.record_start()
        body = [e.body for e in core.two_key.ledger.entries if e.kind == "mcp_proxy_started"][-1]
        self.assertEqual(body["agent_id"], "public")
        self.assertEqual((body["account"], body["agent_source"]), ({"uid": 1234, "name": "tk-gateway"}, "roster"))
        event = project("mcp_proxy_started", body)
        self.assertNotIn("account", event)
        self.assertEqual(event["agent_source"], "roster")

    def test_the_listed_agent_gets_its_tool_and_its_account_on_the_decision(self):
        core = self.core(roster.ServedAgent("billing", 1001, "tk-billing", "roster"))
        self.assertIn("read_report", [t["name"] for t in core.list_tools()])
        out = core.call_tool("read_report", {})
        self.assertTrue(out.allowed, out.reason)
        decision = [e.body for e in core.two_key.ledger.entries if e.kind == "decision"][-1]
        self.assertEqual((decision["agent"]["id"], decision["agent"]["account"]), ("billing", "tk-billing"))


if __name__ == "__main__":
    unittest.main()

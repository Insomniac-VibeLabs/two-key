"""PRIOR_ART.md §4 (iii): quorum protocol specifics (the author selection, 2026-09-30, Entry 2 "C").

* judge-set selection enforcing vendor heterogeneity (>= 2 vendors including >= 1 local weight file);
* availability floor K distinct from approval threshold T; fewer than K valid ballots -> deny without counting;
* schema-constrained Boolean ballots bound to H(action record) and H(constitution); malformed -> abstain;
* judge inputs restricted to the normalized record + constitution (never transcript or tool outputs);
* Path B invoked only after Path A returns true.
"""
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from two_key.action import normalize_action
from two_key.judges import OllamaJudge, OpenAICompatibleJudge
from two_key.judges.base import Ballot, Judge
from two_key.judges.config import JudgeConfigError, load_config
from two_key.judges.credentials import StaticToken
from two_key.core import TwoKeyConfigError
from two_key.quorum import QuorumConfigError, QuorumPolicy, check_judge_set, convene
from two_key.testing import FixedJudge, RaisingJudge
from helpers import TwoKeyFixture

RULES = [{"id": "tools", "allow_only_tools": ["email_send", "search"]},
         {"id": "cap", "deny_if": {"amount_usd_gt": 200}}]
A = normalize_action({"tool": "search", "data_class": "public", "irreversible": False})
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
BIND = {"action_hash": "aa" * 32, "constitution_hash": "cc" * 32, "nl_hash": "11" * 32, "bytecode_hash": "22" * 32}


def hetero(vote_local="yes", vote_cloud="yes"):
    return [FixedJudge("cloud-a", vote_cloud, "openai", vendor="openai"),
            FixedJudge("cloud-b", vote_cloud, "anthropic", vendor="anthropic"),
            FixedJudge("local", vote_local, "ollama-local", vendor="meta-llama", local_weights=True)]


class Recording(Judge):
    is_test_double = True

    def __init__(self, jid, vendor, local=False, vote="yes", echo=None):
        self.judge_id, self.provider, self.vote, self.echo = jid, vendor, vote, echo
        self.local_weights, self.calls = local, []

    def score(self, constitution_text, action, proposal):
        return self.score_bound(constitution_text, action, proposal, None)

    def score_bound(self, constitution_text, action, proposal, binding):
        self.calls.append({"text": constitution_text, "action": action.to_record(), "proposal": proposal,
                           "binding": binding})
        b = Ballot(self.judge_id, self.provider, self.vote, 0.9, "rec")
        if self.echo == "correct" and binding:
            b = replace(b, action_hash=binding["action_hash"], constitution_hash=binding["constitution_hash"],
                        binding="echo")
        elif self.echo == "wrong":
            b = replace(b, action_hash="ff" * 32, constitution_hash=(binding or BIND)["constitution_hash"],
                        binding="echo")
        return b


class Heterogeneity(unittest.TestCase):
    def test_section4_profile_figures(self):
        p = QuorumPolicy.section4()
        self.assertEqual((p.min_vendors, p.min_local_judges, p.judge_inputs, p.require_path_a_first),
                         (2, 1, "record_only", True))
        check_judge_set(hetero(), p)

    def test_selection_refused_without_local_or_second_vendor(self):
        p = QuorumPolicy.section4()
        no_local = [FixedJudge("a", "yes", "openai"), FixedJudge("b", "yes", "anthropic")]
        one_vendor = [FixedJudge("a", "yes", "ollama", local_weights=True), FixedJudge("b", "yes", "ollama",
                                                                                      local_weights=True)]
        for js, why in ((no_local, "insufficient_local_judges:0<1"), (one_vendor, "insufficient_vendors:1<2")):
            with self.subTest(why):
                with self.assertRaisesRegex(QuorumConfigError, why):
                    check_judge_set(js, p)
                with self.assertRaisesRegex(TwoKeyConfigError, why), TwoKeyFixture(RULES, js, quorum_policy=p):
                    pass
                q = convene(js, "c", A, "p", p, BIND)  # defence in depth: the convenor refuses too
                self.assertEqual((q.passed, q.reason, q.counted), (False, f"judge_set_not_heterogeneous:{why}", False))

    def test_vendor_defaults_and_overrides(self):
        o = OllamaJudge(judge_id="l", provider="ollama-local", model="m")
        c = OpenAICompatibleJudge(judge_id="c", provider="xai", model="m", base_url="https://api.x.ai/v1",
                                  credential=StaticToken("t"))
        self.assertEqual((o.local_weights, c.local_weights, c.vendor), (True, False, "xai"))
        o2 = OllamaJudge(judge_id="l2", provider="ollama-local", model="m", local_weights=False, vendor="cloud")
        self.assertEqual((o2.local_weights, o2.vendor), (False, "cloud"))
        v = OpenAICompatibleJudge(judge_id="v", provider="vllm", model="m", base_url="http://127.0.0.1:8000/v1",
                                  local_weights=True, weights_sha256="ab" * 32)
        self.assertEqual(v.describe()["weights_sha256"], "ab" * 32)

    def test_config_keys_and_selection_check(self):
        base = {"judges": [{"id": "g", "type": "openai_compatible", "provider": "xai",
                            "base_url": "https://api.x.ai/v1", "model": "m"},
                           {"id": "c", "type": "anthropic", "model": "m"}]}
        with self.assertRaisesRegex(JudgeConfigError, "insufficient_local_judges"):
            load_config(dict(base, quorum={"required_yes": 2, "min_vendors": 2, "min_local_judges": 1}))
        ok = dict(base, quorum={"required_yes": 2, "min_responding": 3, "min_vendors": 2, "min_local_judges": 1,
                                "heterogeneity_scope": "responding", "judge_inputs": "record_only",
                                "ballot_binding": "echo", "require_path_a_first": True})
        ok["judges"] = base["judges"] + [{"id": "l", "type": "ollama", "model": "llama3", "vendor": "meta",
                                          "echo_binding": True}]
        judges, pol = load_config(ok)
        self.assertEqual((pol.min_responding, pol.ballot_binding), (3, "echo"))
        self.assertTrue(judges[2].local_weights and judges[2].echo_binding)
        with self.assertRaises(JudgeConfigError):
            load_config(dict(ok, quorum={"required_yes": 2, "judge_inputs": "everything"}))

    def test_policy_validation(self):
        for kw in ({"min_vendors": 0}, {"min_local_judges": -1}, {"min_vendors": True},
                   {"heterogeneity_scope": "x"}, {"judge_inputs": "x"}, {"ballot_binding": "x"},
                   {"require_path_a_first": "yes"}):
            with self.subTest(kw), self.assertRaises(QuorumConfigError):
                QuorumPolicy(**kw)

    def test_responding_scope(self):
        js = [FixedJudge("a", "yes", "openai"), FixedJudge("b", "yes", "anthropic"),
              RaisingJudge("local", "ollama")]
        js[2].local_weights = True
        p = QuorumPolicy(required_yes=2, min_vendors=2, min_local_judges=1, heterogeneity_scope="responding")
        q = convene(js, "c", A, "p", p, BIND)
        self.assertEqual(q.reason, "responding_not_heterogeneous:insufficient_local_judges:0<1")
        self.assertFalse(q.counted)
        self.assertTrue(convene(js, "c", A, "p", replace(p, heterogeneity_scope="selection"), BIND).passed)

    def test_loaded_entry_records_judge_attributes_and_policy(self):
        with TwoKeyFixture(RULES, hetero(), quorum_policy=QuorumPolicy.section4()) as tk:
            body = tk.ledger.latest_constitution().body
            self.assertEqual([j["vendor"] for j in body["judges"]], ["openai", "anthropic", "meta-llama"])
            self.assertEqual([j["local_weights"] for j in body["judges"]], [False, False, True])
            self.assertEqual((body["quorum"]["min_vendors"], body["quorum"]["min_local_judges"]), (2, 1))
            self.assertTrue(tk.authorize(SEARCH, "look").allowed)


class AvailabilityFloor(unittest.TestCase):
    def test_below_k_denies_without_counting(self):
        js = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), RaisingJudge("c", "p3")]
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=2, min_responding=3), BIND)
        self.assertFalse(q.passed)
        self.assertEqual(q.reason, "insufficient_responses:2<3")   # 2 yes >= T, but K not met
        self.assertEqual((q.counted, q.yes, q.no, q.valid, q.abstain), (False, None, None, 2, 1))
        rec = q.to_record()
        self.assertEqual((rec["counted"], rec["yes"], rec["no"], rec["min_responding"]), (False, None, None, 3))

    def test_k_distinct_from_t(self):
        js = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "no", "p2"), FixedJudge("c", "yes", "p3")]
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=2, min_responding=3), BIND)
        self.assertEqual((q.passed, q.counted, q.yes, q.no), (True, True, 2, 1))
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=3, min_responding=2), BIND)
        self.assertEqual((q.passed, q.reason, q.counted), (False, "insufficient_yes:2<3", True))

    def test_two_key_records_uncounted_round(self):
        js = [FixedJudge("a", "yes", "p1"), RaisingJudge("b", "p2")]
        with TwoKeyFixture(RULES, js, quorum_policy=QuorumPolicy(required_yes=1, min_responding=2)) as tk:
            d = tk.authorize(SEARCH, "look")
            self.assertEqual(d.reason, "path_b_denied:insufficient_responses:1<2")
            qr = next(e for e in tk.ledger.entries if e.kind == "quorum_result").body
            self.assertEqual((qr["counted"], qr["yes"], qr["no"]), (False, None, None))
            self.assertIsNone(d.quorum["yes"])


class BallotBinding(unittest.TestCase):
    def test_every_ballot_stamped_with_two_key_binding(self):
        with TwoKeyFixture(RULES, [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")],
                           quorum_policy=QuorumPolicy(required_yes=2)) as tk:
            d = tk.authorize(SEARCH, "look")
            self.assertTrue(d.allowed)
            qr = next(e for e in tk.ledger.entries if e.kind == "quorum_result").body
            expect = tk.ballot_binding(normalize_action(SEARCH).to_record())
            an = next(e for e in tk.ledger.entries if e.kind == "action_normalized").body
            self.assertEqual(expect["action_hash"], an["action_digest"])
            self.assertEqual(expect["constitution_hash"], tk.constitution.digest)
            self.assertEqual(qr["binding"], expect)  # written once per round
            for b in qr["ballots"]:
                self.assertEqual(b["binding"], "stamp")
                self.assertFalse(set(expect) & set(b))  # equal to the round binding, so not repeated
            for b in convene(tk.judges, "t", normalize_action(SEARCH), "", tk.quorum_policy, expect).ballots:
                self.assertEqual({f: getattr(b, f) for f in expect}, expect)  # in memory every ballot carries it

    def test_mismatched_binding_is_abstain(self):
        js = [Recording("a", "v1", echo="wrong"), Recording("b", "v2"), Recording("c", "v3")]
        q = convene(js, "c", A, "p", QuorumPolicy(required_yes=2), BIND)
        self.assertEqual(q.ballots[0].vote, "abstain")
        self.assertTrue(q.ballots[0].error.startswith("binding_mismatch"))
        self.assertEqual((q.ballots[0].action_hash, q.ballots[0].binding), ("ff" * 32, "mismatch"))
        rec = q.to_record()
        self.assertEqual(rec["ballots"][0]["action_hash"], "ff" * 32)  # what the judge reported is kept
        self.assertNotIn("constitution_hash", rec["ballots"][0])       # equal to the round binding
        self.assertTrue(q.passed)  # the other two still meet T=2
        q = convene(js[:2], "c", A, "p", QuorumPolicy(required_yes=2), BIND)
        self.assertFalse(q.passed)

    def test_echo_mode_requires_judge_bound_ballots(self):
        p = QuorumPolicy(required_yes=2, ballot_binding="echo")
        q = convene([Recording("a", "v1", echo="correct"), Recording("b", "v2")], "c", A, "p", p, BIND)
        self.assertEqual([b.binding for b in q.ballots], ["echo", "stamp"])
        self.assertTrue(q.ballots[1].error.startswith("unbound_ballot"))
        self.assertFalse(q.passed)
        q = convene([Recording("a", "v1", echo="correct"), Recording("b", "v2", echo="correct")], "c", A, "p", p,
                    BIND)
        self.assertTrue(q.passed)

    def test_judges_receive_binding(self):
        j = Recording("a", "v1")
        convene([j], "c", A, "p", QuorumPolicy(required_yes=1), BIND)
        self.assertEqual(j.calls[0]["binding"], BIND)


def openai_resp(obj):
    return {"choices": [{"message": {"content": json.dumps(obj) if not isinstance(obj, str) else obj}}]}


class Transport:
    def __init__(self, obj):
        self.obj, self.calls = obj, []

    def __call__(self, url, headers, body, timeout):
        self.calls.append(body)
        return openai_resp(self.obj)


class LLMEcho(unittest.TestCase):
    def judge(self, obj, echo=True):
        t = Transport(obj)
        return OpenAICompatibleJudge(judge_id="j", provider="xai", model="m", base_url="https://x.example/v1",
                                     credential=StaticToken("t"), transport=t, echo_binding=echo), t

    def test_echo_roundtrip(self):
        good = {"consistent": True, "confidence": 0.9, "rationale": "ok",
                "action_hash": BIND["action_hash"], "constitution_hash": BIND["constitution_hash"]}
        j, t = self.judge(good)
        q = convene([j], "CONST", A, "", QuorumPolicy(required_yes=1, ballot_binding="echo"), BIND)
        self.assertTrue(q.passed, q.reason)
        self.assertEqual(q.ballots[0].binding, "echo")
        blob = json.dumps(t.calls[0])
        self.assertIn("ballot_binding", blob)
        self.assertIn(BIND["action_hash"], blob)
        self.assertNotIn("untrusted_proposal", blob)  # record-only: no proposal section

    def test_echo_missing_or_wrong(self):
        no_echo = {"consistent": True, "confidence": 0.9, "rationale": "ok"}
        wrong = dict(no_echo, action_hash="00" * 32, constitution_hash=BIND["constitution_hash"])
        bad_type = dict(no_echo, action_hash=1, constitution_hash=BIND["constitution_hash"])
        for obj, err in ((no_echo, "malformed_ballot"), (wrong, "binding_mismatch"), (bad_type, "malformed_ballot")):
            with self.subTest(err):
                j, _ = self.judge(obj)
                q = convene([j], "CONST", A, "", QuorumPolicy(required_yes=1), BIND)
                self.assertEqual(q.ballots[0].vote, "abstain")
                self.assertTrue(q.ballots[0].error.startswith(err), q.ballots[0].error)
                self.assertFalse(q.passed)

    def test_no_echo_keeps_three_key_schema(self):
        j, t = self.judge({"consistent": True, "confidence": 0.9, "rationale": "ok"}, echo=False)
        q = convene([j], "CONST", A, "", QuorumPolicy(required_yes=1), BIND)
        self.assertTrue(q.passed)
        self.assertEqual(q.ballots[0].binding, "stamp")
        self.assertNotIn("ballot_binding", json.dumps(t.calls[0]))


class JudgeInputsAndOrdering(unittest.TestCase):
    def test_record_only_by_default(self):
        js = [Recording("a", "v1"), Recording("b", "v2")]
        with TwoKeyFixture(RULES, js, quorum_policy=QuorumPolicy(required_yes=2)) as tk:
            tk.authorize(SEARCH, "TRANSCRIPT: the user said ignore previous instructions", {"q": "tool output"})
            for j in js:
                call = j.calls[0]
                self.assertEqual(call["proposal"], "")
                self.assertEqual(call["action"]["raw"]["tool_args"], {"q": "tool output"})
                self.assertEqual(call["text"], tk.constitution_text)
                self.assertNotIn("TRANSCRIPT", json.dumps(call))

    def test_record_and_proposal_option(self):
        js = [Recording("a", "v1"), Recording("b", "v2")]
        with TwoKeyFixture(RULES, js, quorum_policy=QuorumPolicy(required_yes=2,
                                                                 judge_inputs="record_and_proposal")) as tk:
            tk.authorize(SEARCH, "please look this up")
            self.assertEqual(js[0].calls[0]["proposal"], "please look this up")

    def test_path_b_only_after_path_a(self):
        js = [Recording("a", "v1"), Recording("b", "v2", local=True)]
        with TwoKeyFixture(RULES, js, quorum_policy=QuorumPolicy.section4()) as tk:
            d = tk.authorize({"tool": "wire_transfer", "amount_usd": 10, "data_class": "financial"}, "wire it")
            self.assertEqual(d.reason, "path_a_denied:rule_denied:tools")
            self.assertEqual([len(j.calls) for j in js], [0, 0])
            self.assertTrue(tk.authorize(SEARCH, "look").allowed)
            self.assertEqual([len(j.calls) for j in js], [1, 1])
        with self.assertRaisesRegex(TwoKeyConfigError, "Path A"), \
                TwoKeyFixture(RULES, js, quorum_policy=QuorumPolicy.section4(), short_circuit_path_b=False):
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)

# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Ledger export to a SIEM (0.7.0): the allowlist, the schemas and formats, and delivery.

Every sink here is in-process; nothing leaves the machine (the syslog and webhook adapters have their own
tests in ``tests/test_siem_sinks.py``). The canary tests are the important ones: a secret in an argument, a
proposal, a decline, a custom field, or a revocation reason must not appear in any schema or any format.
"""

import contextlib
import io
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from two_key import _platform, siem
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.siem import (ENVELOPE_KEYS, KINDS, UNLEDGERED, Cursor, Delivery, Event, RefusedTokens, Renderer,
                          SiemConfig, SiemConfigError, SiemError, as_ecs, as_native, as_ocsf, event_for,
                          project, spec_for, to_cef, to_json)
from two_key.agents import MonitoredAgent
from two_key.testing import TEST_AGENT, FixedJudge

SECRET = "zz-secret-argument-zz"
PROPOSAL_SECRET = "zz-secret-proposal-zz"
DECLINE_SECRET = "zz-secret-decline-zz"
REVOKE_SECRET = "zz-secret-revocation-zz"
FIELD_SECRET = "zz-secret-field-zz"
CANARIES = (SECRET, PROPOSAL_SECRET, DECLINE_SECRET, REVOKE_SECRET, FIELD_SECRET)

RULES = [{"id": "tools", "allow_only_tools": ["search", "pay"]},
         {"id": "cap", "deny_if": {"amount_usd_gt": 100}}]
SPECS = {
    "search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]},
    "pay": {"irreversible": True, "data_class_floor": "financial",
            "amount": {"json_path": "amount_usd", "unit": "usd"},
            "counterparties": [{"json_path": "to", "allow": ["ops@example.org"]}],
            "payload": [{"json_path": "memo", "shape": "string"}],
            "fields": {"region": {"json_path": "region"}}},
}
FIELDS = {"region": {"type": "string", "max_length": 64, "default": "unset"}}
SEARCH = {"tool": "search", "data_class": "public"}
HIGH = [FixedJudge("a", "yes", provider="p0", maker="m0", local_weights=True),
        FixedJudge("b", "yes", provider="p1", maker="m1")]
# Bodies for the ledger kinds a test cannot produce in-process (the ledger writes them itself, or another
# integration does). The allowlist must cover every key of each one.
SAMPLE_BODIES = {
    "witness_pinned": {"witness_public_key": "AAAA"},
    "witness_rotated": {"format": "two-key-witness-rotation-v1", "seq": 3, "prev": "0" * 64,
                        "old_witness_public_key": "AAAA", "new_witness_public_key": "BBBB",
                        "reason": REVOKE_SECRET, "principal_signature": "s1",
                        "old_witness_signature": "s2", "new_witness_signature": "s3"},
    "ledger_recovered": {"dropped_bytes": 10, "dropped_sha256": "sha256:" + "0" * 64,
                         "dropped_nonempty_lines": 1, "tail_torn": False, "head_size": 4,
                         "tail_file": "/tmp/" + SECRET},
    "scanner_unavailable": {"scanner": "clamd", "error": "exception:OSError", "stance": "default"},
    "scanner_available": {"scanner": "clamd", "stance": "default"},
    "mcp_proxy_started": {"agent_id": "buyer", "upstream_program": "server", "upstream_command_digest": "sha256:" + "0" * 64,
                          "schema_digest_pinned": "sha256:" + "1" * 64,
                          "schema_digest_seen": "sha256:" + "1" * 64, "on_schema_change": "refuse",
                          "allow_unresolved_identity": False,
                          "tools": {"search": {"claim": "floor", "facts": []}},
                          "signed_tools_not_listed": []},
    "tool_not_offered": {"origin": "mcp-proxy", "tool": "nope"},
    "tool_receipt_invalid": {"jti": "j1", "tool": "search", "why": "bad_signature"},
    "tool_held": {"tool": "search", "jti": "j1", "why": "missing"},
    "tool_released": {"tool": "search", "reason": REVOKE_SECRET},
    "config_changed": {"command": "set", "settings": ["ttl_seconds"], "signed": False, "weaker": [],
                       "confirmed": False, "constitution_hash": None, "account": SECRET,
                       "files": [{"role": "proxy", "file": "proxy.yaml", "old_sha256": "sha256:" + "0" * 64,
                                  "new_sha256": "sha256:" + "1" * 64}]},
    "scan": {"tool": "search", "scanner": "clamd", "version": "1", "verdict": "flagged",
             "categories": ["malware"], "stance": "default", "elapsed_ms": 3, "scanner_available": True,
             "error": None, "parts": [{"part": "arguments", "bytes": 4, "sha256": "sha256:" + "0" * 64}]},
}


class ListSink:
    """A sink that keeps what it was sent. ``fail`` makes every send a :class:`SiemError`."""

    plaintext = False
    max_body_bytes = None

    def __init__(self, label="list", fail=False, delay=0.0):
        self.label, self.fail, self.delay = label, fail, delay
        self.sent = []
        self.checked = 0
        self.closed = 0

    def record(self):
        return {"type": "list", "label": self.label}

    def check(self):
        self.checked += 1

    def send(self, messages):
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise SiemError("collector is down")
        self.sent.extend(messages)

    def close(self):
        self.closed += 1

    @property
    def text(self):
        return "\n".join(m.body for m in self.sent)

    def seqs(self):
        return [json.loads(m.body)["seq"] for m in self.sent]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.key = generate_private_key()
        env = sign_constitution("Searching is fine. Paying needs care.", RULES, self.key, SPECS,
                                fields=FIELDS)
        self.con = verify_signed(env, self.key.public_key())

    def ledger(self, name="ledger"):
        return Ledger(self.dir / name, self.key)

    def start(self, *, siem_config=None, judges=None, quorum=None, ledger=None, **kw):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            tk = TwoKey(ledger or self.ledger(), self.key.public_key(), self.con,
                        judges or [FixedJudge("a", "yes")], private_key=self.key,
                        quorum=quorum or QuorumPolicy(required_yes=1), allow_test_doubles=True,
                        monitored_agent=TEST_AGENT, siem=siem_config, **kw)
        self.err = err.getvalue()
        self.addCleanup(tk.close)
        return tk

    def exercise(self, tk):
        """Walk the paths that write entries: an allow, a Path A deny, a decline, a gateway deny, a
        redemption, and a revocation."""
        allow = tk.authorize(SEARCH, {"q": "weather"}, "look up the weather")
        self.assertTrue(allow.allowed, allow.reason)
        deny = tk.authorize({"tool": "pay", "data_class": "financial", "amount_usd": 500.0},
                            {"amount_usd": 500.0, "to": "ops@example.org", "memo": SECRET,
                             "region": FIELD_SECRET},
                            f"pay the invoice {PROPOSAL_SECRET}")
        self.assertFalse(deny.allowed)
        agent = MonitoredAgent("grok", "xai", "grok", "https://api.x.ai/v1", "cloud",
                               kind="openai_compatible")
        declined = tk.authorize_from_agent(agent, json.dumps({"decline": DECLINE_SECRET}))
        self.assertEqual(declined.reason, "agent_declined")
        gw = tk.gateway(tools={"search": lambda a: "ok"})
        self.assertFalse(gw.invoke(allow.token, "search", {"q": SECRET}).allowed)
        second = tk.authorize(SEARCH, {"q": "weather"}, "look up the weather")
        self.assertTrue(gw.invoke(second.token, "search", {"q": "weather"}).allowed)
        tk.revoke(REVOKE_SECRET)
        return tk


class Allowlist(Fixture):
    def test_every_ledger_key_is_decided(self):
        """Each key of each body is sent, hashed, or excluded: a new ledger field is never exported by
        accident."""
        tk = self.exercise(self.start())
        for entry in tk.ledger.entries:
            self.check_body(entry.kind, entry.body)
        for kind, body in SAMPLE_BODIES.items():
            self.check_body(kind, body)

    def check_body(self, kind, body):
        spec = spec_for(kind)
        decided = set(spec.sent) | set(spec.hashed) | set(spec.excluded)
        for key in body:
            if key.endswith(("_size", "_digest", "_omitted")):
                continue        # the ledger's own size and digest keys, taken by shape
            self.assertIn(key, decided, f"{kind}.{key} is in no allowlist decision (two_key/siem.py)")

    def test_a_config_change_sends_names_and_digests_never_the_account(self):
        event = project("config_changed", SAMPLE_BODIES["config_changed"])
        self.assertEqual(event["settings"], ["ttl_seconds"])
        self.assertEqual(event["files"][0]["new_sha256"], "sha256:" + "1" * 64)
        self.assertNotIn(SECRET, json.dumps(event))

    def test_known_kinds_cover_the_ledger(self):
        tk = self.exercise(self.start())
        for entry in tk.ledger.entries:
            self.assertIn(entry.kind, KINDS, f"{entry.kind} has no allowlist entry")

    def test_no_field_shares_a_name_with_the_envelope(self):
        for kind, spec in {**KINDS, **UNLEDGERED}.items():
            for key in spec.sent + spec.hashed:
                self.assertNotIn(key, ENVELOPE_KEYS, f"{kind}.{key} would shadow the event envelope")

    def test_an_unknown_kind_sends_nothing_but_its_identity(self):
        """A ledger written by a newer Two-Key does not leak through an older exporter."""
        self.assertEqual(project("something_new_in_0_9", {"secret": SECRET, "size": 3}), {})

    def test_excluded_values_never_reach_an_event(self):
        tk = self.exercise(self.start())
        text = json.dumps([project(e.kind, e.body) for e in tk.ledger.entries])
        for canary in CANARIES:
            self.assertNotIn(canary, text)

    def test_the_proposal_and_the_revocation_reason_become_a_size_and_a_digest(self):
        tk = self.exercise(self.start())
        proposal = [project(e.kind, e.body) for e in tk.ledger.entries if e.kind == "proposal"][1]
        self.assertGreater(proposal["proposal_size"], 10)
        self.assertTrue(proposal["proposal_digest"].startswith("sha256:"))
        self.assertNotIn("proposal", proposal)
        [revocation] = [project(e.kind, e.body) for e in tk.ledger.entries if e.kind == "revocation"]
        self.assertEqual(revocation["reason_size"], len(REVOKE_SECRET))
        self.assertNotIn("reason", revocation)

    def test_the_form_sends_the_data_class_but_not_the_amount_or_counterparty(self):
        tk = self.exercise(self.start())
        [normalized] = [project(e.kind, e.body) for e in tk.ledger.entries
                        if e.kind == "action_normalized" and e.body["tool"] == "pay"]
        self.assertEqual(normalized["data_class"], "financial")
        self.assertTrue(normalized["irreversible"])
        for key in normalized:
            self.assertNotIn("amount", key)
            self.assertNotIn("counterparty", key)
        self.assertNotIn("500", json.dumps(normalized))

    def test_the_agent_id_is_sent_and_the_record_is_not(self):
        tk = self.start()
        tk.authorize(SEARCH, {"q": "weather"}, "look", agent_id="agent-7", hosting="cloud")
        [decision] = [project(e.kind, e.body) for e in tk.ledger.entries if e.kind == "decision"]
        self.assertEqual(decision["agent_id"], "agent-7")
        self.assertEqual(decision["agent_hosting"], "cloud")
        self.assertNotIn("agent", decision)

    def test_size_keys_must_have_the_right_shape(self):
        """A body that puts text where a digest belongs sends neither."""
        body = {"reason": "x", "jti": "j", "tool_args_digest": SECRET, "tool_args_size": "big",
                "tool_args_omitted": SECRET}
        self.assertEqual(project("gateway_denied", body), {"reason": "x", "jti": "j"})

    def test_a_long_value_is_capped_and_control_characters_go(self):
        body = {"reason": "a" * 500 + "\n\x00b"}
        reason = project("path_a", body)["reason"]
        self.assertEqual(len(reason), siem.MAX_TEXT_CHARS)
        self.assertNotIn("\n", reason)

    def test_a_float_json_cannot_spell_is_dropped(self):
        """NaN and the infinities have no JSON spelling, so an event carries None where one was."""
        self.assertEqual(siem._scrub(1.5), 1.5)
        for bad in (float("nan"), float("inf"), float("-inf")):
            self.assertIsNone(siem._scrub(bad))


class Schemas(Fixture):
    def event(self, kind="decision", fields=None):  # skipcq: PYL-R0201 - test only
        return Event(seq=7, entry_hash="h" * 64, prev="p" * 64, kind=kind,
                     fields=fields if fields is not None else {"allowed": True, "reason": "both_paths_allow",
                                                               "tool": "search", "agent_id": "agent-7"},
                     sent_at="2026-10-16T03:04:05.678Z")

    def test_native_carries_the_identity_and_the_fields(self):
        out = as_native(self.event())
        self.assertEqual(out["schema"], siem.SCHEMA_FORMAT)
        self.assertEqual((out["seq"], out["kind"], out["entry_hash"]), (7, "decision", "h" * 64))
        self.assertEqual(out["reason"], "both_paths_allow")
        self.assertTrue(out["ledgered"])
        self.assertNotIn("replay", out)

    def test_a_field_cannot_shadow_the_envelope(self):
        out = as_native(self.event(fields={"seq": 999, "kind": "other", "schema": "forged"}))
        self.assertEqual((out["seq"], out["kind"], out["schema"]), (7, "decision", siem.SCHEMA_FORMAT))

    def test_ecs_maps_the_outcome_and_keeps_the_rest_under_two_key(self):
        out = as_ecs(self.event())
        self.assertEqual(out["event"]["outcome"], "success")
        self.assertEqual(out["event"]["action"], "decision")
        self.assertEqual(out["event"]["sequence"], 7)
        self.assertEqual(out["observer"]["product"], "Two-Key")
        self.assertEqual(out["user"]["id"], "agent-7")
        self.assertEqual(out["two_key"]["reason"], "both_paths_allow")
        self.assertEqual(out["@timestamp"], "2026-10-16T03:04:05.678Z")

    def test_ecs_and_ocsf_report_a_deny_as_a_failure(self):
        deny = self.event(fields={"allowed": False, "reason": "path_a_deny:cap"})
        self.assertEqual(as_ecs(deny)["event"]["outcome"], "failure")
        self.assertEqual(as_ocsf(deny)["status_id"], 2)
        self.assertEqual(as_ocsf(deny)["status_detail"], "path_a_deny:cap")

    def test_ocsf_is_an_authorize_session_event(self):
        out = as_ocsf(self.event())
        self.assertEqual((out["class_uid"], out["category_uid"], out["type_uid"]), (3003, 3, 300399))
        self.assertEqual(out["metadata"]["sequence"], 7)
        self.assertEqual(out["metadata"]["product"]["name"], "Two-Key")
        self.assertEqual(out["time"], 1792119845678)
        self.assertEqual(out["unmapped"]["reason"], "both_paths_allow")

    def test_no_schema_carries_more_than_the_allowlist(self):
        tk = self.exercise(self.start())
        for name in siem.SCHEMAS:
            renderer = Renderer(name, "json")
            text = "\n".join(renderer.body(event_for(e)) for e in tk.ledger.entries)
            for canary in CANARIES:
                self.assertNotIn(canary, text, f"{name} leaked {canary}")

    def test_cef_is_one_line_and_escapes_its_separators(self):
        line = to_cef(self.event(fields={"reason": "a|b=c\\d", "tool": "search"}))
        self.assertTrue(line.startswith("CEF:0|Insomniac-VibeLabs|Two-Key|"))
        self.assertIn("reason=a|b\\=c\\\\d", line)
        self.assertIn("cs2Label=entryHash", line)
        self.assertEqual(len(line.splitlines()), 1)

    def test_cef_needs_the_native_schema(self):
        with self.assertRaisesRegex(SiemConfigError, "cef maps the native schema only"):
            Renderer("ecs", "cef")

    def test_json_is_always_one_line(self):
        self.assertEqual(len(to_json({"a": "x\ny"}).splitlines()), 1)

    def test_severity_is_warning_for_a_deny_and_notice_for_a_rotation(self):
        self.assertEqual(siem.severity_of("decision", {"allowed": True}), siem.INFORMATIONAL)
        self.assertEqual(siem.severity_of("decision", {"allowed": False}), siem.WARNING)
        self.assertEqual(siem.severity_of("gateway_denied", {}), siem.WARNING)
        self.assertEqual(siem.severity_of("witness_rotated", {}), siem.NOTICE)
        self.assertEqual(siem.severity_of("path_b", {"passed": False}), siem.WARNING)


class Delivering(Fixture):
    def config(self, *sinks, **kw):  # skipcq: PYL-R0201 - test only
        return SiemConfig(sinks=tuple(sinks), **kw)

    def drain(self, tk, sink, want):
        for _ in range(200):
            if len(sink.sent) >= want:
                return
            tk.delivery.drain(0.5)
        self.fail(f"{sink.label} took {len(sink.sent)} of {want} events")

    def test_every_entry_reaches_the_sink_in_order_with_its_hash(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.drain(tk, sink, tk.ledger.size())
        self.assertEqual(sink.seqs(), list(range(tk.ledger.size())))
        for message in sink.sent:
            body = json.loads(message.body)
            self.assertEqual(body["entry_hash"], tk.ledger.entries[body["seq"]].entry_hash)
        self.assertEqual(sink.checked, 1)

    def test_the_configuration_is_ledgered_and_exported(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        [entry] = [e for e in tk.ledger.entries if e.kind == "siem_configured"]
        self.assertEqual(entry.body["sinks"], [{"type": "list", "label": "list"}])
        self.assertEqual(entry.body["event_schema"], "native")
        self.drain(tk, sink, tk.ledger.size())

    def test_catch_up_after_an_outage_leaves_no_gap_and_is_marked_a_replay(self):
        sink = ListSink(fail=True)
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        tk.authorize(SEARCH, {"q": "weather"}, "look")
        tk.delivery.drain(1)
        self.assertEqual(sink.sent, [])
        sink.fail = False
        for state in tk.delivery.states:        # the sender is in its backoff; let it try now
            state.next_try = 0.0
        size = tk.ledger.size()
        self.drain(tk, sink, size)
        self.assertEqual(sink.seqs(), list(range(size)))
        early = [json.loads(m.body) for m in sink.sent if json.loads(m.body)["seq"] < 2]
        self.assertTrue(all(body["replay"] for body in early), "a late copy says so")

    def test_a_restart_resumes_from_the_cursor(self):
        first, second = ListSink(), ListSink()
        tk = self.start(siem_config=self.config(first, replay_from="start"))
        self.drain(tk, first, tk.ledger.size())
        tk.close()
        cursor = tk.delivery.cursor.path
        self.assertTrue(cursor.is_file())
        again = self.start(ledger=self.ledger(), siem_config=self.config(second))
        again.authorize(SEARCH, {"q": "weather"}, "look")
        self.drain(again, second, 1)
        self.assertEqual(min(second.seqs()), first.seqs()[-1] + 1)

    def test_on_a_shared_ledger_the_other_proxys_entries_are_marked_replay(self):
        """Run 9y, F4: each proxy sends every entry, so the copies it sends of the other proxy's are marked."""
        mine, other = ListSink("mine"), ListSink("other")
        tk = self.start(ledger=self.ledger(), siem_config=self.config(mine, replay_from="now"))
        peer = self.start(ledger=self.ledger(), siem_config=self.config(other, replay_from="now"))
        start = tk.ledger.size()
        tk.authorize(SEARCH, {"q": "weather"}, "look")       # reads peer's start first, then writes its own
        theirs = {e.seq for e in tk.ledger.entries[start:] if tk.ledger.from_another_process(e.seq)}
        self.assertTrue(theirs, "the peer's start was read from the shared file")
        self.drain(tk, mine, tk.ledger.size() - start)
        bodies = {json.loads(m.body)["seq"]: json.loads(m.body) for m in mine.sent}
        for seq in range(start, tk.ledger.size()):
            with self.subTest(seq=seq):
                self.assertEqual(bodies[seq].get("replay", False), seq in theirs)

    def _restart_with_cursor(self, edit, resumes=False):
        """Run once to fill the cursor, change it with ``edit``, then start again on the same ledger. ``resumes``:
        the second start is expected to send only the entries after the cursor."""
        first, second = ListSink(), ListSink()
        tk = self.start(siem_config=self.config(first, replay_from="start"))
        self.drain(tk, first, tk.ledger.size())
        tk.close()
        path = tk.delivery.cursor.path
        data = json.loads(path.read_text(encoding="utf-8"))
        edit(data)
        path.write_text(json.dumps(data), encoding="utf-8")
        again = self.start(ledger=self.ledger(), siem_config=self.config(second))
        want = again.ledger.size() - (data["sinks"]["list"] + 1 if resumes else 0)
        self.drain(again, second, want)
        return again, second

    def test_a_cursor_past_the_ledger_head_replays_everything_and_warns(self):
        """Live run 9x, C140: a cursor ahead of the ledger is not trusted, so nothing is skipped silently."""
        def ahead(data):
            data["sinks"] = {k: v + 1000 for k, v in data["sinks"].items()}
        tk, sink = self._restart_with_cursor(ahead)
        self.assertIn("past this ledger's last entry", self.err)
        self.assertIn("sending the whole ledger again, marked replay", self.err)
        self.assertEqual(min(sink.seqs()), 0)
        early = [json.loads(m.body) for m in sink.sent]
        self.assertTrue(all(body["replay"] for body in early if body["seq"] < 3))

    def test_a_cursor_for_another_ledger_replays_everything_and_warns(self):
        def other(data):
            data["hashes"] = dict.fromkeys(data["hashes"], "0" * 64)
        _, sink = self._restart_with_cursor(other)
        self.assertIn("is not this ledger's", self.err)
        self.assertEqual(min(sink.seqs()), 0)

    def test_a_cursor_without_hashes_still_resumes(self):
        """A cursor written before 0.7.x kept no hashes: it is checked by length only."""
        seen = {}

        def older(data):
            seen["seq"] = data["sinks"]["list"]
            data.pop("hashes")
        _, sink = self._restart_with_cursor(older, resumes=True)
        self.assertNotIn("delivery cursor", self.err)
        self.assertEqual(min(sink.seqs()), seen["seq"] + 1)

    def test_the_cursor_keeps_the_hash_of_the_last_entry_taken(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        self.drain(tk, sink, tk.ledger.size())
        tk.close()
        data = json.loads(tk.delivery.cursor.path.read_text(encoding="utf-8"))
        seq = data["sinks"]["list"]
        self.assertEqual(data["hashes"]["list"], tk.ledger.entries[seq].entry_hash)

    def test_replay_from_now_does_not_flood_a_new_siem(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="now"))
        before = tk.ledger.size()
        tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.drain(tk, sink, 1)
        self.assertEqual(min(sink.seqs()), before)

    def test_a_full_queue_loses_nothing(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="start", queue_max=1))
        for _ in range(5):
            tk.authorize(SEARCH, {"q": "weather"}, "look")
        size = tk.ledger.size()
        self.drain(tk, sink, size)
        self.assertEqual(sink.seqs(), list(range(size)))

    def test_a_stuck_sink_does_not_delay_a_decision(self):
        sink = ListSink(delay=5.0)
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        started = time.monotonic()
        for _ in range(3):
            self.assertTrue(tk.authorize(SEARCH, {"q": "weather"}, "look").allowed)
        self.assertLess(time.monotonic() - started, 4.0)

    def test_a_sink_that_cannot_be_reached_at_start_is_a_warning_not_a_refusal(self):
        class Unreachable(ListSink):
            def check(self):
                raise SiemError("no route to host")

        sink = Unreachable()
        tk = self.start(siem_config=self.config(sink))
        self.assertIn("WARNING: siem: list: no route to host", self.err)
        self.assertTrue(tk.authorize(SEARCH, {"q": "weather"}, "look").allowed)

    def test_an_oversized_event_falls_back_to_its_digests(self):
        class Tiny(ListSink):
            max_body_bytes = 120

        sink = Tiny()
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        self.drain(tk, sink, 3)
        shortened = [json.loads(m.body) for m in sink.sent if json.loads(m.body).get("truncated")]
        self.assertTrue(shortened)
        self.assertTrue(all("seq" in body and "entry_hash" in body for body in shortened))

    def test_close_is_idempotent_and_closes_the_sinks(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink))
        tk.close()
        tk.close()
        self.assertEqual(sink.closed, 1)

    def test_the_cursor_file_is_owner_only_and_outside_the_ledger(self):
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        self.drain(tk, sink, tk.ledger.size())
        path = tk.delivery.cursor.path
        self.assertFalse(_platform.inside(path, tk.ledger.path))
        if not _platform.WINDOWS:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)
        self.assertTrue(_platform.is_owner_only_dir(path.parent))

    def test_a_cursor_that_cannot_be_read_starts_from_the_head_and_warns(self):
        path = self.dir / "cursor.json"
        path.write_text("not json", encoding="utf-8")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cursor = Cursor(path)
        self.assertFalse(cursor.exists)
        self.assertEqual(cursor.get("list", 12), 12)
        # Not a first start: say which entries only the ledger now holds (live run 8x, C72).
        self.assertIn("is not readable; the copy starts where replay_from says", err.getvalue())

    def test_no_cursor_file_is_a_first_start_and_says_nothing(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            cursor = Cursor(self.dir / "none" / "cursor.json")
        self.assertFalse(cursor.exists)
        self.assertEqual(err.getvalue(), "")

    def test_a_shrunken_ledger_does_not_stall_the_sender(self):
        """After ``two-key recover`` dropped a tail the sink already took, the cursor comes back."""
        sink = ListSink()
        tk = self.start(siem_config=self.config(sink, replay_from="start"))
        self.drain(tk, sink, tk.ledger.size())
        [state] = tk.delivery.states
        state.seq = tk.ledger.size() + 10
        tk.authorize(SEARCH, {"q": "weather"}, "look")
        tk.delivery.drain(1)
        self.assertEqual(state.seq, tk.ledger.size() - 1)


class WithoutSiem(Fixture):
    def test_the_ledger_is_what_it_was(self):
        """Without ``siem=``, nothing changes: no entry, no observer, no thread."""
        tk = self.exercise(self.start())
        self.assertNotIn("siem_configured", [e.kind for e in tk.ledger.entries])
        self.assertIsNone(tk.delivery)
        self.assertIsNone(tk.refused_tokens)
        self.assertEqual(tk.ledger._observers, [])
        self.assertFalse(any("siem" in name for name in [t.name for t in threading.enumerate()]))

    def test_close_without_a_sender_does_nothing(self):
        self.start().close()

    def test_the_gateway_counts_nothing_by_default(self):
        tk = self.start()
        gateway = tk.gateway(tools={"search": lambda a: "ok"})
        self.assertFalse(gateway.invoke("garbage", "search", {"q": "x"}).allowed)
        self.assertEqual(gateway.refused_token_counts(), {})


class Plaintext(Fixture):
    def plain(self, label="plain"):  # skipcq: PYL-R0201 - test only
        sink = ListSink(label=label)
        sink.plaintext = True
        return sink

    def test_plaintext_warns_and_still_starts(self):
        tk = self.start(siem_config=SiemConfig(sinks=(self.plain(),)))
        self.assertIn("the SIEM copy goes out in the clear to ['plain']", self.err)
        self.assertTrue(tk.authorize(SEARCH, {"q": "weather"}, "look").allowed)

    # high_assurance also refuses to start on a machine where another account can change Python's files
    # (two_key/writable.py, and /opt is world-writable on a GitHub runner); these two tests are about the
    # sink, so they do not look at the machine.
    @mock.patch("two_key.writable.runtime_targets", return_value=[])
    def test_high_assurance_refuses_plaintext(self, _):
        with self.assertRaisesRegex(TwoKeyConfigError, "siem_plaintext_refused"):
            self.start(judges=HIGH, quorum=QuorumPolicy.high_assurance(required_yes=2, timeout_seconds=10),
                       siem_config=SiemConfig(sinks=(self.plain(),)))

    @mock.patch("two_key.writable.runtime_targets", return_value=[])
    def test_high_assurance_takes_an_encrypted_sink(self, _):
        tk = self.start(judges=HIGH, quorum=QuorumPolicy.high_assurance(required_yes=2, timeout_seconds=10),
                        siem_config=SiemConfig(sinks=(ListSink(),)))
        self.assertNotIn("in the clear", self.err)
        self.assertIsNotNone(tk.delivery)

    def test_a_bad_siem_argument_is_refused(self):
        with self.assertRaisesRegex(TwoKeyConfigError, "siem_invalid"):
            self.start(siem_config={"sinks": []})


class Config(unittest.TestCase):
    def test_a_config_needs_a_sink(self):
        with self.assertRaisesRegex(SiemConfigError, "at least one sink"):
            SiemConfig(sinks=())

    def test_two_sinks_may_not_share_a_label(self):
        with self.assertRaisesRegex(SiemConfigError, "same label"):
            SiemConfig(sinks=(ListSink(), ListSink()))

    def test_an_unknown_schema_or_replay_is_refused(self):
        with self.assertRaisesRegex(SiemConfigError, "siem.schema"):
            SiemConfig(sinks=(ListSink(),), schema="splunk")
        with self.assertRaisesRegex(SiemConfigError, "siem.replay_from"):
            SiemConfig(sinks=(ListSink(),), replay_from="yesterday")

    def test_the_record_names_where_the_copy_goes(self):
        record = SiemConfig(sinks=(ListSink(),), schema="ecs").record()
        self.assertEqual(record["event_schema"], "ecs")
        self.assertEqual(record["sinks"], [{"type": "list", "label": "list"}])


class Refused(unittest.TestCase):
    def counter(self, **kw):
        self.reported = []
        self.clock = [0.0]
        return RefusedTokens(report=self.reported.append, clock=lambda: self.clock[0], **kw)

    def test_a_refusal_is_classed_never_quoted(self):
        counter = self.counter()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            counter.note("bad_signature")
        self.assertEqual(len(self.reported), 1)
        counts = self.reported[0]
        self.assertEqual(counts["bad_signature"], 1)
        self.assertEqual(counts["total"], 1)
        self.assertIn("bad_signature=1", err.getvalue())
        self.assertIn("no ledger entry", err.getvalue())

    def test_classes_fold_the_library_codes(self):
        counter = self.counter(interval_seconds=1000)
        with contextlib.redirect_stderr(io.StringIO()):
            for reason in ("malformed_token", "issued_in_future", "ttl_too_long", "expired"):
                counter.note(reason)
        self.assertEqual(self.reported[0]["malformed"], 1)      # the first one is reported at once
        self.assertEqual(counter.counts(), {"bad_signature": 0, "expired": 2, "malformed": 0, "other": 1})

    def test_the_report_is_rate_limited(self):
        counter = self.counter(interval_seconds=60)
        with contextlib.redirect_stderr(io.StringIO()):
            for _ in range(50):
                counter.note("bad_signature")
            self.assertEqual(len(self.reported), 1)      # the first one, then silence
            self.clock[0] = 100.0
            counter.note("bad_signature")
        self.assertEqual(len(self.reported), 2)
        self.assertEqual(self.reported[1]["total"], 50)

    def test_flush_reports_what_is_left_and_nothing_twice(self):
        counter = self.counter(interval_seconds=1000)
        with contextlib.redirect_stderr(io.StringIO()):
            counter.note("expired")
            counter.note("expired")
            self.assertEqual(counter.flush()["expired"], 1)      # the first was reported at once
            self.assertIsNone(counter.flush())

    def test_a_failing_report_is_not_a_failing_call(self):
        counter = RefusedTokens(report=lambda counts: 1 / 0)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            counter.note("bad_signature")
        self.assertIn("could not report the refused-token count", err.getvalue())


class RefusedThroughTheGateway(Fixture):
    def test_the_gateway_counts_and_reports_them(self):
        sink = ListSink()
        tk = self.start(siem_config=SiemConfig(sinks=(sink,), refused_token_interval_seconds=1000))
        gateway = tk.gateway(tools={"search": lambda a: "ok"})
        before = tk.ledger.size()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for token in ("garbage", "tk1.e30.AAAA", None):
                self.assertFalse(gateway.invoke(token, "search", {"q": SECRET}).allowed)
        self.assertEqual(tk.ledger.size(), before, "an unverified token must not write to the ledger")
        counts = gateway.refused_token_counts()
        self.assertEqual(sum(counts.values()), 2)       # the first of the three was reported at once
        self.assertEqual(counts["malformed"], 1)
        for _ in range(40):
            if any(m.msgid == "gateway_token_refused" for m in sink.sent):
                break
            tk.delivery.drain(0.5)
        [reported] = [json.loads(m.body) for m in sink.sent if m.msgid == "gateway_token_refused"]
        self.assertEqual(reported["kind"], "gateway_token_refused")
        self.assertFalse(reported["ledgered"])
        self.assertEqual(reported["seq"], -1)
        self.assertNotIn(SECRET, sink.text)
        self.assertNotIn("tk1.e30.AAAA", sink.text)

    def test_close_waits_for_the_sender_s_last_pass(self):
        """A collector that takes a moment must not lose the tail: close waits for one pass over every sink,
        not for ``flush_seconds`` (live run 8x, C15)."""
        sink = ListSink(delay=1.0)
        tk = self.start(siem_config=SiemConfig(sinks=(sink,), flush_seconds=0.1,
                                               refused_token_interval_seconds=1000))
        self.exercise(tk)
        tk.close()
        seqs = sink.seqs()      # from the first entry this sink took through the last the ledger holds
        self.assertEqual(seqs, list(range(seqs[0], tk.ledger.size())))

    def test_close_reports_the_last_counts(self):
        sink = ListSink()
        tk = self.start(siem_config=SiemConfig(sinks=(sink,), refused_token_interval_seconds=1000))
        gateway = tk.gateway(tools={"search": lambda a: "ok"})
        with contextlib.redirect_stderr(io.StringIO()):
            gateway.invoke("garbage", "search", {"q": "x"})
            gateway.invoke("garbage", "search", {"q": "x"})
            tk.close()
        self.assertIsNone(tk.refused_tokens.flush())


class Observer(Fixture):
    def test_an_observer_that_raises_does_not_fail_the_append(self):
        ledger = self.ledger()
        ledger.observe(lambda seq: 1 / 0)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            entry = ledger.append("revocation", {"reason": "x"})
        self.assertEqual(entry.kind, "revocation")
        self.assertIn("ledger observer failed: ZeroDivisionError", err.getvalue())

    def test_notify_never_raises_when_the_queue_is_full(self):
        delivery = Delivery(SiemConfig(sinks=(ListSink(),), queue_max=1), self.ledger())
        for _ in range(10):
            delivery.notify(1)
        delivery.close()


if __name__ == "__main__":
    unittest.main()

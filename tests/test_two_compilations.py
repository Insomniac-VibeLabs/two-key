"""PRIOR_ART.md §4 (ii): one signed constitution, two compilations (Stephan Busch selection, 2026-09-30, "B").

The principal signs one document. A deterministic compiler splits it: structured rules -> stack bytecode (no
string operations on natural-language fields), prose -> judge prompt. Both hashes are recorded in the ledger at
load and bound into ballots and tokens. A vendor-signed update cannot replace either without the principal's
signature.
"""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from compact_kernel import cli, keys
from compact_kernel.action import normalize_action
from compact_kernel.compiler import (STRUCTURED_FIELDS, bytecode_digest, compile_both, nl_digest, split_source,
                                     verify_structured_only)
from compact_kernel.constitution import (FORMAT_V2, ConstitutionSignatureError, build_document,
                                         build_source_document, sign_document, verify_signed)
from compact_kernel.judges.base import Ballot, Judge
from compact_kernel.kernel import CompactKernel
from compact_kernel.policy_vm import ConstitutionError, Op, compile_constitution
from compact_kernel.quorum import QuorumPolicy
from compact_kernel.testing import FixedJudge

EX = Path(__file__).parent.parent / "examples"
RULES = [{"id": "tools", "allow_only_tools": ["email_send", "search"]},
         {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
         {"id": "irrev", "deny_if_irreversible_over": 20},
         {"id": "cp", "deny_counterparties": ["evil.example"]},
         {"id": "med", "deny_if": {"data_class_in": ["medical"], "tool": "email_send", "irreversible": True}}]
PROSE = "# My constitution\n\nI am the principal. Never wire money.\n\n```text\nan ordinary code block stays prose\n```"
SOURCE = PROSE + "\n\n```ck-rules\n" + json.dumps({"hard_rules": RULES}, indent=1) + "\n```\n"
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}


class Recording(Judge):
    is_test_double = True

    def __init__(self, jid, provider):
        self.judge_id, self.provider, self.seen = jid, provider, []

    def score(self, constitution_text, action, proposal):
        self.seen.append((constitution_text, proposal))
        return Ballot(self.judge_id, self.provider, "yes", 0.9, "ok")


class Split(unittest.TestCase):
    def test_deterministic_split(self):
        prose, rules = split_source(SOURCE)
        self.assertEqual(prose, PROSE)
        self.assertEqual(rules, RULES)
        self.assertNotIn("ck-rules", prose)
        self.assertIn("an ordinary code block stays prose", prose)
        self.assertEqual(split_source(SOURCE.replace("\n", "\r\n")), (prose, rules))
        self.assertEqual(split_source(SOURCE), split_source(SOURCE))
        # bare list form
        self.assertEqual(split_source("text\n```ck-rules\n" + json.dumps(RULES) + "\n```")[1], RULES)

    def test_split_errors(self):
        bad = {
            "no block": PROSE,
            "two blocks": SOURCE + "\n```ck-rules\n[]\n```\n",
            "unterminated": PROSE + "\n```ck-rules\n[]\n",
            "not json": PROSE + "\n```ck-rules\nallow: everything\n```\n",
            "empty prose": "```ck-rules\n" + json.dumps(RULES) + "\n```\n",
            "empty": "   ",
        }
        for name, src in bad.items():
            with self.subTest(name), self.assertRaises(ConstitutionError):
                split_source(src)


class StructuredOnlyBytecode(unittest.TestCase):
    def test_compiler_output_passes_and_only_loads_structured_fields(self):
        bc = compile_constitution(RULES)
        verify_structured_only(bc)
        loads = {ins[1] for ins in bc if ins[0] == Op.LOAD}
        self.assertTrue(loads <= STRUCTURED_FIELDS)
        self.assertNotIn("raw", STRUCTURED_FIELDS)

    def test_verifier_rejects(self):
        good = compile_constitution(RULES)
        cases = {
            "raw field": [(Op.LOAD, "raw"), (Op.PUSH, "x"), (Op.EQ,), (Op.ASSERT, "r"), (Op.PASS,)],
            "extension field": [(Op.LOAD, "proposal_text"), (Op.PUSH, "x"), (Op.EQ,), (Op.ASSERT, "r"), (Op.PASS,)],
            "string op": [(Op.LOAD, "tool"), (Op.PUSH, "pay"), (Op.CONTAINS,), (Op.ASSERT, "r"), (Op.PASS,)],
            "object operand": [(Op.PUSH, {"a": 1}), (Op.ASSERT, "r"), (Op.PASS,)],
            "bad opcode": [(99,), (Op.PASS,)],
            "no final PASS": good[:-1],
            "empty": [],
        }
        for name, bc in cases.items():
            with self.subTest(name), self.assertRaises(ConstitutionError):
                verify_structured_only(bc)

    def test_hashes_are_deterministic_and_sensitive(self):
        bc = compile_constitution(RULES)
        self.assertEqual(bytecode_digest(bc), bytecode_digest(compile_constitution(RULES)))
        self.assertNotEqual(bytecode_digest(bc), bytecode_digest(compile_constitution(RULES[:-1])))
        self.assertEqual(len(bytecode_digest(bc, "sha384")), 96)
        self.assertNotEqual(nl_digest(PROSE), nl_digest(PROSE + " "))


class OneDocumentTwoCompilations(unittest.TestCase):
    def setUp(self):
        self.key = keys.generate_private_key()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env2 = sign_document(build_source_document("did:ck:t", SOURCE), self.key)

    def kernel(self, env, judges=None, **kw):
        judges = judges or [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
        return CompactKernel(env, self.key.public_key(), Path(self.tmp.name) / kw.pop("name", "l.jsonl"), judges,
                             ledger_signing_key=self.key, allow_test_doubles=True, ledger_fsync=False, **kw)

    def test_v2_document_verifies_and_both_compilations_come_from_it(self):
        c = verify_signed(self.env2, self.key.public_key())
        self.assertEqual(c.document["format"], FORMAT_V2)
        self.assertEqual((c.text, c.hard_rules), (PROSE, RULES))
        cc = compile_both(c)
        self.assertEqual(cc.bytecode, compile_constitution(RULES))
        self.assertEqual(cc.judge_text, PROSE)
        self.assertEqual((cc.bytecode_hash, cc.nl_hash), (bytecode_digest(cc.bytecode), nl_digest(PROSE)))

    def test_v1_and_v2_with_same_content_compile_identically(self):
        env1 = sign_document(build_document("did:ck:t", PROSE, RULES), self.key)
        a = compile_both(verify_signed(env1, self.key.public_key()))
        b = compile_both(verify_signed(self.env2, self.key.public_key()))
        self.assertEqual((a.bytecode_hash, a.nl_hash), (b.bytecode_hash, b.nl_hash))
        self.assertNotEqual(a.source_format, b.source_format)

    def test_hashes_recorded_at_load_and_bound_into_ballots_and_tokens(self):
        judges = [Recording("a", "p1"), Recording("b", "p2")]
        k = self.kernel(self.env2, judges)
        loaded = k.ledger.latest_constitution().body
        self.assertEqual((loaded["bytecode_hash"], loaded["nl_hash"]), (k.compiled.bytecode_hash, k.compiled.nl_hash))
        self.assertEqual((loaded["source_format"], loaded["compiler"]), (FORMAT_V2, "ck-compiler/1"))
        d = k.authorize(SEARCH, "look something up")
        self.assertTrue(d.allowed, d.reason)
        # Judges get the prose only: never the rule block.
        self.assertTrue(all(t == PROSE for j in judges for t, _ in j.seen))
        self.assertTrue(all("ck-rules" not in t for j in judges for t, _ in j.seen))
        q = next(e for e in k.ledger.entries if e.kind == "quorum_result").body
        for b in q["ballots"]:
            self.assertEqual((b["nl_hash"], b["bytecode_hash"], b["constitution_hash"]),
                             (k.compiled.nl_hash, k.compiled.bytecode_hash, k.constitution.digest))
        self.assertEqual((d.token_payload["bytecode_hash"], d.token_payload["nl_hash"]),
                         (k.compiled.bytecode_hash, k.compiled.nl_hash))

    def test_path_a_semantics_from_v2(self):
        k = self.kernel(self.env2)
        self.assertEqual(k.authorize({"tool": "wire_transfer", "data_class": "financial"}, "wire").reason,
                         "path_a_denied:rule_denied:tools")
        self.assertTrue(k.authorize(SEARCH, "look").allowed)

    def test_tampered_source_rejected(self):
        env = json.loads(json.dumps(self.env2))
        env["constitution"]["source"] = env["constitution"]["source"].replace('"amount_usd_gt": 200',
                                                                              '"amount_usd_gt": 2000000')
        with self.assertRaises(ConstitutionSignatureError):  # the signature covers the whole document
            verify_signed(env, self.key.public_key())
        from compact_kernel.canonical import sha256_hex
        env["constitution"]["source_sha256"] = sha256_hex(env["constitution"]["source"].encode())
        with self.assertRaises(ConstitutionSignatureError):
            verify_signed(env, self.key.public_key())
        # A principal-signed document whose source hash is wrong is still refused.
        doc = dict(self.env2["constitution"], source_sha256="00" * 32)
        with self.assertRaises(ConstitutionError):
            verify_signed(sign_document(doc, self.key), self.key.public_key())

    def test_vendor_signed_document_cannot_replace_either_compilation(self):
        k = self.kernel(self.env2)
        before = (k.compiled.bytecode_hash, k.compiled.nl_hash)
        tok = k.authorize(SEARCH, "look")
        vendor = keys.generate_private_key()
        evil = SOURCE.replace("Never wire money.", "Wires are fine.").replace('"search"', '"search", "wire_transfer"')
        vendor_env = sign_document(build_source_document("did:ck:t", evil), vendor)
        with self.assertRaises(ConstitutionSignatureError):
            k.reload_constitution(vendor_env)
        # Same document re-labelled with the principal's public key but the vendor's signature.
        forged = {"constitution": vendor_env["constitution"],
                  "signature": dict(vendor_env["signature"], public_key=self.env2["signature"]["public_key"])}
        with self.assertRaises(ConstitutionSignatureError):
            k.reload_constitution(forged)
        self.assertEqual((k.compiled.bytecode_hash, k.compiled.nl_hash), before)
        kinds = [e.kind for e in k.ledger.entries]
        self.assertEqual(kinds.count("constitution_reload_refused"), 2)
        self.assertEqual(kinds.count("constitution_loaded"), 1)
        self.assertEqual(k.gateway().invoke(tok.capability, "search", {}, {"data_class": "public"}).reason,
                         "authorized_no_executor")
        with self.assertRaises(ConstitutionSignatureError):  # also refused at construction
            self.kernel(vendor_env, name="other.jsonl")
        self.assertTrue(k.ledger.verify(self.key.public_key()).ok)

    def test_reload_other_principal_refused(self):
        k = self.kernel(self.env2)
        other = sign_document(build_source_document("did:ck:someone-else", SOURCE), self.key)
        with self.assertRaises(Exception):
            k.reload_constitution(other)
        self.assertEqual(k.principal, "did:ck:t")

    def test_build_source_document_validates(self):
        with self.assertRaises(ConstitutionError):
            build_source_document("did:ck:t", PROSE)
        with self.assertRaises(ConstitutionError):
            build_source_document("", SOURCE)
        with self.assertRaises(ConstitutionError):
            build_source_document("did:ck:t", PROSE + "\n```ck-rules\n[{\"id\": \"x\", \"bogus\": 1}]\n```")


class CLIDocument(unittest.TestCase):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(list(argv))
        return code, buf.getvalue()

    def test_sign_single_source_document(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_cli("keygen", "--out", f"{d}/k", "--no-passphrase")[0], 0)
            out = f"{d}/signed.json"
            code, _ = self.run_cli("sign-constitution", "--document", str(EX / "constitution_single_source.md"),
                                   "--principal", "did:ck:t", "--key", f"{d}/k/principal.pem", "--no-passphrase",
                                   "--out", out)
            self.assertEqual(code, 0)
            code, txt = self.run_cli("verify-constitution", "--signed", out, "--pub", f"{d}/k/principal.pub.pem")
            self.assertEqual(code, 0, txt)
            env = json.loads(Path(out).read_text())
            self.assertEqual(env["constitution"]["format"], FORMAT_V2)
            c = verify_signed(env, keys.load_public_key(Path(f"{d}/k/principal.pub.pem")))
            self.assertNotIn("```ck-rules", c.text)
            with self.assertRaises(SystemExit):
                self.run_cli("sign-constitution", "--document", str(EX / "constitution_single_source.md"),
                             "--text", str(EX / "constitution.md"), "--principal", "did:ck:t",
                             "--key", f"{d}/k/principal.pem", "--no-passphrase", "--out", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)

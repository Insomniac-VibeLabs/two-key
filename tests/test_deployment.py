"""Deployment mode (personal / enterprise) and permissioned-ledger anchoring (CONCEPTION_NOTES Entry 9)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from two_key import deployment
from two_key.anchoring import (AnchorError, AnchorUnavailable, FabricAnchor, LocalFileAnchor, NullAnchor,
                               RestPermissionedAnchor, anchor_record, check_anchored_entries)
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.quorum import QuorumPolicy
from two_key.testing import FixedJudge
from helpers import TwoKeyFixture, enterprise_pki, signed

RULES = [{"id": "tools", "allow_only_tools": ["email_send"]}]
YES = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")]
QP = QuorumPolicy(required_yes=2)


class FakeFabricGateway:
    """An in-memory permissioned chain: one block per transaction, a world state that PutAnchor writes once."""

    def __init__(self, orgs=("Org1MSP", "Org2MSP"), fail=False):
        self.orgs, self.fail = list(orgs), fail
        self.blocks, self.state, self.txs = [], {}, {}

    def submit_transaction(self, channel, chaincode, function, args):
        if self.fail:
            raise ConnectionError("orderer unreachable")
        assert (channel, chaincode, function) == ("audit", "twokey-anchor", "PutAnchor")
        key, record_json = args
        code = "VALID"
        if key in self.state:
            code = "MVCC_READ_CONFLICT"            # write-once: an existing key is never overwritten
        else:
            self.state[key] = record_json
        tx_id = f"tx{len(self.blocks):04d}"
        self.blocks.append(tx_id)
        self.txs[tx_id] = {"tx_id": tx_id, "block_number": len(self.blocks) - 1, "validation_code": code,
                           "endorsing_orgs": list(self.orgs)}
        return dict(self.txs[tx_id])

    def evaluate_transaction(self, channel, chaincode, function, args):
        assert function == "GetAnchor"
        return self.state.get(args[0], "").encode()

    def get_transaction(self, channel, tx_id):
        return self.txs.get(tx_id)


def fabric(gw=None, **kw):
    return FabricAnchor(gw or FakeFabricGateway(), channel="audit", chaincode="twokey-anchor", **kw)


class Resolve(unittest.TestCase):
    def test_default_is_personal(self):
        c = deployment.resolve(env={})
        self.assertEqual((c.mode, c.source, c.is_enterprise, c.mode_defaults()), ("personal", "default", False, {}))

    def test_sources_and_validation(self):
        self.assertEqual(deployment.resolve("Enterprise", env={}).to_record(),
                         {"mode": "enterprise", "source": "argument"})
        self.assertEqual(deployment.resolve(env={"TWOKEY_DEPLOYMENT_MODE": "enterprise"}).source, "environment")
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (("c.json", '{"deployment_mode": "enterprise"}'),
                               ("c.yaml", "deployment_mode: enterprise\n")):
                p = Path(tmp) / name
                p.write_text(text)
                c = deployment.resolve(config_path=p, env={"TWOKEY_DEPLOYMENT_MODE": "enterprise"})
                self.assertEqual((c.mode, c.source), ("enterprise", f"environment+config:{p}"))
            with self.assertRaises(deployment.DeploymentConfigError):      # sources disagree
                deployment.resolve("personal", config_path=p, env={})
        for bad in ("corporate", "", 1):
            with self.assertRaises(deployment.DeploymentConfigError):
                deployment.resolve(bad, env={})
        with self.assertRaises(deployment.DeploymentConfigError):
            deployment.resolve(env={"TWOKEY_DEPLOYMENT_MODE": "public"})


class Cli(unittest.TestCase):
    def test_deployment_mode_command(self):
        import contextlib
        import io
        from two_key.cli import main
        out = io.StringIO()
        with mock.patch.dict("os.environ", {"TWOKEY_DEPLOYMENT_MODE": "enterprise"}), contextlib.redirect_stdout(out):
            self.assertEqual(main(["deployment-mode"]), 0)
            self.assertEqual(main(["deployment-mode", "--mode", "personal"]), 1)   # disagrees with the env
        self.assertIn("OK: deployment_mode=enterprise source=environment", out.getvalue())
        self.assertIn("INVALID: deployment_mode is set differently", out.getvalue())


class Modes(unittest.TestCase):
    def test_personal_default_is_unchanged_and_recorded(self):
        with mock.patch.dict("os.environ", {}, clear=False) as env:
            env.pop("TWOKEY_DEPLOYMENT_MODE", None)
            with TwoKeyFixture(RULES, YES, quorum_policy=QP) as tk:
                loaded = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][0].body
                self.assertEqual(loaded["deployment"], {"mode": "personal", "source": "default", "anchor": None})
                self.assertFalse(any(e.kind in ("anchored", "anchor_failed") for e in tk.ledger.entries))
                self.assertIsNone(tk.ledger.head_anchor)

    def test_enterprise_without_an_anchor_fails_at_startup(self):
        for kw in ({}, {"anchor": NullAnchor()}, {"anchor": LocalFileAnchor(Path("x"))}):
            with self.assertRaisesRegex(TwoKeyConfigError, "requires a permissioned-ledger anchor"):
                with TwoKeyFixture(RULES, YES, quorum_policy=QP, deployment_mode="enterprise", siem_host="127.0.0.1", **kw):
                    pass
        with mock.patch.dict("os.environ", {"TWOKEY_DEPLOYMENT_MODE": "enterprise"}):
            with self.assertRaises(TwoKeyConfigError):
                with TwoKeyFixture(RULES, YES, quorum_policy=QP):
                    pass

    def test_personal_refuses_a_permissioned_anchor(self):
        with self.assertRaisesRegex(TwoKeyConfigError, "keeps the ledger local"):
            with TwoKeyFixture(RULES, YES, quorum_policy=QP, deployment_mode="personal", anchor=fabric()):
                pass

    def test_enterprise_anchors_every_signed_head_with_verifiable_receipts(self):
        gw = FakeFabricGateway()
        anchor = fabric(gw, min_endorsing_orgs=2, required_orgs=["Org2MSP"])
        fx = TwoKeyFixture(RULES, YES, quorum_policy=QP, deployment_mode="enterprise", siem_host="127.0.0.1", anchor=anchor)
        with fx as tk:
            args = {"to": "a@example.com", "body": "hi"}
            d = tk.authorize({"tool": "email_send", "counterparty": "a@example.com", "data_class": "public",
                              "irreversible": False}, "Send it.", args)
            self.assertTrue(d.allowed, d.reason)
            gwy = tk.gateway(tools={"email_send": lambda **a: "sent"})
            self.assertEqual(gwy.invoke(d.capability, "email_send", args,
                                        {"counterparty": "a@example.com", "data_class": "public"}).reason, "executed")
            anchored = [e for e in tk.ledger.entries if e.kind == "anchored"]
            self.assertGreaterEqual(len(anchored), 3)       # startup, the decision, the gateway call
            r = anchored[0].body["receipt"]
            self.assertEqual((r["network"], r["validation_code"], r["endorsing_orgs"]),
                             ("hyperledger-fabric", "VALID", ["Org1MSP", "Org2MSP"]))
            self.assertEqual((r["tx_id"], r["block_number"]), ("tx0000", 0))
            self.assertEqual(r["record"]["head"], tk.ledger.entries[anchored[0].seq - 1].digest)
            self.assertEqual(r["record"]["digest_alg"], "sha384")
            self.assertTrue(tk.ledger.verify(fx.key.public_key()).ok)        # the head still covers everything
            checks = check_anchored_entries(tk.ledger, fx.key.public_key(), anchor)
            self.assertEqual({c.reason for c in checks}, {"ok"})
            self.assertEqual(len(checks), len(anchored))
            self.assertEqual({c.reason for c in check_anchored_entries(tk.ledger)}, {"ok_offline"})
            loaded = [e for e in tk.ledger.entries if e.kind == "constitution_loaded"][0].body["deployment"]
            self.assertEqual((loaded["mode"], loaded["anchor"]["network"]), ("enterprise", "hyperledger-fabric"))

    def test_mode_is_set_once_per_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            env, key = signed(RULES)
            path = Path(tmp) / "ledger.jsonl"
            TwoKey(env, key.public_key(), path, YES, ledger_signing_key=key, quorum_policy=QP,
                   allow_test_doubles=True)
            with self.assertRaisesRegex(TwoKeyConfigError, "set once"):
                TwoKey(env, key.public_key(), path, YES, ledger_signing_key=key, quorum_policy=QP,
                       allow_test_doubles=True, deployment_mode="enterprise", siem_host="127.0.0.1", anchor=fabric(),
                       **enterprise_pki(key)[0])
            TwoKey(env, key.public_key(), path, YES, ledger_signing_key=key, quorum_policy=QP,
                   allow_test_doubles=True, deployment_mode="personal")      # same mode reopens fine

    def test_anchor_failure_fails_startup_and_denies_a_decision(self):
        with self.assertRaises(AnchorError):
            with TwoKeyFixture(RULES, YES, quorum_policy=QP, deployment_mode="enterprise", siem_host="127.0.0.1",
                               anchor=fabric(FakeFabricGateway(fail=True))):
                pass
        gw = FakeFabricGateway()
        with TwoKeyFixture(RULES, YES, quorum_policy=QP, deployment_mode="enterprise", siem_host="127.0.0.1", anchor=fabric(gw)) as tk:
            gw.fail = True
            d = tk.authorize({"tool": "email_send", "counterparty": "a@example.com", "data_class": "public",
                              "irreversible": False}, "Send it.", {"to": "a@example.com"})
            self.assertEqual((d.allowed, d.reason), (False, "internal_error:ledger_checkpoint:AnchorError"))
            failed = [e for e in tk.ledger.entries if e.kind == "anchor_failed"][-1].body
            self.assertIn("orderer unreachable", failed["error"])
            self.assertTrue(tk.ledger.verify_chain())


class Receipts(unittest.TestCase):
    def head(self, size=3):
        return {"head": {"format": "x", "size": size, "head": "ab" * 32, "merkle_root": "cd" * 32,
                         "public_key": "pk", "signed_at": 1.0}, "sig": "s"}

    def test_receipt_verification_catches_tampering(self):
        a = fabric(min_endorsing_orgs=2)
        sh = self.head()
        r = a.publish(sh)
        self.assertTrue(a.verify_receipt(r, sh).ok)
        self.assertEqual(a.verify_receipt(r, self.head(4)).reason, "receipt_does_not_match_signed_head")
        self.assertEqual(a.verify_receipt({**r, "tx_id": "tx9999"}).reason, "not_found_on_chain")
        self.assertEqual(a.verify_receipt({**r, "block_number": 7}).reason, "chain_block_number_mismatch")
        self.assertEqual(a.verify_receipt({**r, "endorsing_orgs": ["Org1MSP", "Org9MSP"]}).reason,
                         "chain_endorsing_orgs_mismatch")
        forged = {**r, "record": {**r["record"], "merkle_root": "00" * 32}}
        self.assertEqual(a.verify_receipt(forged).reason, "chain_record_mismatch")
        self.assertEqual(a.verify_receipt({"tx_id": "x"}).reason, "malformed_receipt")

    def test_endorsement_policy(self):
        with self.assertRaisesRegex(AnchorError, "too_few_endorsing_orgs"):
            fabric(FakeFabricGateway(orgs=["Org1MSP"]), min_endorsing_orgs=2).publish(self.head())
        with self.assertRaisesRegex(AnchorError, "missing_endorsing_orgs:AuditorMSP"):
            fabric(required_orgs=["AuditorMSP"]).publish(self.head())
        with self.assertRaises(ValueError):
            fabric(min_endorsing_orgs=0)

    def test_write_once_key_and_invalid_tx_are_rejected(self):
        gw = FakeFabricGateway()
        a = fabric(gw)
        a.publish(self.head())
        with self.assertRaisesRegex(AnchorError, "transaction_not_valid:MVCC_READ_CONFLICT"):
            a.publish(self.head())       # same ledger and size: never overwritten

    def test_gateway_interface_and_optional_sdk(self):
        with self.assertRaises(TypeError):
            FabricAnchor(object(), channel="c", chaincode="cc")
        with mock.patch.dict(sys.modules, {"hfc": None, "hfc.fabric": None}):
            with self.assertRaisesRegex(AnchorUnavailable, "fabric-sdk-py"):
                FabricAnchor.from_fabric_sdk_py("net.json", org="o", user="u", peers=["p"], channel="c",
                                                chaincode="cc")

    def test_rest_adapter(self):
        chain = {}

        def transport(body, headers, timeout):
            self.assertEqual(headers["Content-Type"], "application/json")
            if body["op"] == "put":
                tx = {"tx_id": f"r{len(chain)}", "block_number": 40 + len(chain), "validation_code": "VALID",
                      "endorsing_orgs": ["BankA", "BankB"]}
                chain[body["key"]] = {**tx, "record": body["record"]}
                return tx
            return chain.get(body["key"])

        a = RestPermissionedAnchor(transport=transport, network="example-chain", min_endorsing_orgs=2)
        sh = self.head()
        r = a.publish(sh)
        self.assertEqual((r["network"], r["block_number"], r["endorsing_orgs"]), ("example-chain", 40,
                                                                                   ["BankA", "BankB"]))
        self.assertTrue(a.verify_receipt(r, sh).ok)
        with self.assertRaises(ValueError):
            RestPermissionedAnchor()

    def test_record_holds_digests_only(self):
        rec = anchor_record(self.head())
        self.assertEqual(set(rec), {"format", "digest_alg", "ledger_id", "size", "head", "merkle_root",
                                    "ledger_digest_alg", "signed_head_digest"})
        self.assertNotIn("pk", json.dumps(rec))                         # the key appears only as a digest
        with self.assertRaises(AnchorError):
            anchor_record({"nope": 1})


if __name__ == "__main__":
    unittest.main()

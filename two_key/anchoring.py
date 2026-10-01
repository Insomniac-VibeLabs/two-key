"""Ledger anchoring: publish signed ledger heads outside the local ledger.

Spec 5.6 says production "writes the root to a public log on a schedule".
The author (CONCEPTION_NOTES.md Entry 9, 2026-09-30) said a local ledger is fine
for personal use, and that for enterprise use "an enterprise level (not fully
public) blockchain would be the best". So there are two kinds of anchor:

- ``NullAnchor`` and ``LocalFileAnchor`` (personal use): nothing leaves the
  machine. ``LocalFileAnchor`` only appends to a local file.
- ``PermissionedLedgerAnchor`` (enterprise use): a vendor-neutral interface
  for a permissioned (not public) blockchain. Each signed ledger head is
  submitted as a transaction, and the receipt (transaction id, block number,
  endorsing organizations, and the head digest) can be verified later, both
  offline against the ledger and online against the chain.
  - ``FabricAnchor``: Hyperledger Fabric, through a small gateway interface
    (see the class). ``FabricAnchor.from_fabric_sdk_py`` uses the optional,
    unofficial ``fabric-sdk-py`` package (``hfc``) and raises
    ``AnchorUnavailable`` without it.
  - ``RestPermissionedAnchor``: any permissioned chain behind a JSON REST API.

Non-repudiation from a permissioned chain holds only if its nodes (and the
endorsing organizations) are run by parties who are not all under one
administrator. ``min_endorsing_orgs`` and ``required_orgs`` let a deployment
require that; the defaults are placeholders pending a maintainer decision
(docs/DEPLOYMENT_MODES.md).

Nothing here is tested against a live network: the Fabric adapter is tested
with a fake gateway, and the REST adapter with a fake transport.
"""

from __future__ import annotations

import abc
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .canonical import canonical_bytes, digest_hex
from .crypto.provider import CryptoProvider, default_provider

ANCHOR_FORMAT = "two-key-anchor/1"
ANCHOR_DIGEST_ALG = "sha384"   # FIPS-approved hash with a quantum margin, through the crypto provider
VALID = "VALID"


class AnchorError(RuntimeError):
    """Publishing to, or verifying against, an anchor failed."""


class AnchorUnavailable(AnchorError):
    """An optional anchoring dependency (for example fabric-sdk-py) is not installed."""


class Anchor(abc.ABC):
    kind = "local"           # "local" (personal use) or "permissioned" (enterprise use)

    @abc.abstractmethod
    def publish(self, signed_head: dict) -> dict:
        """Publish a signed ledger head. Return a receipt (JSON-serializable)."""

    def describe(self) -> dict:
        return {"anchor": type(self).__name__, "kind": self.kind}


class NullAnchor(Anchor):
    def publish(self, signed_head: dict) -> dict:
        return {"anchor": "null", "published": False, "note": "no anchoring configured"}


class LocalFileAnchor(Anchor):
    """Appends signed heads to a local file. NOT a public transparency log."""

    def __init__(self, path: Path):
        self.path = Path(path)

    def publish(self, signed_head: dict) -> dict:
        rec = {"anchored_at": time.time(), "signed_head": signed_head}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        # PersonalLedger.signed_head() is {"head": {"size": ..., ...}, "sig": ...}: the size is one level down.
        head = signed_head.get("head")
        size = head.get("size") if isinstance(head, dict) else signed_head.get("size")
        return {"anchor": "local-file", "published": False, "path": str(self.path),
                "size": size, "note": "local stub, not public"}

    def describe(self) -> dict:
        return {**super().describe(), "path": str(self.path)}


# ---------------------------------------------------------------------------
# Permissioned (enterprise) anchoring
# ---------------------------------------------------------------------------
def anchor_record(signed_head: Mapping[str, Any], crypto: CryptoProvider | None = None) -> dict:
    """What is written to the chain for one signed head: no ledger content, only digests."""
    head = signed_head.get("head") if isinstance(signed_head, Mapping) else None
    if not isinstance(head, Mapping) or not isinstance(head.get("size"), int):
        raise AnchorError("not a signed ledger head")
    crypto = crypto or default_provider()
    return {"format": ANCHOR_FORMAT, "digest_alg": ANCHOR_DIGEST_ALG,
            "ledger_id": digest_hex(str(head.get("public_key", "")).encode("utf-8"), ANCHOR_DIGEST_ALG, crypto),
            "size": head["size"], "head": head.get("head"), "merkle_root": head.get("merkle_root"),
            "ledger_digest_alg": head.get("digest_alg", "sha256"),
            "signed_head_digest": digest_hex(canonical_bytes(dict(signed_head)), ANCHOR_DIGEST_ALG, crypto)}


def anchor_key(record: Mapping[str, Any]) -> str:
    return f"{record['ledger_id']}:{record['size']}"


@dataclass(frozen=True)
class AnchorCheck:
    ok: bool
    reason: str
    details: dict = field(default_factory=dict)


class PermissionedLedgerAnchor(Anchor):
    """Vendor-neutral anchor for a permissioned blockchain (enterprise mode).

    Subclasses implement ``_submit(key, record)`` and ``_lookup(receipt)``. Both
    return a mapping with ``tx_id``, ``block_number``, ``validation_code`` and
    ``endorsing_orgs``; ``_lookup`` also returns the ``record`` stored on the
    chain under the key.

    A receipt is accepted only if the transaction is ``VALID`` and endorsed by
    at least ``min_endorsing_orgs`` distinct organizations, including every
    org in ``required_orgs``. Both are PLACEHOLDER defaults (1 and none)
    pending a maintainer decision; a real deployment should require organizations that are
    not all under one administrator.
    """
    kind = "permissioned"
    network = "permissioned"

    def __init__(self, *, min_endorsing_orgs: int = 1, required_orgs: Sequence[str] = (),
                 crypto: CryptoProvider | None = None):
        if isinstance(min_endorsing_orgs, bool) or not isinstance(min_endorsing_orgs, int) or min_endorsing_orgs < 1:
            raise ValueError("min_endorsing_orgs must be an integer >= 1")
        self.min_endorsing_orgs = min_endorsing_orgs
        self.required_orgs = tuple(sorted(set(required_orgs)))
        self.crypto = crypto or default_provider()

    @abc.abstractmethod
    def _submit(self, key: str, record: dict) -> Mapping[str, Any]:
        ...

    @abc.abstractmethod
    def _lookup(self, receipt: Mapping[str, Any]) -> Mapping[str, Any] | None:
        ...

    def describe(self) -> dict:
        return {**super().describe(), "network": self.network, "min_endorsing_orgs": self.min_endorsing_orgs,
                "required_orgs": list(self.required_orgs)}

    def _policy(self, orgs: Sequence[str]) -> str | None:
        distinct = set(orgs)
        if len(distinct) < self.min_endorsing_orgs:
            return f"too_few_endorsing_orgs:{len(distinct)}<{self.min_endorsing_orgs}"
        missing = [o for o in self.required_orgs if o not in distinct]
        return f"missing_endorsing_orgs:{','.join(missing)}" if missing else None

    def publish(self, signed_head: dict) -> dict:
        record = anchor_record(signed_head, self.crypto)
        key = anchor_key(record)
        try:
            tx = dict(self._submit(key, record))
        except AnchorError:
            raise
        except Exception as e:  # noqa: BLE001 - any transport failure is an anchoring failure
            raise AnchorError(f"submit failed: {type(e).__name__}: {e}"[:300]) from None
        receipt = {"anchor": type(self).__name__, "network": self.network, "published": True, "key": key,
                   "tx_id": tx.get("tx_id"), "block_number": tx.get("block_number"),
                   "validation_code": tx.get("validation_code"),
                   "endorsing_orgs": sorted({str(o) for o in tx.get("endorsing_orgs") or ()}),
                   "record": record, "submitted_at": time.time()}
        bad = self._shape(receipt)
        if bad:
            raise AnchorError(f"anchor receipt rejected: {bad}")
        return receipt

    def _shape(self, receipt: Mapping[str, Any]) -> str | None:
        if not isinstance(receipt.get("tx_id"), str) or not receipt["tx_id"]:
            return "missing_tx_id"
        b = receipt.get("block_number")
        if isinstance(b, bool) or not isinstance(b, int) or b < 0:
            return "missing_block_number"
        if receipt.get("validation_code") != VALID:
            return f"transaction_not_valid:{receipt.get('validation_code')}"
        orgs = receipt.get("endorsing_orgs")
        if not isinstance(orgs, list) or not all(isinstance(o, str) for o in orgs):
            return "missing_endorsing_orgs"
        return self._policy(orgs)

    def verify_receipt(self, receipt: Mapping[str, Any], signed_head: Mapping[str, Any] | None = None) -> AnchorCheck:
        """Check a receipt: its shape and endorsement policy, that it matches ``signed_head`` (if given), and
        that the chain holds the same transaction (id, block, VALID, endorsers) and record."""
        if not isinstance(receipt, Mapping) or not isinstance(receipt.get("record"), Mapping):
            return AnchorCheck(False, "malformed_receipt")
        bad = self._shape(receipt)
        if bad:
            return AnchorCheck(False, bad)
        if signed_head is not None:
            try:
                if anchor_record(signed_head, self.crypto) != dict(receipt["record"]):
                    return AnchorCheck(False, "receipt_does_not_match_signed_head")
            except AnchorError:
                return AnchorCheck(False, "malformed_signed_head")
        if receipt.get("key") != anchor_key(receipt["record"]):
            return AnchorCheck(False, "key_mismatch")
        try:
            onchain = self._lookup(receipt)
        except Exception as e:  # noqa: BLE001
            return AnchorCheck(False, f"lookup_failed:{type(e).__name__}")
        if not onchain:
            return AnchorCheck(False, "not_found_on_chain")
        for k in ("tx_id", "block_number", "validation_code"):
            if onchain.get(k) != receipt.get(k):
                return AnchorCheck(False, f"chain_{k}_mismatch")
        if sorted({str(o) for o in onchain.get("endorsing_orgs") or ()}) != list(receipt["endorsing_orgs"]):
            return AnchorCheck(False, "chain_endorsing_orgs_mismatch")
        if dict(onchain.get("record") or {}) != dict(receipt["record"]):
            return AnchorCheck(False, "chain_record_mismatch")
        return AnchorCheck(True, "ok", {"tx_id": receipt["tx_id"], "block_number": receipt["block_number"],
                                        "endorsing_orgs": list(receipt["endorsing_orgs"])})


class FabricAnchor(PermissionedLedgerAnchor):
    """Hyperledger Fabric anchor.

    ``gateway`` is any object with these three methods (a thin bridge to a
    Fabric client):

    - ``submit_transaction(channel, chaincode, function, args) -> mapping``
      with ``tx_id``, ``block_number``, ``validation_code``, and
      ``endorsing_orgs`` (MSP ids), after the transaction is committed;
    - ``evaluate_transaction(channel, chaincode, function, args) -> bytes | str``;
    - ``get_transaction(channel, tx_id) -> mapping`` with ``tx_id``,
      ``block_number``, ``validation_code``, and ``endorsing_orgs`` (for
      example from the ``qscc`` system chaincode).

    The chaincode is expected to offer ``PutAnchor(key, record_json)``, which
    stores the record under the key once (refusing to overwrite), and
    ``GetAnchor(key) -> record_json``. The official Fabric Gateway client APIs
    are Go, Node, and Java; from Python, use ``from_fabric_sdk_py`` (optional,
    unofficial SDK) or a bridge of your own.
    """
    network = "hyperledger-fabric"

    def __init__(self, gateway: Any, *, channel: str, chaincode: str, put_function: str = "PutAnchor",
                 get_function: str = "GetAnchor", **kw: Any):
        super().__init__(**kw)
        for m in ("submit_transaction", "evaluate_transaction", "get_transaction"):
            if not callable(getattr(gateway, m, None)):
                raise TypeError(f"gateway must provide {m}()")
        if not channel or not chaincode:
            raise ValueError("channel and chaincode are required")
        self.gateway, self.channel, self.chaincode = gateway, channel, chaincode
        self.put_function, self.get_function = put_function, get_function

    def describe(self) -> dict:
        return {**super().describe(), "channel": self.channel, "chaincode": self.chaincode}

    def _submit(self, key: str, record: dict) -> Mapping[str, Any]:
        return self.gateway.submit_transaction(self.channel, self.chaincode, self.put_function,
                                               [key, canonical_bytes(record).decode("ascii")])

    def _lookup(self, receipt: Mapping[str, Any]) -> Mapping[str, Any] | None:
        tx = self.gateway.get_transaction(self.channel, receipt["tx_id"])
        if not tx:
            return None
        raw = self.gateway.evaluate_transaction(self.channel, self.chaincode, self.get_function, [receipt["key"]])
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return {**dict(tx), "record": json.loads(raw) if raw else None}

    @classmethod
    def from_fabric_sdk_py(cls, net_profile: str, *, org: str, user: str, peers: Sequence[str], channel: str,
                           chaincode: str, **kw: Any) -> "FabricAnchor":
        """Build the gateway from the optional, unofficial ``fabric-sdk-py`` (``hfc``) package.

        Raises AnchorUnavailable if it is not installed. NOT tested against a live network.
        """
        try:
            from hfc.fabric import Client  # type: ignore[import-not-found]
        except ImportError:
            raise AnchorUnavailable("Hyperledger Fabric anchoring from Python needs the optional fabric-sdk-py "
                                    "package (import name hfc), or pass your own gateway to FabricAnchor") from None
        return cls(_HfcGateway(Client(net_profile=net_profile), org, user, list(peers)),
                   channel=channel, chaincode=chaincode, **kw)


class _HfcGateway:  # pragma: no cover - needs fabric-sdk-py and a network; untested
    """Bridge from fabric-sdk-py to the FabricAnchor gateway interface (best effort, untested)."""

    def __init__(self, client: Any, org: str, user: str, peers: list):
        self.client, self.peers = client, peers
        self.user = client.get_user(org, user)

    def _run(self, coro: Any) -> Any:
        import asyncio
        return asyncio.run(coro)

    def submit_transaction(self, channel, chaincode, function, args):
        self.client.new_channel(channel)
        out = self._run(self.client.chaincode_invoke(requestor=self.user, channel_name=channel, peers=self.peers,
                                                     args=list(args), cc_name=chaincode, fcn=function,
                                                     wait_for_event=True))
        tx_id = json.loads(out)["tx_id"] if isinstance(out, (str, bytes)) else out["tx_id"]  # PutAnchor returns it
        return self.get_transaction(channel, tx_id)

    def evaluate_transaction(self, channel, chaincode, function, args):
        return self._run(self.client.chaincode_query(requestor=self.user, channel_name=channel, peers=self.peers,
                                                     args=list(args), cc_name=chaincode, fcn=function))

    def get_transaction(self, channel, tx_id):
        tx = self._run(self.client.query_transaction(requestor=self.user, channel_name=channel, peers=self.peers,
                                                     tx_id=tx_id, decode=True))
        block = self._run(self.client.query_block_by_txid(requestor=self.user, channel_name=channel,
                                                          peers=self.peers, tx_id=tx_id, decode=True))
        acts = tx["transaction_envelope"]["payload"]["data"]["actions"]
        orgs = sorted({e["endorser"]["Mspid"] for a in acts for e in a["payload"]["action"]["endorsements"]})
        code = tx.get("validation_code")
        return {"tx_id": tx_id, "block_number": int(block["header"]["number"]),
                "validation_code": VALID if code in (0, VALID) else str(code), "endorsing_orgs": orgs}


class RestPermissionedAnchor(PermissionedLedgerAnchor):
    """Any permissioned chain behind a JSON REST API (for example a vendor's or a FireFly-style gateway).

    ``transport(body, headers, timeout) -> response`` (default: HTTPS JSON POST, loopback HTTP allowed).
    Submit: POST ``{"op": "put", "key", "record"}`` to ``submit_url``. Lookup: POST ``{"op": "get", "key",
    "tx_id"}`` to ``lookup_url`` (default: the same URL). Both answer with ``tx_id``, ``block_number``,
    ``validation_code``, ``endorsing_orgs``; lookup also with ``record``.
    """
    network = "rest"

    def __init__(self, submit_url: str | None = None, *, lookup_url: str | None = None,
                 transport: Callable[[dict, dict, float], Any] | None = None,
                 lookup_transport: Callable[[dict, dict, float], Any] | None = None,
                 credential: Any = None, timeout: float = 30.0, network: str = "rest", **kw: Any):
        super().__init__(**kw)
        if transport is None:
            if not submit_url:
                raise ValueError("submit_url or transport is required")
            from .scanning import http_json_transport
            transport = http_json_transport(submit_url)
            lookup_transport = lookup_transport or http_json_transport(lookup_url or submit_url)
        self.transport, self.lookup_transport = transport, lookup_transport or transport
        self.credential, self.timeout, self.network = credential, float(timeout), network
        self.submit_url, self.lookup_url = submit_url, lookup_url or submit_url

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.credential is not None:
            h["Authorization"] = f"Bearer {self.credential.get_token()}"
        return h

    def describe(self) -> dict:
        return {**super().describe(), "submit_url": self.submit_url}

    def _submit(self, key: str, record: dict) -> Mapping[str, Any]:
        r = self.transport({"op": "put", "key": key, "record": record}, self._headers(), self.timeout)
        if not isinstance(r, Mapping):
            raise AnchorError("anchor service answered with something other than a JSON object")
        return r

    def _lookup(self, receipt: Mapping[str, Any]) -> Mapping[str, Any] | None:
        r = self.lookup_transport({"op": "get", "key": receipt["key"], "tx_id": receipt["tx_id"]},
                                  self._headers(), self.timeout)
        return r if isinstance(r, Mapping) else None


def check_anchored_entries(ledger: Any, trusted_key: Any = None, anchor: PermissionedLedgerAnchor | None = None
                           ) -> list[AnchorCheck]:
    """Verify every permissioned ``anchored`` entry in ``ledger`` offline, and online if ``anchor`` is given.

    Offline: the entry's signed head covers exactly the entries before it (size, chain head, Merkle root),
    its signature verifies under ``trusted_key`` (if given), and the receipt's record matches it.
    """
    from .crypto.signatures import as_public_keyset
    out = []
    keyset = as_public_keyset(trusted_key, ledger.crypto) if trusted_key is not None else None
    for e in ledger.entries:
        if e.kind != "anchored" or not isinstance(e.body.get("receipt"), Mapping) \
                or e.body["receipt"].get("published") is not True:
            continue
        sh, receipt = e.body.get("signed_head"), e.body["receipt"]
        head = sh.get("head") if isinstance(sh, Mapping) else None
        if not isinstance(head, Mapping):
            out.append(AnchorCheck(False, "missing_signed_head", {"seq": e.seq}))
            continue
        n = head.get("size")
        if n != e.seq or head.get("head") != ledger.entries[n - 1].digest \
                or head.get("merkle_root") != ledger.root_bytes(n).hex():
            out.append(AnchorCheck(False, "signed_head_does_not_cover_prior_entries", {"seq": e.seq}))
            continue
        if keyset is not None and (head.get("public_key") != keyset.encoded
                                   or not keyset.verify(canonical_bytes(dict(head)), sh.get("sig"))):
            out.append(AnchorCheck(False, "signed_head_signature_invalid", {"seq": e.seq}))
            continue
        if anchor_record(sh, ledger.crypto) != dict(receipt.get("record") or {}):
            out.append(AnchorCheck(False, "receipt_does_not_match_signed_head", {"seq": e.seq}))
            continue
        if anchor is not None:
            c = anchor.verify_receipt(receipt, sh)
            out.append(AnchorCheck(c.ok, c.reason, {"seq": e.seq, **c.details}))
        else:
            out.append(AnchorCheck(True, "ok_offline", {"seq": e.seq, "tx_id": receipt.get("tx_id")}))
    return out

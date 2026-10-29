# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The test vectors in docs/TOOL_CHECK.md: hybrid keys from fixed seeds, a token, a stamp and a receipt. The keys,
hashes and bodies are made again here and must match byte for byte. ML-DSA-65 signs with fresh randomness, so the
signatures differ each time they are made: the published ones must verify instead, and the published token and
stamp must pass the tool's checks. After a format change:

    python tests/test_toolcheck_vectors.py --write
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey  # noqa: E402

from two_key.capability import _b64u  # noqa: E402
from two_key.canonical import canonical_bytes  # noqa: E402
from two_key.keys import HybridPrivateKey, public_raw, sign  # noqa: E402
from two_key.toolcheck import (META_KEY, StampSigner, ToolCheckConfig, ToolChecker, ToolCheckError,  # noqa: E402
                               key_fingerprint, result_hash, tool_args_hash, verify_receipt)

DOC = ROOT / "docs" / "TOOL_CHECK.md"
START, END = "<!-- vectors -->", "<!-- /vectors -->"
IAT = 1_800_000_000


def parts(signed: str) -> dict:
    """A signed object as its three parts. On the wire they are joined with dots; written whole, a token's
    ``<prefix>.eyJ...`` shape reads to secret scanners as a JWT, though these are made from public seeds."""
    prefix, body, signature = signed.split(".")
    return {"prefix": prefix, "body": body, "signature": signature}


def seeded(n: int) -> HybridPrivateKey:
    """The hybrid key from seeds: Ed25519 from 32 bytes of ``n``, ML-DSA-65 from 32 bytes of ``n + 0x10``."""
    return HybridPrivateKey(Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32),
                            MLDSA65PrivateKey.from_seed_bytes(bytes([n + 0x10]) * 32))


def joined(signed: dict) -> str:
    return ".".join((signed["prefix"], signed["body"], signed["signature"]))


def vectors(doc: dict | None = None) -> tuple[dict, dict]:
    """The vectors, and the token, stamp and receipt made here. Given the published vectors (``doc``), their token,
    stamp and receipt are the ones checked and returned, so the bodies made here from them can be compared."""
    capability, stamp_key, tool_key = (seeded(n) for n in (1, 2, 3))
    arguments = {"amount": 12.5, "vendor": "ada"}
    payload = {"v": 2, "alg": "ed25519+ml-dsa-65", "jti": "0123456789abcdef0123456789abcdef",
               "tool": "pay_vendor", "args_hash": "sha256:" + "0" * 64, "ledger_root": "0" * 64, "ledger_size": 7,
               "bytecode_hash": "0" * 64, "nl_hash": "0" * 64, "spec_hash": "0" * 64, "iat": IAT, "exp": IAT + 120,
               "tool_args_hash": tool_args_hash(arguments)}
    body = _b64u(canonical_bytes(payload))
    made = {"token": f"tk2.{body}.{sign(capability, body.encode('ascii'))}"}
    token = joined(doc["token"]) if doc else made["token"]
    made["stamp"] = StampSigner(stamp_key, clock=lambda: IAT + 1).stamp(token, payload, 8)
    stamp = joined(doc["stamp"]) if doc else made["stamp"]
    result = {"content": [{"type": "text", "text": "paid"}], "isError": False}
    with tempfile.TemporaryDirectory() as tmp:
        checker = ToolChecker(ToolCheckConfig("pay_vendor", capability.public_key(), stamp_key.public_key(),
                                              tool_key, Path(tmp, "seen.sqlite")), clock=lambda: IAT + 2)
        call = checker.check(arguments, {META_KEY: {"token": token, "stamp": stamp}})
        made["receipt"] = checker.receipt(call, result)
    receipt = joined(doc["receipt"]) if doc else made["receipt"]
    verify_receipt(receipt, pinned=key_fingerprint(tool_key.public_key()), jti=payload["jti"], tool="pay_vendor",
                   stamp=stamp, result=result_hash(result))
    return {
        "capability_public_key": public_raw(capability.public_key()),
        "capability_key_fingerprint": key_fingerprint(capability.public_key()),
        "stamp_public_key": public_raw(stamp_key.public_key()),
        "stamp_key_fingerprint": key_fingerprint(stamp_key.public_key()),
        "tool_public_key": public_raw(tool_key.public_key()),
        "tool_key_fingerprint": key_fingerprint(tool_key.public_key()),
        "arguments": arguments,
        "tool_args_hash": payload["tool_args_hash"],
        "token": parts(token),
        "stamp": parts(stamp),
        "result": result,
        "result_hash": result_hash(result),
        "receipt": parts(receipt),
        "checked_at": IAT + 2,
    }, made


def block(found: dict) -> str:
    return f"{START}\n```json\n{json.dumps(found, indent=2)}\n```\n{END}"


def current() -> str:
    text = DOC.read_text(encoding="utf-8")
    return text[text.index(START):text.index(END) + len(END)]


def published() -> dict:
    return json.loads(current()[len(START):-len(END)].strip().removeprefix("```json").removesuffix("```"))


class Vectors(unittest.TestCase):
    def test_the_doc_holds_the_vectors_this_code_makes(self):
        doc = published()
        found, made = vectors(doc)     # raises if a published signature fails to verify or a check refuses
        self.assertEqual(current(), block(found), "run python tests/test_toolcheck_vectors.py --write")
        for name in ("token", "stamp", "receipt"):
            self.assertEqual(parts(made[name])["body"], doc[name]["body"], name)
            self.assertEqual(parts(made[name])["prefix"], doc[name]["prefix"], name)

    def test_a_changed_signature_fails(self):
        doc = published()
        for name, refusal in (("token", "^token_invalid$"), ("stamp", "^stamp_invalid$"),
                              ("receipt", "^bad_signature$")):
            signature = doc[name]["signature"]
            other = ("B" if signature[0] == "A" else "A") + signature[1:]
            changed = dict(doc, **{name: dict(doc[name], signature=other)})
            with self.assertRaisesRegex(ToolCheckError, refusal, msg=name):
                vectors(changed)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        page = DOC.read_text(encoding="utf-8")
        DOC.write_text(page.replace(current(), block(vectors()[0])), encoding="utf-8")
        print(f"wrote {DOC.relative_to(ROOT)}")
    else:
        unittest.main()

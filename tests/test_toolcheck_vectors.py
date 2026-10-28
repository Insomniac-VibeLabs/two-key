# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The test vectors in docs/TOOL_CHECK.md: keys from fixed seeds, a token, a stamp and a receipt, made again
here. Ed25519 signatures are deterministic, so the block must match byte for byte. After a format change:

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

from two_key.capability import _b64u  # noqa: E402
from two_key.canonical import canonical_bytes  # noqa: E402
from two_key.keys import public_raw, sign  # noqa: E402
from two_key.toolcheck import (META_KEY, StampSigner, ToolCheckConfig, ToolChecker, key_fingerprint,  # noqa: E402
                               result_hash, tool_args_hash, verify_receipt)

DOC = ROOT / "docs" / "TOOL_CHECK.md"
START, END = "<!-- vectors -->", "<!-- /vectors -->"
IAT = 1_800_000_000


def parts(signed: str) -> dict:
    """A signed object as its three parts. On the wire they are joined with dots; written whole, a token's
    ``<prefix>.eyJ...`` shape reads to secret scanners as a JWT, though these are made from public seeds."""
    prefix, body, signature = signed.split(".")
    return {"prefix": prefix, "body": body, "signature": signature}


def vectors() -> dict:
    capability, stamp_key, tool_key = (Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (1, 2, 3))
    arguments = {"amount": 12.5, "vendor": "ada"}
    payload = {"v": 1, "jti": "0123456789abcdef0123456789abcdef", "tool": "pay_vendor",
               "args_hash": "sha256:" + "0" * 64, "ledger_root": "0" * 64, "ledger_size": 7,
               "bytecode_hash": "0" * 64, "nl_hash": "0" * 64, "spec_hash": "0" * 64, "iat": IAT, "exp": IAT + 120,
               "tool_args_hash": tool_args_hash(arguments)}
    body = _b64u(canonical_bytes(payload))
    token = f"tk1.{body}.{sign(capability, body.encode('ascii'))}"
    stamp = StampSigner(stamp_key, clock=lambda: IAT + 1).stamp(token, payload, 8)
    result = {"content": [{"type": "text", "text": "paid"}], "isError": False}
    with tempfile.TemporaryDirectory() as tmp:
        checker = ToolChecker(ToolCheckConfig("pay_vendor", capability.public_key(), stamp_key.public_key(),
                                              tool_key, Path(tmp, "seen.sqlite")), clock=lambda: IAT + 2)
        call = checker.check(arguments, {META_KEY: {"token": token, "stamp": stamp}})
        receipt = checker.receipt(call, result)
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
    }


def block() -> str:
    return f"{START}\n```json\n{json.dumps(vectors(), indent=2)}\n```\n{END}"


def current() -> str:
    text = DOC.read_text(encoding="utf-8")
    return text[text.index(START):text.index(END) + len(END)]


class Vectors(unittest.TestCase):
    def test_the_doc_holds_the_vectors_this_code_makes(self):
        self.assertEqual(current(), block(), "run python tests/test_toolcheck_vectors.py --write")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        page = DOC.read_text(encoding="utf-8")
        DOC.write_text(page.replace(current(), block()), encoding="utf-8")
        print(f"wrote {DOC.relative_to(ROOT)}")
    else:
        unittest.main()

"""Ledger at rest: AES-256-GCM records and a wrapped data key.

The data key is wrapped by a ledger key that lives outside the ledger
directory. It is never derived from the principal key. A missing or wrong
key fails closed. A non-exportable principal passes ``ledger_key`` explicitly.
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

WRAP_FORMAT = "two-key-ledger-wrap/1"
RECORD_FORMAT = "two-key-ledger-enc/1"
_WRAP_INFO = b"two-key-ledger-wrap/1"
_RECORD_AAD = b"two-key-ledger-enc/1"


class LedgerCryptoError(RuntimeError):
    pass


def wrap_data_key(kek: bytes, data_key: bytes) -> dict:
    nonce = os.urandom(12)
    return {"format": WRAP_FORMAT, "nonce": nonce.hex(),
            "wrapped": AESGCM(kek).encrypt(nonce, data_key, _WRAP_INFO).hex()}


def unwrap_data_key(kek: bytes, blob: dict) -> bytes:
    if not isinstance(blob, dict) or blob.get("format") != WRAP_FORMAT:
        raise LedgerCryptoError("ledger key file is not a Two-Key wrapped data key")
    try:
        return AESGCM(kek).decrypt(bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["wrapped"]), _WRAP_INFO)
    except Exception as e:
        raise LedgerCryptoError("ledger data key rejected (wrong ledger key)") from e


def seal(data_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), _RECORD_AAD)
    return json.dumps({"enc": RECORD_FORMAT, "n": nonce.hex(), "c": ct.hex()}, separators=(",", ":"))


def open_record(data_key: bytes, line: str) -> str:
    try:
        rec = json.loads(line)
        if not isinstance(rec, dict) or rec.get("enc") != RECORD_FORMAT:
            raise LedgerCryptoError("ledger record is not encrypted")
        pt = AESGCM(data_key).decrypt(bytes.fromhex(rec["n"]), bytes.fromhex(rec["c"]), _RECORD_AAD)
    except LedgerCryptoError:
        raise
    except Exception as e:
        raise LedgerCryptoError("ledger record failed to decrypt") from e
    return pt.decode("utf-8")

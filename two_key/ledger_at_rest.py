"""Ledger at rest: AES-256-GCM records, data key wrapped by the principal key.

The hash chain is over the plaintext entry. The file holds ciphertext only.
A missing or wrong principal key fails closed. A non-exportable key (a PKCS#11
key) cannot wrap the data key; pass ledger_key explicitly or this fails closed.
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

WRAP_FORMAT = "two-key-ledger-wrap/1"
RECORD_FORMAT = "two-key-ledger-enc/1"
_WRAP_INFO = b"two-key-ledger-wrap/1"
_RECORD_AAD = b"two-key-ledger-enc/1"


class LedgerCryptoError(RuntimeError):
    pass


def wrap_key_from_principal(signing_key) -> bytes:
    """32-byte key-encryption key from the principal's exportable private material."""
    privs = getattr(signing_key, "_privs", None)
    if privs and any(getattr(p, "external", False) for p in privs):
        raise LedgerCryptoError("principal key is not exportable; pass ledger_key to open the encrypted ledger")
    export = getattr(signing_key, "export_components", None)
    if not callable(export):
        raise LedgerCryptoError("principal key cannot wrap the ledger data key")
    material = json.dumps({"suite": signing_key.suite, "components": export()},
                          sort_keys=True, separators=(",", ":")).encode()
    return HKDF(SHA384(), 32, salt=b"two-key-ledger", info=_WRAP_INFO).derive(material)


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
        raise LedgerCryptoError("ledger data key rejected (wrong principal key)") from e


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

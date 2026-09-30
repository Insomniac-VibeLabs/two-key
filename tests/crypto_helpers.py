"""Helpers for crypto tests: a FAKE liboqs module and signature tampering utilities.

FakeOqs is NOT ML-DSA and NOT secure. It only mimics the liboqs-python API
(oqs.Signature, get_enabled_sig_mechanisms) so the liboqs adapter, backend
selection, and missing-library paths can be tested without liboqs installed.
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import types
from contextlib import contextmanager
from unittest import mock

from compact_kernel.crypto import CryptoProvider, pq_available

PQ = pq_available(CryptoProvider())


def _expand(sk: bytes) -> bytes:
    out, i = b"", 0
    while len(out) < 1952:
        out += hashlib.sha512(sk + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:1952]


def make_fake_oqs(mechs=("ML-DSA-65",)) -> types.ModuleType:
    m = types.ModuleType("oqs")

    class Signature:
        def __init__(self, mech, secret_key=None):
            assert mech == "ML-DSA-65"
            self._sk = secret_key

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def generate_keypair(self):
            self._sk = os.urandom(32)
            return _expand(self._sk)

        def export_secret_key(self):
            return self._sk

        def sign(self, msg):
            return self._sk + hmac.new(self._sk, msg, "sha256").digest()

        def verify(self, msg, sig, pk):
            sk, tag = sig[:32], sig[32:]
            return _expand(sk) == pk and hmac.compare_digest(hmac.new(sk, msg, "sha256").digest(), tag)

    m.Signature = Signature
    m.get_enabled_sig_mechanisms = lambda: list(mechs)
    m.oqs_version = lambda: "fake"
    m.oqs_python_version = lambda: "fake"
    return m


@contextmanager
def fake_oqs(mechs=("ML-DSA-65",)):
    with mock.patch.dict(sys.modules, {"oqs": make_fake_oqs(mechs)}):
        yield


@contextmanager
def no_oqs():
    with mock.patch.dict(sys.modules, {"oqs": None}):
        yield


@contextmanager
def pyca_without_mldsa():
    """Simulate a pyca cryptography build without ML-DSA (the import fails)."""
    with mock.patch.dict(sys.modules, {"cryptography.hazmat.primitives.asymmetric.mldsa": None}):
        yield


def decode_sig(sig_b64: str) -> dict:
    return json.loads(base64.b64decode(sig_b64))


def encode_sig(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).decode()


def flip_component(sig_b64: str, index: int) -> str:
    """Flip one bit in component ``index`` of a hybrid signature, keeping the structure valid."""
    obj = decode_sig(sig_b64)
    raw = bytearray(base64.b64decode(obj["sigs"][index][1]))
    raw[len(raw) // 2] ^= 0x01
    obj["sigs"][index][1] = base64.b64encode(bytes(raw)).decode()
    return encode_sig(obj)

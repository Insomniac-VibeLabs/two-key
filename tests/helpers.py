"""Shared test fixtures. Keys are generated per test and never written to the repo."""
import tempfile
from pathlib import Path

from compact_kernel import keys
from compact_kernel.constitution import build_document, sign_document
from compact_kernel.kernel import CompactKernel

DEFAULT_TEXT = "I am the principal. The agent is my fiduciary. No wires. No medical data off-device."


def signed(rules, text=DEFAULT_TEXT, principal="did:ck:test", key=None):
    key = key or keys.generate_private_key()
    return sign_document(build_document(principal, text, rules), key), key


class KernelFixture:
    """Context manager that builds a kernel in a temporary directory."""

    def __init__(self, rules, judges, text=DEFAULT_TEXT, **kw):
        self.rules, self.judges, self.text, self.kw = rules, judges, text, kw

    def __enter__(self) -> CompactKernel:
        self.tmp = tempfile.TemporaryDirectory()
        env, key = signed(self.rules, self.text)
        self.key = key
        kw = dict(self.kw)
        kw.setdefault("allow_test_doubles", True)
        try:
            self.kernel = CompactKernel(env, key.public_key(), Path(self.tmp.name) / "ledger.jsonl",
                                        self.judges, **self._extra(key, kw))
        except Exception:
            self.tmp.cleanup()
            raise
        return self.kernel

    def _extra(self, key, kw):
        kw.setdefault("ledger_signing_key", key)
        return kw

    def __exit__(self, *exc):
        self.tmp.cleanup()

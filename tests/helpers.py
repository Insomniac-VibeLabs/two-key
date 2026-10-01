"""Shared test fixtures. Keys are generated per test and never written to the repo."""
import os
import tempfile
from pathlib import Path

from two_key import keys
from two_key.constitution import build_document, sign_document
from two_key.core import TwoKey

DEFAULT_TEXT = "I am the principal. The agent is my fiduciary. No wires. No medical data off-device."


def signed(rules, text=DEFAULT_TEXT, principal="did:twokey:test", key=None):
    key = key or keys.generate_private_key()
    return sign_document(build_document(principal, text, rules), key), key


PRINCIPAL_EMAIL = "principal@two-key.test.invalid"
AGENT_URI = "spiffe://two-key.test/agent"
ROLE_MAP = {f"email:{PRINCIPAL_EMAIL}": ["principal"], f"uri:{AGENT_URI}": ["agent"],
            "dns:judge.two-key.test.invalid": ["judge"]}


def enterprise_pki(key, **config_kw):
    """A throwaway test PKI certifying ``key`` as the principal. Returns (TwoKey kwargs, TestPki)."""
    from two_key.pki_testing import TestPki
    t = TestPki()
    cert, _ = t.issue("Principal", email=PRINCIPAL_EMAIL, key=key)
    return {"pki": t.config(ROLE_MAP, **config_kw), "principal_credential": t.credential(cert)}, t


class TwoKeyFixture:
    """Context manager that builds a TwoKey instance in a temporary directory."""

    def __init__(self, rules, judges, text=DEFAULT_TEXT, **kw):
        self.rules, self.judges, self.text, self.kw = rules, judges, text, kw

    def __enter__(self) -> TwoKey:
        self.tmp = tempfile.TemporaryDirectory()
        env, key = signed(self.rules, self.text)
        self.key = key
        kw = dict(self.kw)
        kw.setdefault("allow_test_doubles", True)
        try:
            self.two_key = TwoKey(env, key.public_key(), Path(self.tmp.name) / "ledger.jsonl",
                                        self.judges, **self._extra(key, kw))
        except Exception:
            self.tmp.cleanup()
            raise
        return self.two_key

    def _extra(self, key, kw):
        kw.setdefault("ledger_signing_key", key)
        mode = kw.get("deployment_mode") or os.environ.get("TWOKEY_DEPLOYMENT_MODE")
        if str(mode).strip().lower() == "enterprise":
            kw.setdefault("siem_host", "127.0.0.1")
        if str(mode).strip().lower() == "enterprise" and "pki" not in kw:
            # Enterprise mode needs PKI identities (Entry 11). Tests written before that don't send agent
            # assertions, so the fixture turns that requirement off; tests/test_pki.py covers assertions.
            extra, self.pki = enterprise_pki(key, require_agent_identity=False)
            kw.update(extra)
        return kw

    def __exit__(self, *exc):
        self.tmp.cleanup()

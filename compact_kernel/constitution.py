"""Constitution upload, signing, and verification.

The principal uploads two files:
  1. a plain-English constitution (.txt or .md). It goes to the Path B judges.
  2. structured hard rules (.json, .yaml, .yml). They are compiled for Path A.

Both are bundled into a canonical document and signed with the principal's
key: legacy Ed25519 (default), ECDSA P-384, or a hybrid ML-DSA-65 suite
(compact_kernel.crypto.signatures; both halves of a hybrid must verify). The kernel loads a constitution only after verifying the
signature against a public key the principal trusts. Unsigned, modified,
or foreign-signed constitutions are rejected (spec 5.1 item 2: "Changing it
requires a fresh signature. Model vendors cannot push a new constitution.").
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import keys
from .canonical import canonical_bytes, digest_hex, sha256_hex
from .crypto.provider import CryptoProvider
from .crypto.signatures import LEGACY_SUITE, SUITES, as_private_keyset, as_public_keyset
from .policy_vm import ConstitutionError, validate_rules

FORMAT = "compact-kernel-constitution/1"
TEXT_SUFFIXES = {".txt", ".md", ".markdown"}
RULES_SUFFIXES = {".json", ".yaml", ".yml"}
MAX_TEXT_BYTES = 1_000_000


class ConstitutionSignatureError(ValueError):
    """Signature missing, invalid, or by an untrusted key."""


@dataclass(frozen=True)
class Constitution:
    principal: str
    text: str
    hard_rules: list
    created_at: str
    document: dict   # the exact signed document
    signer_fingerprint: str | None = None
    signer_suite: str = LEGACY_SUITE
    digest_alg: str = "sha256"   # "sha384" when signed with a non-legacy (e.g. hybrid PQ) suite

    @property
    def digest(self) -> str:
        return digest_hex(canonical_bytes(self.document), self.digest_alg)


def load_text_file(path: Path) -> str:
    path = Path(path)
    if path.suffix.lower() not in TEXT_SUFFIXES:
        raise ConstitutionError(f"constitution text must be one of {sorted(TEXT_SUFFIXES)}: {path.name}")
    data = path.read_bytes()
    if len(data) > MAX_TEXT_BYTES:
        raise ConstitutionError("constitution text too large")
    text = data.decode("utf-8")
    if not text.strip():
        raise ConstitutionError("constitution text is empty")
    return text


def load_rules_file(path: Path) -> list:
    path = Path(path)
    suf = path.suffix.lower()
    if suf not in RULES_SUFFIXES:
        raise ConstitutionError(f"hard rules must be one of {sorted(RULES_SUFFIXES)}: {path.name}")
    raw = path.read_text(encoding="utf-8")
    if suf == ".json":
        data = json.loads(raw)
    else:
        try:
            import yaml  # optional dependency
        except ImportError as e:  # pragma: no cover
            raise ConstitutionError("PyYAML is required for YAML rules (pip install pyyaml)") from e
        data = yaml.safe_load(raw)
    if isinstance(data, dict) and set(data) == {"hard_rules"}:
        data = data["hard_rules"]
    validate_rules(data)  # fail early on bad rules
    return data


def build_document(principal: str, text: str, hard_rules: list, created_at: str | None = None) -> dict:
    if not isinstance(principal, str) or not principal.strip():
        raise ConstitutionError("principal identifier required")
    validate_rules(hard_rules)
    return {
        "format": FORMAT,
        "principal": principal,
        "created_at": created_at or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "constitution_text": text,
        "constitution_text_sha256": sha256_hex(text.encode("utf-8")),
        "hard_rules": hard_rules,
    }


def sign_document(document: dict, key: Any, provider: CryptoProvider | None = None) -> dict:
    """Sign with an Ed25519 private key (legacy format) or any PrivateKeySet (e.g. hybrid ML-DSA-65)."""
    ks = as_private_keyset(key, provider)
    pub = ks.public()
    return {
        "constitution": document,
        "signature": {"alg": pub.envelope_alg, "public_key": pub.encoded, "sig": ks.sign(canonical_bytes(document))},
    }


def sign_files(text_path: Path, rules_path: Path, principal: str, key: Any) -> dict:
    return sign_document(build_document(principal, load_text_file(text_path), load_rules_file(rules_path)), key)


_KNOWN_ALGS = {"Ed25519"} | (set(SUITES) - {LEGACY_SUITE})


def verify_signed(envelope: Any, trusted_key: Any, provider: CryptoProvider | None = None) -> Constitution:
    """Verify a signed constitution envelope against the principal's trusted key.

    The envelope's suite must equal the trusted key's suite (no downgrade). For a
    hybrid trusted key every component must verify; if no PQ backend is available
    this raises PQUnavailableError instead of checking only the classical half.
    """
    trusted = as_public_keyset(trusted_key, provider)
    if not isinstance(envelope, dict) or "constitution" not in envelope:
        raise ConstitutionSignatureError("not a signed constitution envelope")
    sig = envelope.get("signature")
    if not isinstance(sig, dict) or not sig.get("sig"):
        raise ConstitutionSignatureError("constitution is unsigned")
    if sig.get("alg") not in _KNOWN_ALGS:
        raise ConstitutionSignatureError(f"unsupported signature algorithm {sig.get('alg')!r}")
    if sig.get("alg") != trusted.envelope_alg:
        raise ConstitutionSignatureError(
            f"signature suite {sig.get('alg')!r} does not match the trusted key's suite "
            f"{trusted.envelope_alg!r} (downgrade refused)")
    if set(envelope) - {"constitution", "signature"}:
        raise ConstitutionSignatureError("unexpected fields in envelope")
    embedded = sig.get("public_key", "")
    try:
        keys.b64d(embedded)
    except Exception as e:
        raise ConstitutionSignatureError("malformed embedded public key") from e
    if embedded != trusted.encoded:
        raise ConstitutionSignatureError("constitution signed by a key other than the principal's trusted key")
    doc = envelope["constitution"]
    if not isinstance(doc, dict):
        raise ConstitutionSignatureError("malformed constitution document")
    if not trusted.verify(canonical_bytes(doc), sig["sig"]):
        raise ConstitutionSignatureError("signature does not match: constitution was modified or forged")
    if doc.get("format") != FORMAT:
        raise ConstitutionError(f"unsupported constitution format {doc.get('format')!r}")
    text = doc.get("constitution_text")
    if not isinstance(text, str) or sha256_hex(text.encode("utf-8")) != doc.get("constitution_text_sha256"):
        raise ConstitutionError("constitution text hash mismatch")
    validate_rules(doc.get("hard_rules"))
    return Constitution(doc["principal"], text, doc["hard_rules"], doc["created_at"], doc,
                        trusted.fingerprint, trusted.suite,
                        "sha256" if trusted.suite == LEGACY_SUITE else "sha384")


def save_envelope(path: Path, envelope: dict) -> None:
    Path(path).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_envelope(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

"""Constitution upload, signing, and verification.

The principal uploads two files:
  1. a plain-English constitution (.txt or .md). It goes to the Path B judges.
  2. structured hard rules (.json, .yaml, .yml). They are compiled for Path A.

Both are bundled into a canonical document and signed with the principal's
key: legacy Ed25519 (default), ECDSA P-384, or a hybrid ML-DSA-65 suite
(two_key.crypto.signatures; both halves of a hybrid must verify). Two-Key loads a constitution only after verifying the
signature against a public key the principal trusts. Unsigned, modified,
or foreign-signed constitutions are rejected (spec 5.1 item 2: "Changing it
requires a fresh signature. Model vendors cannot push a new constitution.").

Two document formats are accepted (both signed as one document):
  two-key-constitution/1  separate ``constitution_text`` and ``hard_rules`` fields
  two-key-constitution/2  one Markdown ``source``; compiler.split_source
                                 extracts the ```twokey-rules block (PRIOR_ART.md §4 (ii))
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import keys
from .canonical import canonical_bytes, digest_hex
from .crypto.provider import CryptoProvider
from .crypto.signatures import LEGACY_SUITE, SUITES, as_private_keyset, as_public_keyset
from .policy_vm import ConstitutionError, validate_rules

FORMAT = "two-key-constitution/1"
FORMAT_V2 = "two-key-constitution/2"
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
    digest_alg: str = "sha384"   # every suite since F_REVIEW (Entry 10); the document hash is what this covers

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
        "constitution_text_sha384": digest_hex(text.encode("utf-8"), "sha384"),
        "hard_rules": hard_rules,
    }


def build_source_document(principal: str, source: str, created_at: str | None = None) -> dict:
    """Single-source (/2) document: prose plus exactly one ```twokey-rules JSON block."""
    from .compiler import split_source
    if not isinstance(principal, str) or not principal.strip():
        raise ConstitutionError("principal identifier required")
    _, rules = split_source(source)
    validate_rules(rules)
    return {
        "format": FORMAT_V2,
        "principal": principal,
        "created_at": created_at or _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "source_sha384": digest_hex(source.encode("utf-8"), "sha384"),
    }


def sign_source_file(source_path: Path, principal: str, key: Any) -> dict:
    return sign_document(build_source_document(principal, load_text_file(source_path)), key)


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
    if doc.get("format") == FORMAT:
        text, rules = doc.get("constitution_text"), doc.get("hard_rules")
        if not isinstance(text, str) or not _embedded_digest_ok(doc, "constitution_text", text, provider):
            raise ConstitutionError("constitution text hash mismatch")
    elif doc.get("format") == FORMAT_V2:
        from .compiler import split_source
        src = doc.get("source")
        if not isinstance(src, str) or not _embedded_digest_ok(doc, "source", src, provider):
            raise ConstitutionError("constitution source hash mismatch")
        text, rules = split_source(src)
    else:
        raise ConstitutionError(f"unsupported constitution format {doc.get('format')!r}")
    validate_rules(rules)
    if not isinstance(doc.get("principal"), str) or not isinstance(doc.get("created_at"), str):
        raise ConstitutionError("principal and created_at are required")
    return Constitution(doc["principal"], text, rules, doc["created_at"], doc,
                        trusted.fingerprint, trusted.suite, "sha384")


def _embedded_digest_ok(doc: dict, field: str, value: str, provider: CryptoProvider | None) -> bool:
    """New documents carry ``<field>_sha384``; documents signed before F_REVIEW carry ``<field>_sha256``
    (legacy reader). Every digest field present must match, and at least one must be present."""
    present = [(alg, doc[f"{field}_{alg}"]) for alg in ("sha384", "sha256") if f"{field}_{alg}" in doc]
    data = value.encode("utf-8")
    return bool(present) and all(digest_hex(data, alg, provider) == want for alg, want in present)


def save_envelope(path: Path, envelope: dict) -> None:
    Path(path).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_envelope(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

"""Constitution upload, signing, and verification.

The principal uploads two files:
  1. a plain-English constitution (.txt or .md). It goes to the Path B judges.
  2. structured hard rules (.json, .yaml, .yml). They are compiled for Path A.

Both are bundled into a canonical document and signed with the principal's
Ed25519 key. The kernel loads a constitution only after verifying the
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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import keys
from .canonical import canonical_bytes, sha256_hex
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

    @property
    def digest(self) -> str:
        return sha256_hex(canonical_bytes(self.document))


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


def sign_document(document: dict, key: Ed25519PrivateKey) -> dict:
    return {
        "constitution": document,
        "signature": {
            "alg": "Ed25519",
            "public_key": keys.b64e(keys.public_key_raw(key)),
            "sig": keys.sign(key, canonical_bytes(document)),
        },
    }


def sign_files(text_path: Path, rules_path: Path, principal: str, key: Ed25519PrivateKey) -> dict:
    return sign_document(build_document(principal, load_text_file(text_path), load_rules_file(rules_path)), key)


def verify_signed(envelope: Any, trusted_key: Ed25519PublicKey) -> Constitution:
    """Verify a signed constitution envelope against the principal's trusted key."""
    if not isinstance(envelope, dict) or "constitution" not in envelope:
        raise ConstitutionSignatureError("not a signed constitution envelope")
    sig = envelope.get("signature")
    if not isinstance(sig, dict) or not sig.get("sig"):
        raise ConstitutionSignatureError("constitution is unsigned")
    if sig.get("alg") != "Ed25519":
        raise ConstitutionSignatureError(f"unsupported signature algorithm {sig.get('alg')!r}")
    if set(envelope) - {"constitution", "signature"}:
        raise ConstitutionSignatureError("unexpected fields in envelope")
    trusted_raw = keys.public_key_raw(trusted_key)
    try:
        embedded = keys.b64d(sig.get("public_key", ""))
    except Exception as e:
        raise ConstitutionSignatureError("malformed embedded public key") from e
    if embedded != trusted_raw:
        raise ConstitutionSignatureError("constitution signed by a key other than the principal's trusted key")
    doc = envelope["constitution"]
    if not isinstance(doc, dict):
        raise ConstitutionSignatureError("malformed constitution document")
    if not keys.verify(trusted_key, canonical_bytes(doc), sig["sig"]):
        raise ConstitutionSignatureError("signature does not match: constitution was modified or forged")
    if doc.get("format") != FORMAT:
        raise ConstitutionError(f"unsupported constitution format {doc.get('format')!r}")
    text = doc.get("constitution_text")
    if not isinstance(text, str) or sha256_hex(text.encode("utf-8")) != doc.get("constitution_text_sha256"):
        raise ConstitutionError("constitution text hash mismatch")
    validate_rules(doc.get("hard_rules"))
    return Constitution(doc["principal"], text, doc["hard_rules"], doc["created_at"], doc,
                        keys.fingerprint(trusted_key))


def save_envelope(path: Path, envelope: dict) -> None:
    Path(path).write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_envelope(path: Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

"""Enterprise PKI identities: X.509 certificates for principals, agents, and judges.

Stephan Busch, 2026-10-01 (CONCEPTION_NOTES.md Entry 11): "add ... PKI for
enterprise use". This module is AI-prepared engineering. Every setting not
yet decided by Stephan is marked PLACEHOLDER and listed in
docs/PROVISIONAL_READINESS.md.

What a certificate is checked for (``PkiVerifier.verify``)
----------------------------------------------------------
1. **Chain** to a configured trust anchor, through ``cryptography``'s X.509
   verifier (RFC 5280 path building, client profile). It checks signatures,
   validity periods (expiry), CA basic constraints, and path length. The
   leaf must carry a subjectAltName; its EKU, if present, must allow
   clientAuth.
2. **Key usage:** the leaf must assert ``digitalSignature``.
3. **Revocation** of every certificate below the anchor: OCSP first, then
   CRL (``revocation="ocsp_then_crl"``), or just one of them. OCSP responses
   and CRLs are signature-checked and must be current. When no answer can
   be obtained, ``revocation_unreachable="fail_closed"`` (the default)
   rejects the certificate. PLACEHOLDER pending Stephan; ``"fail_open"``
   accepts it and records ``status="unreachable"``.
4. **Role:** the subject DN and each SAN (``subject:<RFC 4514>``,
   ``email:``, ``uri:``, ``dns:``) are looked up in ``role_map``. The
   requested Two-Key role (``principal``, ``agent``, ``judge``) must be
   among the roles found. Matching is exact. Wildcards are an open question.
5. **Hybrid post-quantum binding:** a non-critical certificate extension
   (``MLDSA_BINDING_OID``) carries SHA-384 of the holder's ML-DSA-65 public
   key. The CA signs it, it is revoked with the certificate, and it can be
   checked offline. If the extension is present, the matching ML-DSA-65 key
   must be presented, and the identity's key is the hybrid suite
   (ML-DSA-65 + the certificate's classical key). Classical-only use of such
   a certificate is refused, so there is no downgrade. Chosen over a signed
   binding record because a record signed only by the classical key would
   fall with that key; the CA's signature over the extension does not
   depend on the holder's key.

Keys on hardware: ``Pkcs11PrivateKey`` wraps a key held on a PKCS#11
token (HSM or smart card) behind a small ``Pkcs11Token`` interface;
``PythonPkcs11Token`` is the adapter for the optional ``python-pkcs11``
package. Without it, ``Pkcs11Unavailable`` is raised and nothing else
changes.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID  # noqa: F401  (NameOID: helpers)

from .crypto.provider import CryptoProvider, default_provider

ROLES = ("principal", "agent", "judge")
# Two-Key ML-DSA-65 public-key binding extension. A UUID-based OID (ITU-T X.667 arc 2.25) needs no registration.
MLDSA_BINDING_OID = x509.ObjectIdentifier("2.25.141047315843386214707424547383219486297")
ID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18"           # NIST OID for ML-DSA-65 (FIPS 204)
REVOCATION_METHODS = ("ocsp_then_crl", "ocsp", "crl")
REVOCATION_UNREACHABLE = ("fail_closed", "fail_open")
DEFAULT_REVOCATION_UNREACHABLE = "fail_closed"     # PLACEHOLDER pending Stephan
AGENT_ASSERTION_FORMAT = "two-key-agent-assertion/1"
DOMAIN_AGENT_REQUEST = "two-key/agent-request"
DEFAULT_AGENT_ASSERTION_MAX_AGE = 300              # seconds; PLACEHOLDER pending Stephan


class PkiError(Exception):
    """Base class for PKI errors."""


class PkiConfigError(PkiError, ValueError):
    """The PKI configuration is missing or invalid."""


class CertificateRejected(PkiError):
    """A certificate failed a check. ``reason`` is a short code (chain, expired, key_usage, revoked, ...)."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason, self.detail = reason, detail


class Pkcs11Unavailable(PkiError):
    """The optional python-pkcs11 package (or a PKCS#11 module) is not available."""


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _utc(cert_or_obj, name: str):
    v = getattr(cert_or_obj, name + "_utc", None)
    if v is None:
        v = getattr(cert_or_obj, name)
        if v is not None and v.tzinfo is None:
            v = v.replace(tzinfo=_dt.timezone.utc)
    return v


def load_certificates(data: bytes | str | Path) -> list[x509.Certificate]:
    """Certificates from PEM (one or more) or DER bytes, or a file path."""
    if isinstance(data, (str, Path)) and not (isinstance(data, str) and data.lstrip().startswith("-----")):
        data = Path(data).read_bytes()
    if isinstance(data, str):
        data = data.encode("ascii")
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_certificates(data)
    return [x509.load_der_x509_certificate(data)]


def _load_crl(data: bytes) -> x509.CertificateRevocationList:
    if b"-----BEGIN" in data:
        return x509.load_pem_x509_crl(data)
    return x509.load_der_x509_crl(data)


def cert_fingerprint(cert: x509.Certificate) -> str:
    return "sha384:" + cert.fingerprint(hashes.SHA384()).hex()


def mldsa_binding_value(mldsa_public_raw: bytes) -> bytes:
    """DER of the binding extension: SEQUENCE { OID id-ml-dsa-65, OCTET STRING SHA-384(public key) }."""
    oid = _der_oid(ID_ML_DSA_65)
    digest = hashlib.sha384(mldsa_public_raw).digest()
    body = oid + b"\x04" + bytes([len(digest)]) + digest
    return b"\x30" + bytes([len(body)]) + body


def mldsa_binding_extension(mldsa_public_raw: bytes) -> x509.UnrecognizedExtension:
    """The extension a CA adds (non-critical) to bind the holder's ML-DSA-65 key to the certificate."""
    return x509.UnrecognizedExtension(MLDSA_BINDING_OID, mldsa_binding_value(mldsa_public_raw))


def _der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(enc))
    return b"\x06" + bytes([len(out)]) + bytes(out)


def certificate_names(cert: x509.Certificate) -> list[str]:
    """The names role_map is matched against: ``subject:<RFC 4514>`` and each SAN with a type prefix."""
    names = [f"subject:{cert.subject.rfc4514_string()}"]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return names
    for v in san.get_values_for_type(x509.RFC822Name):
        names.append(f"email:{v}")
    for v in san.get_values_for_type(x509.UniformResourceIdentifier):
        names.append(f"uri:{v}")
    for v in san.get_values_for_type(x509.DNSName):
        names.append(f"dns:{v}")
    return names


# ---------------------------------------------------------------------------
# Credentials and identities
# ---------------------------------------------------------------------------
@dataclass
class Credential:
    """What a party presents: its leaf certificate, any intermediates, and (hybrid) its ML-DSA-65 public key."""
    certificate: x509.Certificate
    chain: list = field(default_factory=list)
    mldsa_public: bytes | None = None

    @classmethod
    def from_pem(cls, cert: bytes | str | Path, chain: bytes | str | Path | None = None,
                 mldsa_public: bytes | None = None) -> "Credential":
        certs = load_certificates(cert)
        extra = load_certificates(chain) if chain else []
        return cls(certs[0], certs[1:] + extra, mldsa_public)

    def to_record(self) -> dict:
        pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode("ascii")  # noqa: E731
        return {"certificate": pem(self.certificate), "chain": [pem(c) for c in self.chain],
                "mldsa_public": None if self.mldsa_public is None else base64.b64encode(self.mldsa_public).decode()}

    @classmethod
    def from_record(cls, d: Mapping[str, Any]) -> "Credential":
        mp = d.get("mldsa_public")
        return cls(load_certificates(d["certificate"].encode("ascii"))[0],
                   [load_certificates(c.encode("ascii"))[0] for c in d.get("chain") or []],
                   None if mp is None else base64.b64decode(mp, validate=True))


@dataclass(frozen=True)
class Identity:
    role: str
    roles: tuple
    subject: str
    names: tuple
    issuer: str
    serial: str
    fingerprint: str
    not_after: str
    public_keyset: Any = field(repr=False)
    mldsa_bound: bool = False
    revocation: tuple = ()      # one (subject, method, status) triple per checked certificate

    def to_record(self) -> dict:
        return {"role": self.role, "roles": list(self.roles), "subject": self.subject, "names": list(self.names),
                "issuer": self.issuer, "serial": self.serial, "certificate": self.fingerprint,
                "not_after": self.not_after, "key": self.public_keyset.fingerprint,
                "suite": self.public_keyset.suite, "mldsa_bound": self.mldsa_bound,
                "revocation": [{"subject": s, "method": m, "status": st} for s, m, st in self.revocation]}


def classical_suite(public_key) -> str:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP384R1):
        return "ecdsa-p384"
    raise CertificateRejected("key_type", f"certificate key {type(public_key).__name__} is not Ed25519 or "
                                          "ECDSA P-384 (the Two-Key signature suites)")


def credential_keyset(cred: Credential, provider: CryptoProvider | None = None):
    """The Two-Key public key set of a credential: classical, or hybrid with the presented ML-DSA-65 key."""
    from .crypto.signatures import PublicKeySet, _EcdsaP384, _Ed25519
    provider = provider or default_provider()
    pub = cred.certificate.public_key()
    suite = classical_suite(pub)
    impl = _Ed25519 if suite == "ed25519" else _EcdsaP384
    raw = impl.public_raw(pub)
    if cred.mldsa_public is None:
        return PublicKeySet(suite, [pub], [raw], provider)
    pq = provider.require_pq()
    return PublicKeySet(f"hybrid-mldsa65-{'ed25519' if suite == 'ed25519' else 'p384'}",
                        [pq.public_from_raw(cred.mldsa_public), pub], [cred.mldsa_public, raw], provider)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@dataclass
class PkiConfig:
    """Trust anchors, revocation sources, role mapping. See the module docstring for each check.

    ``crl_fetcher(url) -> bytes`` and ``ocsp_fetcher(url, request_der) -> bytes`` do the network I/O, so tests and
    air-gapped sites can supply their own. ``default_transport()`` gives a urllib-based pair (untested against
    real responders). ``ocsp_url`` overrides the certificate's AIA URL.
    """
    trust_anchors: list
    intermediates: list = field(default_factory=list)
    crls: list = field(default_factory=list)
    crl_fetcher: Callable[[str], bytes] | None = None
    ocsp_fetcher: Callable[[str, bytes], bytes] | None = None
    ocsp_url: str | None = None
    revocation: str = "ocsp_then_crl"
    revocation_unreachable: str = DEFAULT_REVOCATION_UNREACHABLE     # PLACEHOLDER pending Stephan
    role_map: Mapping[str, Sequence[str]] = field(default_factory=dict)
    require_agent_identity: bool = True        # enterprise default; PLACEHOLDER pending Stephan
    require_judge_identities: bool = False     # PLACEHOLDER pending Stephan
    agent_assertion_max_age: int = DEFAULT_AGENT_ASSERTION_MAX_AGE
    max_chain_depth: int = 4

    def __post_init__(self):
        if not self.trust_anchors:
            raise PkiConfigError("PKI needs at least one trust anchor")
        if self.revocation not in REVOCATION_METHODS:
            raise PkiConfigError(f"revocation must be one of {REVOCATION_METHODS}")
        if self.revocation_unreachable not in REVOCATION_UNREACHABLE:
            raise PkiConfigError(f"revocation_unreachable must be one of {REVOCATION_UNREACHABLE}")
        rm = {}
        for name, roles in dict(self.role_map).items():
            roles = [roles] if isinstance(roles, str) else list(roles)
            bad = [r for r in roles if r not in ROLES]
            if bad or not isinstance(name, str) or ":" not in name:
                raise PkiConfigError(f"role_map entry {name!r}: names look like 'email:...', 'uri:...', 'dns:...' "
                                     f"or 'subject:CN=...'; roles must be in {ROLES}")
            rm[name] = tuple(roles)
        self.role_map = rm

    @classmethod
    def from_mapping(cls, d: Mapping[str, Any], base_dir: str | Path = ".") -> "PkiConfig":
        """Build from a config-file ``pki:`` section. Paths are relative to ``base_dir``."""
        base = Path(base_dir)
        p = lambda x: x if Path(x).is_absolute() else base / x  # noqa: E731
        certs = lambda key: [c for f in d.get(key) or [] for c in load_certificates(p(f))]  # noqa: E731
        known = {"trust_anchors", "intermediates", "crls", "ocsp_url", "revocation", "revocation_unreachable",
                 "role_map", "require_agent_identity", "require_judge_identities", "agent_assertion_max_age",
                 "max_chain_depth", "network_revocation"}
        unknown = set(d) - known
        if unknown:
            raise PkiConfigError(f"unknown pki settings: {sorted(unknown)}")
        kw: dict[str, Any] = {k: d[k] for k in ("ocsp_url", "revocation", "revocation_unreachable", "role_map",
                                                 "require_agent_identity", "require_judge_identities",
                                                 "agent_assertion_max_age", "max_chain_depth") if k in d}
        if d.get("network_revocation"):
            kw["crl_fetcher"], kw["ocsp_fetcher"] = default_transport()
        return cls(trust_anchors=certs("trust_anchors"), intermediates=certs("intermediates"),
                   crls=[_load_crl(Path(p(f)).read_bytes()) for f in d.get("crls") or []], **kw)

    def describe(self) -> dict:
        return {"trust_anchors": [cert_fingerprint(c) for c in self.trust_anchors],
                "revocation": self.revocation, "revocation_unreachable": self.revocation_unreachable,
                "crls": len(self.crls), "ocsp": self.ocsp_fetcher is not None, "role_map_entries": len(self.role_map),
                "require_agent_identity": self.require_agent_identity,
                "require_judge_identities": self.require_judge_identities}


def default_transport(timeout: float = 5.0):
    """(crl_fetcher, ocsp_fetcher) over HTTP with urllib. Untested against real CAs/responders."""
    import urllib.request

    def crl(url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=timeout) as r:  # noqa: S310 (CRL DPs are http by design)
            return r.read()

    def ocsp_(url: str, req: bytes) -> bytes:
        rq = urllib.request.Request(url, data=req, headers={"Content-Type": "application/ocsp-request"})
        with urllib.request.urlopen(rq, timeout=timeout) as r:  # noqa: S310
            return r.read()
    return crl, ocsp_


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def _verify_signature(pub, signature: bytes, data: bytes, hash_alg) -> bool:
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(signature, data)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, data, ec.ECDSA(hash_alg))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(signature, data, padding.PKCS1v15(), hash_alg)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


class PkiVerifier:
    def __init__(self, config: PkiConfig, provider: CryptoProvider | None = None,
                 clock: Callable[[], float] | None = None):
        self.config = config
        self.provider = provider or default_provider()
        self.clock = clock

    def _time(self, at: _dt.datetime | None) -> _dt.datetime:
        if at is not None:
            return at
        if self.clock is not None:
            return _dt.datetime.fromtimestamp(self.clock(), _dt.timezone.utc)
        return _now()

    def describe(self) -> dict:
        return self.config.describe()

    # -- the full check --------------------------------------------------------
    def verify(self, cred: Credential, role: str, at: _dt.datetime | None = None) -> Identity:
        if role not in ROLES:
            raise PkiConfigError(f"role must be one of {ROLES}")
        now = self._time(at)
        leaf = cred.certificate
        nb, na = _utc(leaf, "not_valid_before"), _utc(leaf, "not_valid_after")
        if now > na:
            raise CertificateRejected("expired", f"certificate expired at {na.isoformat()}")
        if now < nb:
            raise CertificateRejected("not_yet_valid", f"certificate is valid from {nb.isoformat()}")
        chain = self._chain(cred, now)
        self._key_usage(leaf)
        revocation = tuple(self._revocation(chain[i], chain[i + 1], now) for i in range(len(chain) - 1))
        names = certificate_names(leaf)
        roles = tuple(sorted({r for n in names for r in self.config.role_map.get(n, ())}))
        if role not in roles:
            raise CertificateRejected("role", f"{names[0]} is not mapped to role {role!r} (mapped: {list(roles)})")
        bound = self._mldsa_binding(cred)
        keyset = credential_keyset(cred, self.provider)
        return Identity(role, roles, leaf.subject.rfc4514_string(), tuple(names), leaf.issuer.rfc4514_string(),
                        format(leaf.serial_number, "x"), cert_fingerprint(leaf), na.isoformat(), keyset, bound,
                        revocation)

    def _chain(self, cred: Credential, now: _dt.datetime) -> list:
        from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
        try:
            verifier = (PolicyBuilder().store(Store(list(self.config.trust_anchors))).time(now)
                        .max_chain_depth(self.config.max_chain_depth).build_client_verifier())
            res = verifier.verify(cred.certificate, list(cred.chain) + list(self.config.intermediates))
        except VerificationError as e:
            raise CertificateRejected("chain", f"does not chain to a configured trust anchor: {e}") from None
        except ValueError as e:
            raise CertificateRejected("chain", str(e)) from None
        return list(res.chain)

    @staticmethod
    def _key_usage(leaf: x509.Certificate) -> None:
        try:
            ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            raise CertificateRejected("key_usage", "certificate has no keyUsage extension") from None
        if not ku.digital_signature:
            raise CertificateRejected("key_usage", "keyUsage does not allow digitalSignature")

    def _mldsa_binding(self, cred: Credential) -> bool:
        try:
            ext = cred.certificate.extensions.get_extension_for_oid(MLDSA_BINDING_OID).value
        except x509.ExtensionNotFound:
            if cred.mldsa_public is not None:
                raise CertificateRejected("mldsa_binding", "an ML-DSA-65 key was presented but the certificate "
                                                           "does not bind one") from None
            return False
        if cred.mldsa_public is None:
            raise CertificateRejected("mldsa_binding", "the certificate binds an ML-DSA-65 key; present it "
                                                       "(classical-only use would be a downgrade)")
        if ext.value != mldsa_binding_value(cred.mldsa_public):
            raise CertificateRejected("mldsa_binding", "the presented ML-DSA-65 key does not match the "
                                                       "certificate's binding")
        return True

    # -- revocation ---------------------------------------------------------------
    def _revocation(self, cert, issuer, now) -> tuple:
        subject = cert.subject.rfc4514_string()
        methods = {"ocsp_then_crl": ("ocsp", "crl"), "ocsp": ("ocsp",), "crl": ("crl",)}[self.config.revocation]
        problems = []
        for m in methods:
            try:
                status = self._ocsp(cert, issuer, now) if m == "ocsp" else self._crl(cert, issuer, now)
            except _NoAnswer as e:
                problems.append(f"{m}: {e}")
                continue
            if status == "revoked":
                raise CertificateRejected("revoked", f"{subject} is revoked ({m})")
            return (subject, m, "good")
        if self.config.revocation_unreachable == "fail_open":
            return (subject, "none", "unreachable")
        raise CertificateRejected("revocation_unreachable",
                                  f"no revocation status for {subject} ({'; '.join(problems)}); "
                                  "revocation_unreachable='fail_closed' (placeholder pending Stephan)")

    def _crl(self, cert, issuer, now) -> str:
        candidates = [c for c in self.config.crls if c.issuer == issuer.subject]
        if not candidates and self.config.crl_fetcher is not None:
            for url in _crl_urls(cert):
                try:
                    candidates.append(_load_crl(self.config.crl_fetcher(url)))
                except Exception as e:  # network or parse failure: no answer from this source
                    raise _NoAnswer(f"fetch {url} failed: {type(e).__name__}") from None
        if not candidates:
            raise _NoAnswer("no CRL for the issuer")
        for crl in candidates:
            if crl.issuer != issuer.subject or not crl.is_signature_valid(issuer.public_key()):
                continue
            last, nxt = _utc(crl, "last_update"), _utc(crl, "next_update")
            if last > now or (nxt is not None and nxt < now):
                continue
            return "revoked" if crl.get_revoked_certificate_by_serial_number(cert.serial_number) else "good"
        raise _NoAnswer("no current CRL with a valid issuer signature")

    def _ocsp(self, cert, issuer, now) -> str:
        if self.config.ocsp_fetcher is None:
            raise _NoAnswer("no OCSP transport configured")
        url = self.config.ocsp_url or _ocsp_url(cert)
        if not url:
            raise _NoAnswer("no OCSP URL")
        req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256()).build()
        try:
            resp = ocsp.load_der_ocsp_response(self.config.ocsp_fetcher(url, req.public_bytes(serialization.Encoding.DER)))
        except Exception as e:
            raise _NoAnswer(f"request to {url} failed: {type(e).__name__}") from None
        if resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise _NoAnswer(f"responder status {resp.response_status.name}")
        signer = self._ocsp_signer(resp, issuer, now)
        if signer is None or not _verify_signature(signer.public_key(), resp.signature, resp.tbs_response_bytes,
                                                   resp.signature_hash_algorithm):
            raise _NoAnswer("OCSP response signature is not from the issuer or its delegated responder")
        if resp.serial_number != cert.serial_number or \
                resp.issuer_key_hash != req.issuer_key_hash or resp.issuer_name_hash != req.issuer_name_hash:
            raise _NoAnswer("OCSP response is for a different certificate")
        this, nxt = _utc(resp, "this_update"), _utc(resp, "next_update")
        if this > now + _dt.timedelta(minutes=5) or (nxt is not None and nxt < now):
            raise _NoAnswer("OCSP response is not current")
        if resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            return "revoked"
        if resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return "good"
        raise _NoAnswer("responder says status unknown")

    @staticmethod
    def _ocsp_signer(resp, issuer, now):
        def is_responder(c) -> bool:
            if resp.responder_name is not None:
                return c.subject == resp.responder_name
            return x509.SubjectKeyIdentifier.from_public_key(c.public_key()).digest == resp.responder_key_hash
        if is_responder(issuer):
            return issuer
        for c in resp.certificates:  # delegated responder: issued by the CA, EKU OCSPSigning, currently valid
            if not is_responder(c):
                continue
            try:
                c.verify_directly_issued_by(issuer)
                eku = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            except (InvalidSignature, ValueError, TypeError, x509.ExtensionNotFound):
                continue
            if ExtendedKeyUsageOID.OCSP_SIGNING in eku and _utc(c, "not_valid_before") <= now <= _utc(c, "not_valid_after"):
                return c
        return None


class _NoAnswer(Exception):
    pass


def _crl_urls(cert) -> list[str]:
    try:
        dps = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return []
    return [n.value for dp in dps for n in (dp.full_name or []) if isinstance(n, x509.UniformResourceIdentifier)]


def _ocsp_url(cert) -> str | None:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for d in aia:
        if d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP and \
                isinstance(d.access_location, x509.UniformResourceIdentifier):
            return d.access_location.value
    return None


# ---------------------------------------------------------------------------
# Agent assertions: the agent proves it holds its certified key, per request
# ---------------------------------------------------------------------------
def request_digest(action_record: Mapping[str, Any], proposal: str, args_hash_sha384: str,
                   provider: CryptoProvider | None = None) -> str:
    from .canonical import typed_hash
    return typed_hash({"action": dict(action_record), "proposal": str(proposal), "args_hash": args_hash_sha384},
                      DOMAIN_AGENT_REQUEST, "sha384", provider or default_provider())


def agent_request_digest(proposed: Any, proposal: str, tool_args: Mapping[str, Any] | None,
                         provider: CryptoProvider | None = None) -> str:
    """What an agent signs: H(normalized action, proposal text, SHA-384 args hash) in two-key-enc/2."""
    from .action import normalize_action
    from .canonical import freeze_call
    from .capability import args_hash
    provider = provider or default_provider()
    action = normalize_action(proposed)
    a_hash = args_hash(action.tool, freeze_call("", {} if tool_args is None else tool_args).args(), "sha384", provider)
    return request_digest(action.to_record(), proposal, a_hash, provider)


def _assertion_message(d: Mapping[str, Any]) -> bytes:
    from .canonical import typed_bytes
    return typed_bytes({k: d[k] for k in ("format", "request_digest", "issued_at", "nonce", "credential")},
                       DOMAIN_AGENT_REQUEST + "/assertion")


def sign_agent_request(credential: Credential, signing_key: Any, proposed: Any, proposal: str,
                       tool_args: Mapping[str, Any] | None = None, *, provider: CryptoProvider | None = None,
                       clock: Callable[[], float] = time.time) -> dict:
    """An agent assertion for one request, signed with the agent's certified key (or hybrid key set)."""
    from .crypto.signatures import as_private_keyset
    provider = provider or default_provider()
    d = {"format": AGENT_ASSERTION_FORMAT, "request_digest": agent_request_digest(proposed, proposal, tool_args, provider),
         "issued_at": int(clock()), "nonce": provider.random_bytes(16).hex(), "credential": credential.to_record()}
    d["signature"] = as_private_keyset(signing_key, provider).sign(_assertion_message(d))
    return d


def verify_agent_assertion(verifier: PkiVerifier, assertion: Mapping[str, Any], request_digest: str,
                           seen_nonces: set | None = None) -> Identity:
    """Check an agent assertion: certificate (role agent), signature, request binding, freshness, replay."""
    if not isinstance(assertion, Mapping) or assertion.get("format") != AGENT_ASSERTION_FORMAT:
        raise CertificateRejected("assertion", "not a two-key agent assertion")
    try:
        cred = Credential.from_record(assertion["credential"])
        issued = int(assertion["issued_at"])
        nonce = str(assertion["nonce"])
        msg = _assertion_message(assertion)
    except (KeyError, TypeError, ValueError) as e:
        raise CertificateRejected("assertion", f"malformed agent assertion ({type(e).__name__})") from None
    now = verifier.clock() if verifier.clock else time.time()
    if abs(now - issued) > verifier.config.agent_assertion_max_age:
        raise CertificateRejected("assertion_stale", "agent assertion is outside the allowed age")
    if seen_nonces is not None and nonce in seen_nonces:
        raise CertificateRejected("assertion_replay", "agent assertion nonce was already used")
    ident = verifier.verify(cred, "agent")
    if assertion.get("request_digest") != request_digest:
        raise CertificateRejected("assertion_binding", "agent assertion is for a different request")
    if not ident.public_keyset.verify(msg, assertion.get("signature")):
        raise CertificateRejected("assertion_signature", "agent assertion signature does not verify")
    if seen_nonces is not None:
        seen_nonces.add(nonce)
    return ident


# ---------------------------------------------------------------------------
# PKCS#11 (HSM / smart card) signing keys
# ---------------------------------------------------------------------------
class Pkcs11Token:
    """Minimal token interface. ``sign`` returns the raw PKCS#11 output (ECDSA: r || s; EdDSA: R || S)."""

    def public_key(self, label: str):  # pragma: no cover - interface
        raise NotImplementedError

    def sign(self, label: str, mechanism: str, data: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


class Pkcs11PrivateKey:
    """A non-exportable private key on a token, usable as a component of a Two-Key PrivateKeySet.

    Supports ECDSA P-384 (the token signs the SHA-384 digest with CKM_ECDSA) and Ed25519 (CKM_EDDSA).
    """
    external = True

    def __init__(self, token: Pkcs11Token, label: str):
        self.token, self.label = token, label
        self._pub = token.public_key(label)
        classical_suite(self._pub)  # refuse other key types early

    def __repr__(self) -> str:
        return f"<Pkcs11PrivateKey {self.label!r} on {type(self.token).__name__}>"

    def public_key(self):
        return self._pub

    def sign(self, data: bytes, algorithm=None) -> bytes:
        if isinstance(self._pub, ed25519.Ed25519PublicKey):
            return self.token.sign(self.label, "EDDSA", data)
        if not (isinstance(algorithm, ec.ECDSA) and isinstance(algorithm.algorithm, hashes.SHA384)):
            raise TypeError("PKCS#11 P-384 keys sign with ECDSA SHA-384 only")
        raw = self.token.sign(self.label, "ECDSA", hashlib.sha384(data).digest())
        n = len(raw) // 2
        return encode_dss_signature(int.from_bytes(raw[:n], "big"), int.from_bytes(raw[n:], "big"))

    def private_bytes(self, *a, **k):
        raise TypeError("this key is on a PKCS#11 token and cannot be exported")

    def private_numbers(self):
        raise TypeError("this key is on a PKCS#11 token and cannot be exported")


class PythonPkcs11Token(Pkcs11Token):
    """Adapter for the optional ``python-pkcs11`` package (``pip install python-pkcs11``).

    ``module`` is the vendor PKCS#11 library path (for example SoftHSM's ``libsofthsm2.so``). Tested here against
    SoftHSM 2.6 only; untested against real HSMs or smart cards.
    """

    def __init__(self, module: str, token_label: str, pin: str):
        try:
            import pkcs11  # type: ignore
        except ImportError:
            raise Pkcs11Unavailable("PKCS#11 support needs the optional python-pkcs11 package "
                                    "(pip install python-pkcs11) and a vendor PKCS#11 module") from None
        self._p11 = pkcs11
        try:
            lib = pkcs11.lib(module)
            self._session = lib.get_token(token_label=token_label).open(user_pin=pin)
        except Exception as e:
            raise Pkcs11Unavailable(f"cannot open PKCS#11 token {token_label!r}: {type(e).__name__}: {e}") from None

    def _key(self, label: str, cls):
        return self._session.get_key(object_class=cls, label=label)

    def public_key(self, label: str):
        p = self._p11
        from pkcs11.util.ec import encode_ec_public_key  # type: ignore
        k = self._key(label, p.ObjectClass.PUBLIC_KEY)
        if k.key_type == p.KeyType.EC:
            return serialization.load_der_public_key(encode_ec_public_key(k))  # SubjectPublicKeyInfo DER
        if k.key_type == getattr(p.KeyType, "EC_EDWARDS", None):
            point = k[p.Attribute.EC_POINT]
            raw = point[2:] if len(point) == 34 and point[0] == 0x04 else point
            return ed25519.Ed25519PublicKey.from_public_bytes(bytes(raw))
        raise CertificateRejected("key_type", f"token key {label!r} is not EC or EdDSA")

    def sign(self, label: str, mechanism: str, data: bytes) -> bytes:
        p = self._p11
        k = self._key(label, p.ObjectClass.PRIVATE_KEY)
        mech = {"ECDSA": p.Mechanism.ECDSA, "EDDSA": p.Mechanism.EDDSA}[mechanism]
        return bytes(k.sign(data, mechanism=mech))


def signing_keyset(classical_private: Any, mldsa_private: Any = None, provider: CryptoProvider | None = None):
    """A PrivateKeySet for a certified identity: the certificate's key (software or Pkcs11PrivateKey), plus the
    ML-DSA-65 private key for the hybrid suite."""
    from .crypto.signatures import PrivateKeySet
    provider = provider or default_provider()
    suite = classical_suite(classical_private.public_key())
    if mldsa_private is None:
        return PrivateKeySet(suite, [classical_private], provider)
    return PrivateKeySet(f"hybrid-mldsa65-{'ed25519' if suite == 'ed25519' else 'p384'}",
                         [mldsa_private, classical_private], provider)

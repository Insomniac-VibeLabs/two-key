"""A throwaway test PKI (root CA, intermediate CA, leaf certificates, CRLs, an OCSP responder) and a
software PKCS#11 token. For tests, the demo, and HOWTO examples only: keys live in memory, nothing is
protected, and none of it is meant for real use.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from .pki import Credential, PkiConfig, Pkcs11PrivateKey, Pkcs11Token, mldsa_binding_extension, signing_keyset

CRL_URL = "http://crl.two-key.test.invalid/intermediate.crl"
OCSP_URL = "http://ocsp.two-key.test.invalid/"
ROOT_CRL_URL = "http://crl.two-key.test.invalid/root.crl"


def _name(cn: str, org: str = "Two-Key Test PKI") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class TestPki:
    """Root -> intermediate -> leaves, all ECDSA P-384 / SHA-384 unless a leaf key is supplied."""
    __test__ = False  # not a unittest/pytest class

    def __init__(self, now: _dt.datetime | None = None, org: str = "Two-Key Test PKI"):
        self.now = now or _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
        self.org = org
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = self._ca(_name("Test Root CA", org), self.root_key, None, None, path_length=1, years=10)
        self.intermediate_key = ec.generate_private_key(ec.SECP384R1())
        self.intermediate = self._ca(_name("Test Issuing CA", org), self.intermediate_key, self.root, self.root_key,
                                     path_length=0, years=5)
        self.issued: dict[int, tuple[x509.Certificate, x509.Certificate, Any]] = {}  # serial -> (cert, issuer, key)
        self.revoked: set[int] = set()
        self.issued[self.intermediate.serial_number] = (self.intermediate, self.root, self.root_key)

    def _ca(self, name, key, issuer, issuer_key, path_length, years):
        issuer_name = issuer.subject if issuer is not None else name
        signer = issuer_key or key
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name).public_key(key.public_key())
             .serial_number(x509.random_serial_number())
             .not_valid_before(self.now - _dt.timedelta(days=1))
             .not_valid_after(self.now + _dt.timedelta(days=365 * years))
             .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
             .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False))
        if issuer is not None:  # the intermediate: revocation is checked through the root's CRL / OCSP
            b = (b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                    [x509.UniformResourceIdentifier(ROOT_CRL_URL)], None, None, None)]), critical=False)
                 .add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
                     AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL))]), critical=False))
        return b.sign(signer, hashes.SHA384())

    def issue(self, cn: str, *, email: str | None = None, uri: str | None = None, dns: str | None = None,
              key: Any = None, mldsa_public: bytes | None = None, days: int = 30,
              not_before: _dt.datetime | None = None, digital_signature: bool = True,
              client_auth: bool = True, by_root: bool = False):
        """A leaf certificate. Returns ``(certificate, private_key)``; the key is new P-384 unless given."""
        key = key or ec.generate_private_key(ec.SECP384R1())
        issuer, ikey = (self.root, self.root_key) if by_root else (self.intermediate, self.intermediate_key)
        sans = [x509.RFC822Name(email)] if email else []
        sans += [x509.UniformResourceIdentifier(uri)] if uri else []
        sans += [x509.DNSName(dns)] if dns else []
        nb = not_before or (self.now - _dt.timedelta(hours=1))
        b = (x509.CertificateBuilder().subject_name(_name(cn, self.org)).issuer_name(issuer.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(nb).not_valid_after(nb + _dt.timedelta(days=days))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature, not digital_signature, False, False, False, False, False,
                                          False, False), critical=True)
             .add_extension(x509.SubjectAlternativeName(sans or [x509.DNSName(f"{cn.lower().replace(' ', '-')}.test.invalid")]),
                            critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ikey.public_key()), critical=False)
             .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                 [x509.UniformResourceIdentifier(CRL_URL)], None, None, None)]), critical=False)
             .add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
                 AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL))]), critical=False))
        if client_auth:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        if mldsa_public is not None:
            b = b.add_extension(mldsa_binding_extension(mldsa_public), critical=False)
        cert = b.sign(ikey, hashes.SHA384())
        self.issued[cert.serial_number] = (cert, issuer, ikey)
        return cert, key

    def credential(self, cert: x509.Certificate, mldsa_public: bytes | None = None) -> Credential:
        chain = [] if cert.issuer == self.root.subject else [self.intermediate]
        return Credential(cert, chain, mldsa_public)

    def identity(self, cn: str, *, email: str | None = None, uri: str | None = None, dns: str | None = None,
                 pq: bool = False, key: Any = None, provider: Any = None, **kw):
        """A certified identity in one call: ``(Credential, PrivateKeySet)``. ``pq=True`` adds an ML-DSA-65 key
        bound by the certificate extension (needs a PQ backend)."""
        from .crypto.provider import default_provider
        provider = provider or default_provider()
        mldsa_priv = mldsa_raw = None
        if pq:
            be = provider.require_pq()
            mldsa_priv = be.generate()
            mldsa_raw = be.public_raw(be.public_of(mldsa_priv))
        cert, priv = self.issue(cn, email=email, uri=uri, dns=dns, key=key, mldsa_public=mldsa_raw, **kw)
        return self.credential(cert, mldsa_raw), signing_keyset(priv, mldsa_priv, provider)

    def revoke(self, cert: x509.Certificate) -> None:
        self.revoked.add(cert.serial_number)

    def crl(self, *, by_root: bool = False, next_update_days: int = 7, last_update: _dt.datetime | None = None):
        issuer, ikey = (self.root, self.root_key) if by_root else (self.intermediate, self.intermediate_key)
        last = last_update or (self.now - _dt.timedelta(hours=1))
        b = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
             .last_update(last).next_update(last + _dt.timedelta(days=next_update_days)))
        for serial, (cert, iss, _) in self.issued.items():
            if serial in self.revoked and iss.subject == issuer.subject:
                b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial)
                                              .revocation_date(last).build())
        return b.sign(ikey, hashes.SHA384())

    def crls(self) -> list:
        return [self.crl(), self.crl(by_root=True)]

    def ocsp_fetcher(self, *, unreachable: bool = False):
        """An in-memory OCSP responder: ``fetch(url, request_der) -> response_der``. The issuing CA signs."""
        def fetch(url: str, req_der: bytes) -> bytes:
            if unreachable:
                raise ConnectionError("test OCSP responder is unreachable")
            req = ocsp.load_der_ocsp_request(req_der)
            entry = self.issued.get(req.serial_number)
            if entry is None:
                return ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(
                    _DER)
            cert, issuer, ikey = entry
            revoked = req.serial_number in self.revoked
            b = ocsp.OCSPResponseBuilder().add_response(
                cert=cert, issuer=issuer, algorithm=req.hash_algorithm,
                cert_status=ocsp.OCSPCertStatus.REVOKED if revoked else ocsp.OCSPCertStatus.GOOD,
                this_update=self.now - _dt.timedelta(minutes=1), next_update=self.now + _dt.timedelta(days=1),
                revocation_time=self.now - _dt.timedelta(minutes=30) if revoked else None,
                revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, issuer)
            return b.sign(ikey, hashes.SHA384()).public_bytes(_DER)
        return fetch

    def config(self, role_map: Mapping[str, Any], *, ocsp: bool = False, crl: bool = True, **kw) -> PkiConfig:
        """A PkiConfig trusting this root: CRLs in memory (default) and/or the in-memory OCSP responder."""
        kw.setdefault("revocation", "ocsp_then_crl")
        return PkiConfig(trust_anchors=[self.root], crls=self.crls() if crl else [],
                         ocsp_fetcher=self.ocsp_fetcher() if ocsp else None, role_map=role_map, **kw)


from cryptography.hazmat.primitives.serialization import Encoding as _Enc  # noqa: E402

_DER = _Enc.DER


class SoftwareToken(Pkcs11Token):
    """A fake PKCS#11 token holding software keys, with the token's raw output formats. Test double only."""
    is_test_double = True

    def __init__(self):
        self._keys: dict[str, Any] = {}
        self.calls: list[tuple[str, str]] = []

    def generate(self, label: str, kind: str = "p384") -> Pkcs11PrivateKey:
        self._keys[label] = ec.generate_private_key(ec.SECP384R1()) if kind == "p384" else \
            ed25519.Ed25519PrivateKey.generate()
        return Pkcs11PrivateKey(self, label)

    def public_key(self, label: str):
        return self._keys[label].public_key()

    def sign(self, label: str, mechanism: str, data: bytes) -> bytes:
        self.calls.append((label, mechanism))
        k = self._keys[label]
        if mechanism == "EDDSA":
            return k.sign(data)
        if mechanism == "ECDSA":  # CKM_ECDSA over a SHA-384 digest; raw r || s
            r, s = decode_dss_signature(k.sign(data, ec.ECDSA(Prehashed(hashes.SHA384()))))
            n = (k.curve.key_size + 7) // 8
            return r.to_bytes(n, "big") + s.to_bytes(n, "big")
        raise ValueError(f"mechanism {mechanism} not supported")

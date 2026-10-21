# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""A throwaway certificate authority for the SIEM sink tests. Offline: nothing is fetched or published.

``test_ca(dir)`` writes a CA certificate, a server certificate for 127.0.0.1 and localhost, and a client
certificate, all signed by that CA, and returns their paths. The keys are Ed25519 where the TLS stack takes
them and RSA otherwise; this module uses ECDSA (P-256), which every supported OpenSSL accepts for TLS 1.2
and 1.3.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DAY = datetime.timedelta(days=1)


@dataclass(frozen=True)
class Certificates:
    ca_file: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    other_ca_file: Path


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) - DAY


def _authority(common: str):
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (x509.CertificateBuilder()
                   .subject_name(_name(common)).issuer_name(_name(common))
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(_now()).not_valid_after(_now() + 30 * DAY)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                                  critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                                content_commitment=False, key_encipherment=False,
                                                data_encipherment=False, key_agreement=False,
                                                encipher_only=False, decipher_only=False), critical=True)
                   .sign(key, hashes.SHA256()))
    return key, certificate


def _issued(ca_key, ca_cert, common: str, *, server: bool):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (x509.CertificateBuilder()
               .subject_name(_name(common)).issuer_name(ca_cert.subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(_now()).not_valid_after(_now() + 30 * DAY)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                            content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                              critical=False)
               .add_extension(x509.ExtendedKeyUsage(
                   [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if server
                    else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                         x509.DNSName("localhost"), x509.DNSName(common)]), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def _write(path: Path, *, key=None, certificate=None) -> None:
    data = b""
    if certificate is not None:
        data += certificate.public_bytes(serialization.Encoding.PEM)
    if key is not None:
        data += key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    path.write_bytes(data)
    os.chmod(path, 0o600)


def test_ca(directory: Path | str, common: str = "siem.test") -> Certificates:
    """Write the CA, a server certificate (127.0.0.1, localhost, ``common``), and a client certificate."""
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = _authority("two-key test CA")
    other_key, other_cert = _authority("two-key other CA")
    server_key, server_cert = _issued(ca_key, ca_cert, common, server=True)
    client_key, client_cert = _issued(ca_key, ca_cert, "two-key client", server=False)
    paths = Certificates(out / "ca.pem", out / "server.pem", out / "server.key",
                         out / "client.pem", out / "client.key", out / "other-ca.pem")
    _write(paths.ca_file, certificate=ca_cert)
    _write(paths.other_ca_file, certificate=other_cert)
    _write(paths.server_cert, certificate=server_cert)
    _write(paths.server_key, key=server_key)
    _write(paths.client_cert, certificate=client_cert)
    _write(paths.client_key, key=client_key)
    del other_key
    return paths

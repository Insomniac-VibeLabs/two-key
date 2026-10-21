# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Where an endpoint really is, from its URL host. Never from a declared flag.

Both checks use an explicit allowlist, not ``ipaddress``'s ``is_private``
(which also covers documentation, benchmark, reserved, and NAT64 ranges).

``host_is_loopback`` accepts ``localhost``, 127.0.0.0/8, and ::1.
``host_is_local`` also accepts the RFC 1918 ranges (10.0.0.0/8,
172.16.0.0/12, 192.168.0.0/16) and IPv6 unique-local fc00::/7. An
IPv4-mapped IPv6 literal (::ffff:a.b.c.d) is judged by its IPv4 address.
Everything else is not local, including documentation (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32), benchmark (198.18.0.0/15),
reserved (240.0.0.0/4), shared/CGNAT (100.64.0.0/10), link-local
(169.254.0.0/16, a cloud metadata service; fe80::/10), unspecified,
multicast, and NAT64 (64:ff9b::/96, which reaches the public IPv4 internet).
A DNS name other than ``localhost`` is not local, even if it resolves to a
private address today: names can be repointed.

``model_is_cloud`` marks a model id ending in ``:cloud`` or ``-cloud`` (an
Ollama cloud model, run by ollama.com even when the local daemon proxies it).
Such a judge or agent is cloud and never local, whatever its host.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

_CLOUD_MODEL = re.compile(r"[:-]cloud$")

LOOPBACK_NAMES = {"localhost"}


def url_host(url: str | None) -> str:
    try:
        return (urlparse(url or "").hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
LOCAL_NETWORKS = LOOPBACK_NETWORKS + (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def _unmapped(ip):
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _in(ip, nets) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def host_is_loopback(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if host in LOOPBACK_NAMES:
        return True
    ip = _ip(host)
    return ip is not None and _in(_unmapped(ip), LOOPBACK_NETWORKS)


def host_is_local(host: str) -> bool:
    if host_is_loopback(host):
        return True
    ip = _ip((host or "").lower().rstrip("."))
    return ip is not None and _in(_unmapped(ip), LOCAL_NETWORKS)


_DASHES = re.compile(r"[\u2010-\u2015\u2212\u2043\u2e3a\u2e3b\ufe58\ufe63\uff0d]")
_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\u2060\ufeff\u00ad]")


def fold_model_id(model: str | None) -> str:
    """NFKC, lower case, Unicode dashes folded to ``-``, zero-width characters dropped, trimmed."""
    m = unicodedata.normalize("NFKC", model or "")
    m = _ZERO_WIDTH.sub("", _DASHES.sub("-", m))
    return m.strip().lower()


def model_is_cloud(model: str | None) -> bool:
    """True for a model id ending in ``:cloud`` or ``-cloud`` (case and Unicode forms folded)."""
    return bool(_CLOUD_MODEL.search(fold_model_id(model)))

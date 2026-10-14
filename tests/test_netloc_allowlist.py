"""Locality is an explicit allowlist (127/8, ::1, RFC 1918, fc00::/7), not ipaddress.is_private."""

import unittest

from two_key.judges.openai_compat import OpenAICompatibleJudge
from two_key.netloc import host_is_local, host_is_loopback

LOCAL = ["localhost", "127.0.0.1", "127.9.9.9", "::1", "[::1]", "::ffff:127.0.0.1",
         "10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.1", "fc00::1", "fd12:3456::1", "::ffff:10.0.0.1"]
NOT_LOCAL = {
    "documentation": ["192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:db8::1", "::ffff:192.0.2.1"],
    "benchmark": ["198.18.0.1", "198.19.255.1"],
    "reserved": ["240.0.0.1", "255.255.255.254"],
    "shared/CGNAT": ["100.64.0.1"],
    "link-local": ["169.254.169.254", "fe80::1"],
    "NAT64": ["64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::1"],
    "6to4/Teredo": ["2002:a00:1::1", "2001::1"],
    "unspecified/multicast": ["0.0.0.0", "::", "224.0.0.1", "ff02::1"],  # skipcq: BAN-B104 -- hostname fixture for the address classifier, not a bind
    "outside RFC 1918": ["172.32.0.1", "172.15.255.1", "11.0.0.1"],
    "public": ["8.8.8.8", "2606:4700::1111"],
    "names": ["example.local", "localhost.example.com", "my-gpu-box"],
}


class Allowlist(unittest.TestCase):
    def test_local(self):
        for h in LOCAL:
            self.assertTrue(host_is_local(h), h)

    def test_not_local(self):
        for kind, hosts in NOT_LOCAL.items():
            for h in hosts:
                self.assertFalse(host_is_local(h), f"{kind}: {h}")
                self.assertFalse(host_is_loopback(h), f"{kind}: {h}")

    def test_loopback_is_only_127_and_1(self):
        for h in ("10.0.0.5", "192.168.1.1", "fd00::1"):
            self.assertFalse(host_is_loopback(h), h)

    def test_judge_on_a_documentation_address_is_not_local(self):
        for url in ("https://192.0.2.10:8000/v1", "https://[64:ff9b::a00:1]:8000/v1", "https://198.18.0.5/v1"):
            self.assertFalse(OpenAICompatibleJudge("j", "openai", "m", url, local_weights=True).is_local(), url)
        # Not local, so plain HTTP to it is refused as for any remote endpoint.
        with self.assertRaisesRegex(ValueError, "refusing plain-HTTP"):
            OpenAICompatibleJudge("j", "openai", "m", "http://192.0.2.10:8000/v1")
        self.assertTrue(OpenAICompatibleJudge("j", "openai", "m", "http://10.1.2.3:8000/v1", allow_insecure_http=True,
                                                    local_weights=True).is_local())


if __name__ == "__main__":
    unittest.main(verbosity=2)

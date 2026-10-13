"""#45: the gateway runs in the TwoKey process, on the TwoKey ledger object. A split gateway is unsupported."""

import tempfile
import unittest
import warnings
from pathlib import Path

from two_key import gateway as gateway_mod
from two_key.capability import CapabilityVerifier, TokenError
from two_key.constitution import sign_constitution, verify_signed
from two_key.core import TwoKey, TwoKeyConfigError
from two_key.gateway import ToolGateway, TwoKeyDeploymentWarning
from two_key.keys import generate_private_key
from two_key.ledger import Ledger
from two_key.quorum import QuorumPolicy
from two_key.testing import TEST_AGENT, FixedJudge

RULES = [{"id": "tools", "allow_only_tools": ["search"]}]
SPECS = {"search": {"irreversible": False, "data_class_floor": "public", "payload": [{"json_path": "q"}]}}
SEARCH = {"tool": "search", "data_class": "public", "irreversible": False}
ROOT = Path(__file__).resolve().parent.parent


class GatewayBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = generate_private_key()
        self.path = Path(self.tmp.name, "ledger")
        self.env = sign_constitution("Searching is fine.", RULES, self.key, SPECS)
        self.tk = self._two_key(private_key=self.key)
        gateway_mod._reset_deployment_warning()
        self.addCleanup(gateway_mod._reset_deployment_warning)
        self.calls = []

    def _two_key(self, **kw):
        return TwoKey(Ledger(self.path, self.key), self.key.public_key(),
                      verify_signed(self.env, self.key.public_key()), [FixedJudge("a", "yes")],
                      quorum=QuorumPolicy(required_yes=1), allow_test_doubles=True, monitored_agent=TEST_AGENT, **kw)

    def _tool(self, args):
        self.calls.append(args)
        return "ok"

    def test_helper_gateway_verifies_only_and_shares_the_ledger(self):
        gw = self.tk.gateway(tools={"search": self._tool})
        self.assertIs(gw.ledger, self.tk.ledger)
        self.assertIs(gw.compiled, self.tk.compiled)
        self.assertIsInstance(gw.issuer, CapabilityVerifier)
        self.assertIsNone(getattr(gw.issuer, "private_key", None))
        with self.assertRaises(TokenError):
            gw.issuer.issue(tool="search", arguments={})
        d = self.tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.assertTrue(gw.invoke(d.token, "search", {"q": "weather"}).allowed)
        self.assertEqual(self.calls, [{"q": "weather"}])

    def test_helper_refuses_without_an_issuer(self):
        keyless = tempfile.TemporaryDirectory()
        self.addCleanup(keyless.cleanup)
        self.path = Path(keyless.name, "ledger")
        tk = self._two_key()
        with self.assertRaises(TwoKeyConfigError):
            tk.gateway(tools={"search": self._tool})

    def test_no_warning_on_the_two_key_ledger(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.tk.gateway(tools={"search": self._tool})
            ToolGateway(self.tk.ledger, self.tk.issuer.verifier(), self.tk.compiled, tools={})
        self.assertEqual([w for w in caught if issubclass(w.category, TwoKeyDeploymentWarning)], [])

    def test_separately_opened_ledger_warns_once_and_fails_closed(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            other = Ledger(self.path, self.key)        # what a gateway-only process would open
            gw = ToolGateway(other, self.tk.issuer.verifier(), self.tk.compiled, tools={"search": self._tool})
            ToolGateway(Ledger(self.path, self.key), self.tk.issuer.verifier(), self.tk.compiled, tools={})
        ours = [w for w in caught if issubclass(w.category, TwoKeyDeploymentWarning)]
        self.assertEqual(len(ours), 1)                  # at most once per process
        self.assertIn("TwoKey.gateway()", str(ours[0].message))
        # A token issued after the separate ledger opened is refused, and the tool never runs.
        d = self.tk.authorize(SEARCH, {"q": "weather"}, "look")
        self.assertTrue(d.allowed, d.reason)
        r = gw.invoke(d.token, "search", {"q": "weather"})
        self.assertFalse(r.allowed)
        self.assertTrue(r.reason.startswith(("ledger_size_invalid", "ledger_failed")), r.reason)
        self.assertEqual(self.calls, [])
        # The supported gateway still redeems it.
        self.assertTrue(self.tk.gateway(tools={"search": self._tool}).invoke(d.token, "search",
                                                                            {"q": "weather"}).allowed)

    def test_warning_can_be_made_an_error(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", TwoKeyDeploymentWarning)
            with self.assertRaises(TwoKeyDeploymentWarning):
                ToolGateway(Ledger(self.path, self.key), self.tk.issuer.verifier(), self.tk.compiled, tools={})


class DeploymentDocs(unittest.TestCase):
    """The docs must not promise a gateway in its own process or host (#45)."""

    FILES = ("README.md", "docs/HOWTO.md", "SECURITY.md", "docs/THREAT_MODEL.md", "docs/SCOPE.md",
             "docs/JUDGES_AND_QUORUM.md", "docs/FIT.md", "llms.txt", "AGENTS.md")
    STALE = ("designed, not built", "designed, not yet built", "designed but not yet built",
             "designed but not yet implemented", "meant to run in its own process",
             "intended setup puts the gateway in its own process")

    def test_no_split_gateway_promise(self):
        for name in self.FILES:
            text = " ".join((ROOT / name).read_text(encoding="utf-8").split())
            for phrase in self.STALE:
                self.assertFalse(phrase in text, f"{name}: {phrase!r}")

    def test_boundary_is_stated(self):
        for name in ("README.md", "docs/HOWTO.md", "SECURITY.md", "docs/THREAT_MODEL.md"):
            text = " ".join((ROOT / name).read_text(encoding="utf-8").split())
            self.assertTrue("not supported" in text, name)
            self.assertTrue("TwoKey.gateway()" in text, name)


if __name__ == "__main__":
    unittest.main()

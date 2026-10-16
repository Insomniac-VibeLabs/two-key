"""judges.yaml callback hooks take the same ``module:function`` form as proxy.yaml fact hooks."""

import unittest

from two_key.judges.config import HOOK, JudgeConfigError, build_credential
from two_key.mcp_proxy import config as proxy_config


class HookSpec(unittest.TestCase):
    def test_one_pattern_for_both_configs(self):
        self.assertIs(proxy_config.HOOK, HOOK)

    def test_malformed_specs_are_refused_before_import(self):
        for spec in ["m", "m:", ":f", "m:f:g", "m.:f", ".m:f", "m..n:f", "m:f.g", "m-n:f", "m:f()",
                     "os:system; x", " m:f", "m:f ", "../m:f", "1m:f", 7, None]:
            with self.subTest(spec=spec):
                with self.assertRaisesRegex(JudgeConfigError, "hook must be 'module:function'"):
                    build_credential({"type": "callback", "callback": spec})

    def test_a_long_spec_is_cut_in_the_message(self):
        with self.assertRaises(JudgeConfigError) as cm:
            build_credential({"type": "callback", "callback": "x" * 5000})
        self.assertLess(len(str(cm.exception)), 200)

    def test_well_formed_spec_loads(self):
        cred = build_credential({"type": "callback", "callback": "os.path:join"})
        self.assertIsNotNone(cred)

    def test_well_formed_but_missing_module_is_refused(self):
        with self.assertRaisesRegex(JudgeConfigError, "cannot import hook"):
            build_credential({"type": "callback", "callback": "no_such_module_tk.sub:fn"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

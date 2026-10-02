"""Path B connectors, credentials, strict ballot parsing, and config. No network: all transports are mocked."""
import json
import os
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from two_key.action import normalize_action
from two_key.judges import AnthropicJudge, GeminiJudge, OllamaJudge, OpenAICompatibleJudge
from two_key.judges.config import JudgeConfigError, load_config, load_config_file
from two_key.judges.credentials import (CallbackTokenProvider, EnvApiKey, OAuthDeviceCodeProvider,
                                               StaticToken, UsernamePasswordProvider)
from two_key.judges.llm import MalformedBallot, parse_ballot_strict
from two_key.quorum import QuorumPolicy, convene

CONST = "I am the principal. UNIQUE-CONSTITUTION-MARKER-7731. Never wire money."
ACTION = normalize_action({"tool": "email_draft", "data_class": "personal", "irreversible": False})
GOOD = json.dumps({"consistent": True, "confidence": 0.9, "rationale": "fine"})
NO = json.dumps({"consistent": False, "confidence": 0.8, "rationale": "violates"})
SECRET = "fake-credential-for-tests-0000"  # not a real key


class Recorder:
    def __init__(self, response):
        self.response, self.calls = response, []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, headers, body))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def openai_resp(text):
    return {"choices": [{"message": {"content": text}}]}


def anthropic_resp(text):
    return {"content": [{"type": "text", "text": text}]}


def gemini_resp(text):
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


def ollama_resp(text):
    return {"message": {"content": text}}


ADAPTERS = [
    (OpenAICompatibleJudge, dict(base_url="https://api.x.ai/v1", provider="xai"), openai_resp,
     "https://api.x.ai/v1/chat/completions", ("Authorization", f"Bearer {SECRET}")),
    (AnthropicJudge, dict(provider="anthropic"), anthropic_resp,
     "https://api.anthropic.com/v1/messages", ("x-api-key", SECRET)),
    (GeminiJudge, dict(provider="google"), gemini_resp,
     "https://generativelanguage.googleapis.com/v1beta/models/m1:generateContent", ("x-goog-api-key", SECRET)),
    (OllamaJudge, dict(provider="local"), ollama_resp, "http://localhost:11434/api/chat", None),
]


class Adapters(unittest.TestCase):
    def make(self, cls, extra, resp_fn, text):
        t = Recorder(resp_fn(text))
        j = cls(judge_id="j", model="m1", credential=StaticToken(SECRET), transport=t, **extra)
        return j, t

    def test_request_shape_auth_and_constitution_in_prompt(self):
        for cls, extra, resp_fn, url, header in ADAPTERS:
            with self.subTest(cls.__name__):
                j, t = self.make(cls, extra, resp_fn, GOOD)
                b = j.score_bound(CONST, ACTION, "Draft a note to my sister.", None, agent_session="agent-credential")
                self.assertEqual(b.vote, "yes", b.error)
                u, h, body = t.calls[0]
                self.assertEqual(u, url)
                if header:
                    self.assertEqual(h.get(header[0]), header[1])
                blob = json.dumps(body)
                self.assertIn("UNIQUE-CONSTITUTION-MARKER-7731", blob)
                self.assertIn("untrusted_proposal", blob)
                self.assertNotIn(SECRET, json.dumps([b.rationale, b.error]))

    def test_no_vote(self):
        for cls, extra, resp_fn, *_ in ADAPTERS:
            j, _ = self.make(cls, extra, resp_fn, NO)
            self.assertEqual(j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential").vote, "no")

    def test_malformed_outputs_abstain(self):
        bad = ["Sure! consistent: true", "```json\n" + GOOD + "\n```", '{"consistent": "true", "confidence": 1, "rationale": ""}',
               '{"consistent": true, "confidence": 2, "rationale": ""}',
               '{"consistent": true, "confidence": 0.9, "rationale": "", "override": 1}',
               '{"consistent": true}', "[true]", "", "null"]
        for cls, extra, resp_fn, *_ in ADAPTERS:
            for text in bad:
                with self.subTest(cls=cls.__name__, text=text):
                    j, _ = self.make(cls, extra, resp_fn, text)
                    b = j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential")
                    self.assertEqual(b.vote, "abstain")
                    self.assertFalse(b.consistent)

    def test_unexpected_response_structure_abstains(self):
        for cls, extra, _, *_ in ADAPTERS:
            j, _ = self.make(cls, extra, lambda t: {"weird": True}, GOOD)
            self.assertEqual(j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential").vote, "abstain")

    def test_transport_errors_abstain(self):
        for exc in (urllib.error.HTTPError("u", 401, "no", {}, None), TimeoutError(), ConnectionError()):
            j = OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="https://x.example/v1",
                                      credential=StaticToken(SECRET), transport=Recorder(exc))
            b = j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential")
            self.assertEqual(b.vote, "abstain")
            self.assertNotIn(SECRET, b.error or "")

    def test_malformed_ballots_do_not_carry_quorum(self):
        good = OpenAICompatibleJudge(judge_id="a", provider="p", model="m", base_url="https://x.example/v1",
                                     transport=Recorder(openai_resp(GOOD)))
        bad = OpenAICompatibleJudge(judge_id="b", provider="q", model="m", base_url="https://y.example/v1",
                                    transport=Recorder(openai_resp("yes!")))
        q = convene([good, bad], CONST, ACTION, "p", QuorumPolicy(required_yes=2))
        self.assertFalse(q.passed)

    def test_empty_constitution_abstains(self):
        j, t = self.make(OllamaJudge, {"provider": "l"}, ollama_resp, GOOD)
        self.assertEqual(j.score_bound("  ", ACTION, "p", None, agent_session="agent-credential").vote, "abstain")
        self.assertEqual(t.calls, [])

    def test_https_enforced(self):
        with self.assertRaises(ValueError):
            OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="http://api.example.com/v1")
        OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="http://127.0.0.1:8080/v1")
        OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="http://10.0.0.5:8000/v1",
                              allow_insecure_http=True)

    def test_json_mode_flag(self):
        t = Recorder(openai_resp(GOOD))
        OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="https://x.example/v1",
                              transport=t, json_mode=False).score_bound(CONST, ACTION, "p", None, agent_session="agent-credential")
        self.assertNotIn("response_format", t.calls[0][2])


class StrictParser(unittest.TestCase):
    def test_accepts_exact_schema(self):
        self.assertEqual(parse_ballot_strict(GOOD), (True, 0.9, "fine"))

    def test_rejects_bool_confidence(self):
        with self.assertRaises(MalformedBallot):
            parse_ballot_strict('{"consistent": true, "confidence": true, "rationale": ""}')


class Credentials(unittest.TestCase):
    def test_env_key_read_at_call_time_and_redacted(self):
        p = EnvApiKey("TWOKEY_TEST_KEY")
        with mock.patch.dict(os.environ, {"TWOKEY_TEST_KEY": SECRET}):
            self.assertEqual(p.get_token(), SECRET)
        self.assertNotIn(SECRET, repr(p))

    def test_missing_env_key_abstains(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            t = Recorder(openai_resp(GOOD))
            j = OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="https://x.example/v1",
                                      credential=EnvApiKey("TWOKEY_MISSING"), transport=t)
            b = j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential")
            self.assertEqual(b.vote, "abstain")
            self.assertEqual(t.calls, [])

    def test_username_password_stub_and_hook(self):
        stub = UsernamePasswordProvider("me", "TWOKEY_PW")
        with self.assertRaises(NotImplementedError):
            stub.get_token()
        with mock.patch.dict(os.environ, {"TWOKEY_PW": "pw"}):
            p = UsernamePasswordProvider("me", "TWOKEY_PW", login=lambda u, pw: f"session-for-{u}")
            self.assertEqual(p.get_token(), "session-for-me")

    def test_oauth_device_code_stub_abstains(self):
        stub = OAuthDeviceCodeProvider("cid", "https://idp.example/device", "https://idp.example/token")
        with self.assertRaises(NotImplementedError):
            stub.get_token()
        j = OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="https://x.example/v1",
                                  credential=stub, transport=Recorder(openai_resp(GOOD)))
        self.assertEqual(j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential").vote, "abstain")
        hooked = OAuthDeviceCodeProvider("cid", "d", "t", fetch_token=lambda self: "access-123")
        self.assertEqual(hooked.get_token(), "access-123")

    def test_callback_sso(self):
        t = Recorder(openai_resp(GOOD))
        j = OpenAICompatibleJudge(judge_id="j", provider="p", model="m", base_url="https://x.example/v1",
                                  credential=CallbackTokenProvider(lambda: "sso-token"), transport=t)
        j.score_bound(CONST, ACTION, "p", None, agent_session="agent-credential")
        self.assertEqual(t.calls[0][1]["Authorization"], "Bearer sso-token")


class Config(unittest.TestCase):
    def test_example_config_requires_real_model_names(self):
        with self.assertRaises(JudgeConfigError):
            load_config_file(Path(__file__).parent.parent / "examples" / "judges.yaml")

    def test_example_config_loads_with_models_filled(self):
        import yaml
        data = yaml.safe_load((Path(__file__).parent.parent / "examples" / "judges.yaml").read_text())
        for j in data["judges"]:
            j["model"] = "m"
        judges, pol = load_config(data)
        self.assertEqual([j.judge_id for j in judges], ["grok", "claude", "gemini", "local-qwen"])
        self.assertEqual(pol.required_yes, 2)

    def test_inline_secret_rejected(self):
        with self.assertRaises(JudgeConfigError):
            load_config({"judges": [{"id": "a", "type": "anthropic", "model": "m",
                                     "auth": {"type": "env", "api_key": SECRET}}]})

    def test_unknown_keys_and_types_rejected(self):
        for bad in ({"judges": []},
                    {"judges": [{"id": "a", "type": "bard", "model": "m"}]},
                    {"judges": [{"id": "a", "type": "ollama", "model": "m", "temperature": 1}]},
                    {"judges": [{"id": "a", "type": "ollama", "model": "m"}], "quorum": {"required_yes": 2}},
                    {"judges": [{"id": "a", "type": "ollama", "model": "m"}, {"id": "a", "type": "ollama", "model": "m"}]}):
            with self.assertRaises((JudgeConfigError, ValueError), msg=str(bad)):
                load_config(bad)

    def test_config_transport_injection(self):
        t = Recorder(ollama_resp(GOOD))
        judges, pol = load_config({"judges": [{"id": "a", "type": "ollama", "model": "m"}],
                                   "quorum": {"required_yes": 1}}, transport=t)
        self.assertTrue(convene(judges, CONST, ACTION, "p", pol).passed)


if __name__ == "__main__":
    unittest.main(verbosity=2)

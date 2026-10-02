"""Judge transport and provider request tweaks. No network except loopback."""
import json
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from two_key.action import normalize_action
from two_key.judges import AnthropicJudge, GeminiJudge, OpenAICompatibleJudge
from two_key.judges.credentials import StaticToken
from two_key.judges.transport import pooled_transport, reset_pool

CONST = "I am the principal. UNIQUE-CONSTITUTION-MARKER-7731. Never wire money."
ACTION = normalize_action({"tool": "email_draft", "data_class": "personal", "irreversible": False})
GOOD = json.dumps({"consistent": True, "confidence": 0.9, "rationale": "fine"})
SECRET = "fake-credential-for-tests-0000"


class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def openai_resp(text):
    return {"choices": [{"message": {"content": text}}]}


class RequestShape(unittest.TestCase):
    def test_openai_cloud_uses_schema_and_does_not_store(self):
        t = Recorder([openai_resp(GOOD)])
        OpenAICompatibleJudge(judge_id="j", provider="openai", model="m",
                              base_url="https://api.openai.com/v1", credential=StaticToken(SECRET),
                              transport=t).score_bound(CONST, ACTION, "p", None, agent_session="agent")
        body = t.calls[0][2]
        self.assertEqual(body["response_format"]["type"], "json_schema")
        self.assertTrue(body["response_format"]["json_schema"]["strict"])
        self.assertFalse(body["response_format"]["json_schema"]["schema"]["additionalProperties"])
        self.assertIs(body["store"], False)
        self.assertNotIn("reasoning_effort", body)

    def test_xai_uses_schema_and_low_reasoning(self):
        t = Recorder([openai_resp(GOOD)])
        OpenAICompatibleJudge(judge_id="j", provider="xai", model="m",
                              base_url="https://api.x.ai/v1", credential=StaticToken(SECRET),
                              transport=t).score_bound(CONST, ACTION, "p", None, agent_session="agent")
        body = t.calls[0][2]
        self.assertEqual(body["response_format"]["type"], "json_schema")
        self.assertEqual(body["reasoning_effort"], "low")
        self.assertNotIn("store", body)

    def test_local_server_stays_on_json_object(self):
        t = Recorder([openai_resp(GOOD)])
        OpenAICompatibleJudge(judge_id="j", provider="local", model="m",
                              base_url="https://llm.internal/v1", credential=StaticToken(SECRET),
                              transport=t).score_bound(CONST, ACTION, "p", None, agent_session="agent")
        self.assertEqual(t.calls[0][2]["response_format"], {"type": "json_object"})

    def test_schema_400_falls_back_once(self):
        t = Recorder([urllib.error.HTTPError("u", 400, "schema", {}, None), openai_resp(GOOD)])
        b = OpenAICompatibleJudge(judge_id="j", provider="xai", model="m",
                                  base_url="https://api.x.ai/v1", credential=StaticToken(SECRET),
                                  transport=t).score_bound(CONST, ACTION, "p", None, agent_session="agent")
        self.assertEqual(b.vote, "yes", b.error)
        self.assertEqual(t.calls[1][2]["response_format"], {"type": "json_object"})
        self.assertNotIn("reasoning_effort", t.calls[1][2])
        self.assertGreaterEqual(t.calls[0][3], t.calls[1][3])

    def test_auth_failure_is_not_retried_by_fallback(self):
        t = Recorder([urllib.error.HTTPError("u", 401, "no", {}, None)])
        b = OpenAICompatibleJudge(judge_id="j", provider="xai", model="m",
                                  base_url="https://api.x.ai/v1", credential=StaticToken(SECRET),
                                  transport=t).score_bound(CONST, ACTION, "p", None, agent_session="agent")
        self.assertEqual(b.vote, "abstain")
        self.assertEqual(len(t.calls), 1)

    def test_anthropic_caches_trusted_prefix_only(self):
        t = Recorder([{"content": [{"type": "text", "text": GOOD}]}])
        AnthropicJudge(judge_id="j", provider="anthropic", model="m",
                       credential=StaticToken(SECRET), transport=t).score_bound(
            CONST, ACTION, "Draft a note.", None, agent_session="agent")
        body = t.calls[0][2]
        self.assertEqual(body["system"][0]["cache_control"], {"type": "ephemeral"})
        blocks = body["messages"][0]["content"]
        self.assertEqual(blocks[0]["cache_control"], {"type": "ephemeral"})
        self.assertIn("UNIQUE-CONSTITUTION-MARKER-7731", blocks[0]["text"])
        self.assertNotIn("untrusted_action_record", blocks[0]["text"])
        self.assertNotIn("cache_control", blocks[1])
        self.assertIn("untrusted_action_record", blocks[1]["text"])
        self.assertNotIn("anthropic-beta", t.calls[0][1])

    def test_gemini_schema_is_dropped_on_400(self):
        t = Recorder([urllib.error.HTTPError("u", 400, "schema", {}, None),
                      {"candidates": [{"content": {"parts": [{"text": GOOD}]}}]}])
        b = GeminiJudge(judge_id="j", provider="google", model="m",
                        credential=StaticToken(SECRET), transport=t).score_bound(
            CONST, ACTION, "p", None, agent_session="agent")
        self.assertEqual(b.vote, "yes", b.error)
        self.assertIn("responseSchema", t.calls[0][2]["generationConfig"])
        self.assertNotIn("responseSchema", t.calls[1][2]["generationConfig"])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        state = self.server.state
        state["hits"] += 1
        state["conns"].add(id(self.connection))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://evil.example/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if state["hits"] == 1 and state.get("fail_once"):
            body = b'{"error":"busy"}'
            self.send_response(503)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        body = json.dumps({"choices": [{"message": {"content": GOOD}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class PooledTransport(unittest.TestCase):
    def setUp(self):
        reset_pool()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.state = {"hits": 0, "conns": set(), "fail_once": False}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/chat/completions"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        reset_pool()

    def test_retries_transient_then_reuses_connection(self):
        self.server.state["fail_once"] = True
        first = pooled_transport(self.url, {"Authorization": "Bearer t"}, {"model": "m"}, 5)
        second = pooled_transport(self.url, {"Authorization": "Bearer t"}, {"model": "m"}, 5)
        self.assertEqual(first["choices"][0]["message"]["content"], GOOD)
        self.assertEqual(second["choices"][0]["message"]["content"], GOOD)
        self.assertEqual(self.server.state["hits"], 3)
        self.assertGreaterEqual(len(self.server.state["conns"]), 1)

    def test_redirect_is_not_followed(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            pooled_transport(self.url.replace("/v1/chat/completions", "/redirect"), {}, {"a": 1}, 5)
        self.assertEqual(cm.exception.code, 302)


if __name__ == "__main__":
    unittest.main()

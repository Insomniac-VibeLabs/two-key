"""Placeholders are refused. A cloud judge cannot reuse the agent's session."""
import unittest

from two_key.judges.config import JudgeConfigError, build_judge
from two_key.judges.openai_compat import OpenAICompatibleJudge


class Token:
    def __init__(self, value):
        self.value = value

    def get_token(self):
        return self.value


class Session(unittest.TestCase):
    def test_placeholder_ballot_key_is_refused(self):
        spec = {"id": "aeacus", "type": "openai_compatible", "provider": "aeacus-local",
                "base_url": "http://127.0.0.1:8765/v1", "model": "aeacus-micro-v1",
                "ballot_key": "REPLACE_WITH_BALLOT_KEY", "allow_insecure_http": True}
        with self.assertRaisesRegex(JudgeConfigError, "REPLACE_WITH_BALLOT_KEY"):
            build_judge(spec)

    def test_cloud_judge_refuses_the_agent_session(self):
        judge = OpenAICompatibleJudge("cloud", "openai", "m", "https://api.openai.com/v1", Token("agent-session"))
        ballot = judge.score_bound("constitution", _action(), "", None, agent_session="agent-session")
        self.assertEqual(ballot.vote, "abstain")
        self.assertIn("cloud_judge_reused_agent_session", ballot.error)

    def test_annotated_judge_may_receive_the_proposal(self):
        judge = OpenAICompatibleJudge("cloud", "openai", "m", "https://api.openai.com/v1", Token("judge-key"),
                                      receives_proposal=True)
        self.assertTrue(judge.receives_proposal)
        self.assertTrue(judge.is_cloud())


def _action():
    from two_key.action import normalize_action
    return normalize_action({"tool": "search", "data_class": "public", "irreversible": False})

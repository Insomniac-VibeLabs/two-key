"""The live harness (tests/live) keeps three promises that nothing else checks, and each breaks silently:

- a sabotage patch (tests/live/sabotage.py) must still match the source it weakens, or the pass would "test" a
  package nothing was done to;
- COVERAGE.md and the case file must agree, or the map in RESULTS.md says more or less than the cases do;
- every deployment-story case must name a step the story actually runs.

None of this needs the MCP SDK, a bot, or the network.
"""
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LIVE = REPO / "tests" / "live"


def load(name):
    spec = importlib.util.spec_from_file_location(f"live_{name}", LIVE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def coverage_rows():
    rows = []
    for line in (LIVE / "COVERAGE.md").read_text(encoding="utf-8").splitlines():
        cells = [x.strip() for x in line.strip().strip("|").split("|")]
        if len(cells) == 5 and re.fullmatch(r"F\d+", cells[0]):
            rows.append(cells)
    return rows


class SabotagePatches(unittest.TestCase):
    def test_every_patch_still_applies_exactly_once(self):
        sabotage = load("sabotage")
        for name in sabotage.PATCHES:
            with self.subTest(patch=name), tempfile.TemporaryDirectory() as tmp:
                dest = sabotage.apply(name, REPO, Path(tmp) / "pkg")
                self.assertTrue((dest / "two_key" / "__init__.py").is_file())

    def test_a_blind_spot_says_why(self):
        sabotage = load("sabotage")
        for name, patch in sabotage.PATCHES.items():
            self.assertTrue(patch.get("what"), name)
            if "blind_spot" in patch:
                self.assertGreater(len(patch["blind_spot"]), 40, f"{name}: say why the harness cannot see it")

    def test_the_repository_is_not_touched(self):
        sabotage = load("sabotage")
        before = (REPO / "two_key" / "core.py").read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            sabotage.apply("path_a_ignored", REPO, Path(tmp) / "pkg")
        self.assertEqual((REPO / "two_key" / "core.py").read_bytes(), before)


class CoverageMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.make = load("make_cases")
        cls.rows = coverage_rows()

    def test_one_row_per_default_and_ids_are_unique(self):
        ids = [r[0] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 20)

    def test_unit_tests_named_exist(self):
        for fid, _default, unit, _live, _note in self.rows:
            for name in re.findall(r"tests/[\w./]+\.py", unit):
                self.assertTrue((REPO / name).is_file(), f"{fid}: {name} does not exist")

    def test_live_column_matches_the_cases(self):
        tagged = {tag for k in self.make.c for tag in k.get("covers", [])}
        for fid, _default, _unit, live, note in self.rows:
            self.assertIn(live, ("yes", "partly", "no"), fid)
            if live == "no":
                self.assertNotIn(fid, tagged, f"{fid} says no live case but a case is tagged with it")
            else:
                self.assertIn(fid, tagged, f"{fid} says {live} but no case is tagged with it")
            if live != "yes":
                self.assertTrue(note, f"{fid}: say what is left to the unit tests")
        self.assertLessEqual(tagged, {r[0] for r in self.rows}, "a case is tagged with a row COVERAGE.md lacks")

    def test_every_default_in_agents_md_is_a_row(self):
        text = (REPO / "AGENTS.md").read_text(encoding="utf-8")
        section = text.split("## Fail-closed defaults to preserve", 1)[1].split("See [CONTRIBUTING.md]", 1)[0]
        bullets = [b for b in re.split(r"\n(?=- )", section) if b.startswith("- ")]
        self.assertLessEqual(len(self.rows), len(bullets) + 4)
        self.assertGreaterEqual(len(self.rows), len(bullets) - 4,
                                "AGENTS.md gained fail-closed defaults COVERAGE.md has no row for")


class Cases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.make = load("make_cases")

    def test_titles_are_unique(self):
        titles = [k["title"] for k in self.make.c]
        self.assertEqual(len(titles), len(set(titles)))

    def test_every_deploy_case_names_a_step_the_story_runs(self):
        story = (LIVE / "deploy_cases.py").read_text(encoding="utf-8")
        steps = [k["step"] for k in self.make.c if k["kind"] == "deploy"]
        self.assertGreater(len(steps), 20)
        self.assertEqual(len(steps), len(set(steps)))
        for step in steps:
            self.assertTrue(f'"{step}"' in story, f"deploy_cases.py never runs a step named {step}")

    def test_every_case_has_an_expectation_the_report_reads(self):
        report = (LIVE / "report.py").read_text(encoding="utf-8")
        for k in self.make.c:
            effect = k["expect"]["effect"]
            self.assertTrue(f'"{effect}"' in report, f"report.py has no verdict for {effect!r} ({k['title']})")

    def test_the_free_play_round_has_no_answer_in_it(self):
        play = [k for k in self.make.c if k["expect"]["effect"] == "invariants"]
        self.assertEqual(len(play), 1)
        self.assertNotIn("reasons", play[0]["expect"])
        self.assertEqual(set(play[0]["persona"].values()), {"EVIL"})


if __name__ == "__main__":
    unittest.main()

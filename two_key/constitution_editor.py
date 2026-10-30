# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""What ``two-key constitution-editor`` does, without a display (the window is two_key/constitution_gui.py).

A constitution is one signed body: the prose every judge reads in full (the judges' prompt text), the hard
rules Path A runs, a spec for each allowed tool, the custom-field registry, and the serial. A :class:`Draft`
holds all five. :func:`check` runs the checks ``sign_constitution`` runs, on the same code
(``constitution.signed_body``), and lists the notes ``two-key sign-constitution`` prints. :func:`sign_and_save`
signs with the principal key and writes three files, each beside its target and then renamed into place:

- the prose (``constitution.md``),
- the rules file (``hard_rules.yaml``: serial, fields, hard_rules, tool_specs), which signs to the same body
  with ``two-key sign-constitution`` and is what ``two-key config set --rules`` needs,
- the signed constitution (``constitution.signed.json``), verified before it is written.

:func:`try_call` signs the draft with a throwaway key and runs one call through ``TwoKey.authorize`` on a
temporary ledger with a stand-in judge that votes yes and keeps the prompt it was sent. It shows what Path A
decides and the exact text a judge would read. Nothing it does touches a real key, ledger, or judge.

Nothing here changes what is signed or how: signing is ``sign_constitution``, verifying is ``verify_signed``.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from . import _platform
from .canonical import canonical_hash
from .constitution import (ENVELOPE_FORMATS, RULES_FILE_KEYS, domain_allow_notes, encrypted_pass_notes,
                           load_envelope, load_serial, load_unsigned_with_fields, save_envelope, sign_constitution,
                           signed_body, verify_signed)
from .fields import case_warnings, not_applicable_notes, path_notes
from .policy_vm import ConstitutionError, RULE_TYPES
from .strict import StrictParseError, load_file_strict, load_yaml, loads_json

ALLOW = "allow_only_tools"
DATA_CLASSES = ("public", "personal", "medical", "financial", "classified")
CLAIMS = ("none", "floor", *DATA_CLASSES, "financial+medical")
FILE_NAMES = {"prose": "constitution.md", "rules": "hard_rules.yaml", "signed": "constitution.signed.json"}
# A starting body for each rule type, for the window's Template button. Use-case agnostic on purpose: the
# tool names and limits are placeholders to replace.
RULE_TEMPLATES: dict[str, Any] = {
    ALLOW: ["TOOL_ID"],
    "deny_if": {"tool": "TOOL_ID"},
    "deny_if_irreversible_over": 100,
    "deny_counterparties": ["blocked.example"],
    "deny_if_fields": {"FIELD_NAME": {"eq": "VALUE"}},
}
SPEC_KEYS = ("irreversible", "data_class_floor", "deny_unmapped")      # the ones the window has controls for
FIELDS_EXAMPLE = {
    "environment": {"type": "enum", "values": ["dev", "staging", "prod"], "default": "dev",
                    "description": "Where the call takes effect."},
}
# What a judge reads before the constitution. Shown with the prompt, never edited here: it is Two-Key's.
NOT_SIGNED_NOTE = ("The judges' system prompt is Two-Key's own and is not part of the constitution; the "
                   "constitution's prose goes into every judge's prompt in full, inside <principal_constitution>.")


WARNING, NOTE = "WARNING", "note"      # the levels sign-constitution prints


class EditorError(ValueError):
    """A file could not be read or written, or a value could not be parsed. Nothing was written."""


def _starter_prose() -> str:
    from .setup_cmd import STARTER_PROSE
    return STARTER_PROSE


@dataclass
class Draft:
    """Everything the constitution signs, as the editor holds it. ``rules`` includes the allow list."""
    prose: str = ""
    rules: list = field(default_factory=list)
    tool_specs: dict = field(default_factory=dict)
    fields: dict = field(default_factory=dict)
    serial: int | None = 1
    envelope_format: str = "auto"

    def copy(self) -> "Draft":
        return copy.deepcopy(self)


def new_draft() -> Draft:
    """A new constitution: the starter prose, an empty allow list, serial 1. It does not sign until a tool is
    added."""
    return Draft(prose=_starter_prose(), rules=[{"id": "tools", ALLOW: []}])


def draft_from(prose: str, document: Mapping) -> Draft:
    """A draft from the prose and a rules-file document (the mapping in ``hard_rules.yaml``)."""
    if not isinstance(document, Mapping):
        raise EditorError("the rules file must be a mapping with hard_rules and tool_specs")
    unknown = sorted(set(document) - set(RULES_FILE_KEYS))
    if unknown:
        raise EditorError(f"unknown rules-file key(s) {unknown}")
    rules, specs, fields = document.get("hard_rules"), document.get("tool_specs"), document.get("fields")
    if not isinstance(rules, list):
        raise EditorError("hard_rules must be a list")
    if not isinstance(specs, Mapping):
        raise EditorError("tool_specs must be a mapping")
    if fields is not None and not isinstance(fields, Mapping):
        raise EditorError("fields must be a mapping")
    return Draft(prose=prose, rules=copy.deepcopy(rules), tool_specs=copy.deepcopy(dict(specs)),
                 fields=copy.deepcopy(dict(fields or {})), serial=document.get("serial"))


def open_sources(prose_path: Path | str, rules_path: Path | str) -> Draft:
    """A draft from a prose file and a rules file, as ``two-key sign-constitution`` reads them."""
    try:
        prose = Path(prose_path).read_text(encoding="utf-8")
        document = load_file_strict(rules_path)
    except (OSError, StrictParseError, UnicodeDecodeError) as e:
        raise EditorError(f"{e}") from None
    except ImportError:
        raise EditorError("reading YAML rules needs the yaml extra (pip install pyyaml)") from None
    return draft_from(prose, document)


def open_signed(path: Path | str, public_key=None) -> tuple[Draft, str]:
    """A draft from a signed constitution, to edit as the next version: the serial goes up by one. With
    ``public_key`` the signature is checked first. Returns the draft and a line that says what was checked."""
    try:
        envelope = load_envelope(path)
    except (OSError, ConstitutionError) as e:
        raise EditorError(str(e)) from None
    signed = envelope.get("signed") if isinstance(envelope, dict) else None
    if not isinstance(signed, dict):
        raise EditorError(f"{path}: not a signed constitution (no signed body)")
    if public_key is not None:
        try:
            verify_signed(envelope, public_key)
        except ValueError as e:
            raise EditorError(f"{path}: {e}") from None
        said = f"signature checked; digest {canonical_hash(signed)}"
    else:
        said = "signature not checked (no public key given)"
    old = signed.get("serial")
    document = {k: v for k, v in signed.items() if k != "prose"}
    if isinstance(document.get("tool_specs"), Mapping):
        document["tool_specs"] = {tool: tidy_spec(spec) for tool, spec in document["tool_specs"].items()}
    draft = draft_from(signed.get("prose") or "", document)
    draft.serial = old + 1 if isinstance(old, int) and not isinstance(old, bool) else 1
    return draft, f"{said}; serial {old if old is not None else 'none'}, the new version gets {draft.serial}"


def _without_none(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _without_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_without_none(v) for v in value]
    return value


def tidy_spec(spec: Any) -> Any:
    """A signed (canonical) tool spec without the defaults the signer fills in (``amount: null``,
    ``payload: []``, ``deny_unmapped: false``, ``shape: null``), so it reads as a person writes it. It signs
    to the same canonical spec."""
    if not isinstance(spec, Mapping):
        return spec
    out = _without_none(spec)
    return {k: v for k, v in out.items() if v not in ([], {}) and not (k == "deny_unmapped" and v is False)}


# -- tools and rules ------------------------------------------------------------------------------------------


def allow_rule(draft: Draft) -> dict:
    """The first ``allow_only_tools`` rule, added at the top when there is none."""
    for rule in draft.rules:
        if isinstance(rule, dict) and isinstance(rule.get(ALLOW), list):
            return rule
    rule = {"id": "tools", ALLOW: []}
    draft.rules.insert(0, rule)
    return rule


def tool_names(draft: Draft) -> list[str]:
    """Every tool the draft names: allow-listed, then any spec for a tool no allow list names."""
    out: list[str] = []
    for rule in draft.rules:
        listed = rule.get(ALLOW) if isinstance(rule, dict) else None
        for name in listed if isinstance(listed, list) else []:
            if isinstance(name, str) and name not in out:
                out.append(name)
    out += [name for name in draft.tool_specs if name not in out]
    return out


def set_tool(draft: Draft, name: str, spec: Mapping, old_name: str | None = None) -> None:
    """Add a tool, or change one (``old_name`` renames it): allow-listed, with this spec."""
    name = name.strip()
    if not name:
        raise EditorError("a tool needs an id")
    if name != old_name and name in tool_names(draft):
        raise EditorError(f"tool {name!r} is already in the constitution")
    if old_name is not None and old_name != name:
        _rename_tool(draft, old_name, name)
    listed = allow_rule(draft)[ALLOW]
    if name not in tool_names(draft):
        listed.append(name)
    draft.tool_specs[name] = dict(spec)


def _rename_tool(draft: Draft, old: str, new: str) -> None:
    for rule in draft.rules:
        listed = rule.get(ALLOW) if isinstance(rule, dict) else None
        if isinstance(listed, list):
            rule[ALLOW] = [new if item == old else item for item in listed]
    draft.tool_specs = {new if k == old else k: v for k, v in draft.tool_specs.items()}


def remove_tool(draft: Draft, name: str) -> None:
    """Take a tool out of every allow list and drop its spec."""
    for rule in draft.rules:
        listed = rule.get(ALLOW) if isinstance(rule, dict) else None
        if isinstance(listed, list):
            rule[ALLOW] = [item for item in listed if item != name]
    draft.tool_specs.pop(name, None)


def spec_form(spec: Mapping) -> tuple[dict, dict]:
    """A spec split into the keys the window has controls for and the rest (argument mappings)."""
    known = {k: spec[k] for k in SPEC_KEYS if k in spec}
    return known, {k: v for k, v in spec.items() if k not in SPEC_KEYS}


def build_spec(irreversible: bool, floor: str, deny_unmapped: bool, mappings: Mapping) -> dict:
    """A tool spec from the controls and the mappings text. ``deny_unmapped`` is written only when on."""
    unknown = sorted(set(mappings) & set(SPEC_KEYS))
    if unknown:
        raise EditorError(f"set {unknown} with the controls above, not in the mappings")
    spec: dict[str, Any] = {"irreversible": bool(irreversible), "data_class_floor": floor}
    if deny_unmapped:
        spec["deny_unmapped"] = True
    spec.update(mappings)
    return spec


def rule_type(rule: Any) -> str:
    """The rule's type, or ``?`` when it has none or more than one."""
    found = [t for t in RULE_TYPES if isinstance(rule, Mapping) and t in rule]
    return found[0] if len(found) == 1 else "?"


def rule_summary(rule: Any) -> str:
    """One line for the rules table."""
    kind = rule_type(rule)
    if kind == "?":
        return dump_value(rule)
    return " ".join(dump_value(rule[kind]).split())


def build_rule(rule_id: str, kind: str, body: Any) -> dict:
    """A rule from the editor's id, type, and body."""
    if kind not in RULE_TYPES:
        raise EditorError(f"rule type must be one of {list(RULE_TYPES)}")
    rule: dict[str, Any] = {}
    if rule_id.strip():
        rule["id"] = rule_id.strip()
    rule[kind] = body
    return rule


def move_rule(draft: Draft, index: int, step: int) -> int:
    """Move a rule up (-1) or down (+1). Path A reports the first rule that denies, so order shows. Returns the
    rule's new index."""
    target = index + step
    if not 0 <= index < len(draft.rules) or not 0 <= target < len(draft.rules):
        return index
    draft.rules[index], draft.rules[target] = draft.rules[target], draft.rules[index]
    return target


def parse_value(text: str, what: str) -> Any:
    """A YAML (or JSON) value typed into the window, read strictly: a duplicate key is refused."""
    if not text.strip():
        return {}
    try:
        return load_yaml(text)
    except ImportError:
        pass
    except StrictParseError as e:
        raise EditorError(f"{what}: {e}") from None
    try:
        return loads_json(text)
    except StrictParseError as e:
        raise EditorError(f"{what}: {e} (YAML needs the yaml extra; JSON is read without it)") from None


def dump_value(value: Any) -> str:
    """A value as the window shows it: block YAML, or JSON without the yaml extra."""
    if value in ({}, None):
        return ""
    if not isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    try:
        import yaml
    except ImportError:
        return json.dumps(value, indent=2, ensure_ascii=False)
    return yaml.safe_dump(value, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100)


# -- checking and signing --------------------------------------------------------------------------------------


def rules_document(draft: Draft) -> dict:
    """The rules file's document: serial, fields, hard_rules, tool_specs (empty ones left out)."""
    doc: dict[str, Any] = {}
    if draft.serial is not None:
        doc["serial"] = draft.serial
    if draft.fields:
        doc["fields"] = draft.fields
    doc["hard_rules"] = draft.rules
    doc["tool_specs"] = draft.tool_specs
    return doc


def rules_text(draft: Draft, json_file: bool = False) -> str:
    """The rules file as it is written: JSON for a ``.json`` name, YAML otherwise."""
    doc = rules_document(draft)
    if json_file:
        return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    import yaml
    return ("# Written by two-key constitution-editor and signed into constitution.signed.json.\n"
            "# Sign it again with two-key sign-constitution or the editor; every key: docs/SETTINGS.md.\n"
            + yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100))


@dataclass(frozen=True)
class Report:
    """What :func:`check` found. ``error`` is None when the draft signs."""
    error: str | None
    notes: tuple[tuple[str, str], ...] = ()      # (WARNING or note, text)
    envelope_format: str = ""
    digest: str = ""
    body: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None


def _signed_notes(signed: Mapping) -> list[tuple[str, str]]:
    """The notes ``two-key sign-constitution`` prints, in its order."""
    registry = signed.get("fields") or {}
    rules, specs = signed["hard_rules"], signed["tool_specs"]
    out = [(WARNING if warn else NOTE, line) for warn, line in not_applicable_notes(rules, specs, registry)]
    out += [(WARNING, line) for line in case_warnings(rules, specs, registry)]
    out += [(WARNING if warn else NOTE, line) for warn, line in domain_allow_notes(specs)]
    out += [(WARNING, line) for line in encrypted_pass_notes(specs)]
    out += [(NOTE, line) for line in path_notes(specs, registry)]
    return out


def check(draft: Draft) -> Report:
    """Run the signing checks on the draft without a key. The body and digest are what signing would sign."""
    if not draft.prose.strip():
        return Report("the prose is empty: the judges read it in full, so write what the principal wants")
    if draft.envelope_format not in ENVELOPE_FORMATS:
        return Report(f"envelope format must be one of {list(ENVELOPE_FORMATS)}")
    try:
        fmt, signed = signed_body(draft.prose, copy.deepcopy(draft.rules), copy.deepcopy(draft.tool_specs),
                                  fields=copy.deepcopy(draft.fields) or None,
                                  envelope_format=draft.envelope_format, serial=draft.serial)
        notes = _signed_notes(signed)
    except (ValueError, TypeError) as e:
        return Report(str(e))
    if draft.serial is None:
        from .setup_cmd import NO_SERIAL
        notes.insert(0, (WARNING, f"no serial: {NO_SERIAL}"))
    return Report(None, tuple(notes), fmt, canonical_hash(signed), signed)


@dataclass(frozen=True)
class Saved:
    """What :func:`sign_and_save` wrote."""
    prose: str
    rules: str
    signed: str
    digest: str
    fingerprint: str
    envelope_format: str
    notes: tuple[tuple[str, str], ...]


def target_paths(folder: Path | str, names: Mapping[str, str] | None = None) -> dict[str, Path]:
    """The three files in ``folder``; ``names`` replaces any of ``FILE_NAMES``."""
    chosen = {**FILE_NAMES, **{k: v for k, v in (names or {}).items() if v}}
    if set(chosen) != set(FILE_NAMES):
        raise EditorError(f"file names: expected {sorted(FILE_NAMES)}")
    out = {role: Path(folder) / chosen[role] for role in FILE_NAMES}
    if len(set(out.values())) != len(out):
        raise EditorError("the prose, rules, and signed files need three different names")
    return out


def existing(paths: Mapping[str, Path]) -> list[str]:
    """The files among ``paths`` that are already there."""
    return [str(p) for p in paths.values() if os.path.lexists(p)]


def _write_text(path: Path, text: str) -> None:
    """Write beside ``path`` (owner-only), then rename over it: a reader never sees half a file."""
    tmp = path.parent / f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    try:
        with os.fdopen(_platform.create_new(tmp, owner_only=True), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        _platform.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def _write_sources(paths: Mapping[str, Path], draft: Draft, refused: str) -> None:
    """Write the prose and the rules file. A folder or file that cannot be written is an ``EditorError``."""
    for role, text in (("prose", draft.prose),
                       ("rules", rules_text(draft, paths["rules"].suffix.lower() == ".json"))):
        try:
            _write_text(paths[role], text)
        except OSError as e:
            raise EditorError(f"{refused}: {write_refusal(paths[role], e)}") from None


def write_refusal(path: Path, error: OSError) -> str:
    """Why ``path`` could not be written, in words: the file and folder, not the temporary file's name."""
    reason = error.strerror or type(error).__name__
    return f"cannot write {path.name} in {path.parent}: {reason}"


def same_from_files(paths: Mapping[str, Path], signed: Mapping) -> None:
    """The prose and rules files read back as ``two-key sign-constitution`` reads them sign the same body."""
    try:
        prose, rules, specs, fields = load_unsigned_with_fields(paths["prose"], paths["rules"])
        _, again = signed_body(prose, rules, specs, fields=fields or None, serial=load_serial(paths["rules"]))
    except (OSError, ValueError) as e:
        raise EditorError(f"the files written do not read back ({e}); the signed file was not written") from None
    if canonical_hash(again) != canonical_hash(signed):
        raise EditorError("the rules file written does not read back as what was signed; the signed file was not "
                          "written")


def sign_and_save(draft: Draft, private_key, folder: Path | str, names: Mapping[str, str] | None = None, *,
                  overwrite: bool = False) -> Saved:
    """Sign the draft and write the prose, the rules file, and the signed constitution into ``folder``.

    Refused, with nothing written, when the draft does not check out, when a file is there and ``overwrite``
    is off, or when ``folder`` is not a folder. The signed file is written last, after the envelope verifies
    with the key's public half and the written prose and rules read back as the same body."""
    report = check(draft)
    if not report.ok:
        raise EditorError(f"not signed: {report.error}")
    if not Path(folder).is_dir():
        raise EditorError(f"{folder} is not a folder")
    paths = target_paths(folder, names)
    there = existing(paths)
    if there and not overwrite:
        raise EditorError(f"not signed: {', '.join(there)} already there; tick Replace to write over "
                          "them (sign-constitution's --force)")
    envelope = sign_constitution(draft.prose, copy.deepcopy(draft.rules), private_key,
                                 copy.deepcopy(draft.tool_specs), fields=copy.deepcopy(draft.fields) or None,
                                 envelope_format=draft.envelope_format, serial=draft.serial)
    verify_signed(json.loads(json.dumps(envelope)), private_key.public_key())
    _write_sources(paths, draft, "not signed")
    same_from_files(paths, envelope["signed"])
    try:
        save_envelope(paths["signed"], envelope, owner_only=True)
    except OSError as e:
        raise EditorError(f"not signed: {write_refusal(paths['signed'], e)}") from None
    return Saved(str(paths["prose"]), str(paths["rules"]), str(paths["signed"]), canonical_hash(envelope["signed"]),
                 envelope["fingerprint"], envelope["format"], report.notes)


def save_sources(draft: Draft, folder: Path | str, names: Mapping[str, str] | None = None, *,
                 overwrite: bool = False) -> list[str]:
    """Write the prose and the rules file only, unsigned (to review, or to sign later). The draft need not
    check out yet."""
    paths = target_paths(folder, names)
    wanted = {role: paths[role] for role in ("prose", "rules")}
    there = existing(wanted)
    if there and not overwrite:
        raise EditorError(f"not saved: {', '.join(there)} already there; tick Replace to write over them")
    _write_sources(wanted, draft, "not saved")
    return [str(p) for p in wanted.values()]


# -- trying a call ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Trial:
    """One call through the draft: what Path A decided and the prompt a judge was sent."""
    path_a_allowed: bool | None
    path_a_reason: str
    decision_reason: str
    system_prompt: str
    user_prompt: str

    def text(self) -> str:
        verdict = {True: "allows", False: "denies", None: "did not run"}[self.path_a_allowed]
        lines = [f"Path A {verdict} the call: {self.path_a_reason}",
                 f"Two-Key's decision with one stand-in judge voting yes: {self.decision_reason}", ""]
        if not self.user_prompt:
            return "\n".join([*lines, "No judge was asked (the call was refused before Path B)."])
        return "\n".join([*lines, NOT_SIGNED_NOTE, "", "System prompt:", self.system_prompt, "",
                          "User prompt:", self.user_prompt])


class _PromptKeeper:
    """A stand-in judge: votes yes and keeps the prompt an LLM judge would have been sent."""
    is_test_double = True

    def __init__(self) -> None:
        self.judge_id, self.provider = "stand-in", "constitution-editor"
        self.prompt = ""

    def score(self, constitution_text, action, proposal):
        from .judges.base import Ballot
        from .judges.llm import build_user_prompt
        self.prompt = build_user_prompt(constitution_text, action, proposal)
        return Ballot(self.judge_id, self.provider, "yes", 1.0, "stand-in")


def claim_for(tool: str, claim: str, specs: Mapping) -> dict:
    """The claim a guard or proxy sends for this tool (two_key/guard.py ``Guard.claim``)."""
    if claim == "none":
        return {"tool": tool}
    if claim == "floor":
        return {"tool": tool, "data_class": (specs.get(tool) or {}).get("data_class_floor", "classified")}
    return {"tool": tool, "data_class": claim}


def try_call(draft: Draft, tool: str, arguments: Any, *, claim: str = "none", proposal: str = "",
             facts: Any = None) -> Trial:
    """Run one call through the draft on a temporary ledger with a throwaway key and a stand-in judge."""
    from .core import TwoKey
    from .judges.llm import SYSTEM_PROMPT
    from .keys import generate_private_key
    from .ledger import Ledger
    from .testing import TEST_AGENT
    report = check(draft)
    if not report.ok:
        raise EditorError(f"the draft does not sign yet: {report.error}")
    key = generate_private_key()
    envelope = sign_constitution(draft.prose, copy.deepcopy(draft.rules), key, copy.deepcopy(draft.tool_specs),
                                 fields=copy.deepcopy(draft.fields) or None, serial=draft.serial)
    judge = _PromptKeeper()
    with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
        two_key = TwoKey(Ledger(Path(tmp) / "ledger", key), key.public_key(), verify_signed(envelope, key.public_key()),
                         [judge], private_key=key, allow_test_doubles=True, monitored_agent=TEST_AGENT)
        try:
            decision = two_key.authorize(claim_for(tool, claim, draft.tool_specs), arguments,
                                         proposal or f"call {tool}", facts=facts)
        finally:
            two_key.close()
    path_a = decision.path_a or {}
    allowed = path_a.get("allowed") if isinstance(path_a.get("allowed"), bool) else None
    return Trial(allowed, str(path_a.get("reason") or decision.reason), decision.reason,
                 SYSTEM_PROMPT if judge.prompt else "", judge.prompt)

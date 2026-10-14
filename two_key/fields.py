"""Custom Path A fields: a signed registry of typed fields, read from argument bytes.

The principal declares each field once, at the top of the rules file (``fields:``), with a type and a
``default``. A tool spec maps the fields it carries to argument paths (``tool_specs.<tool>.fields``). A
mapped field is required: a missing value is a deny. A tool that does not map a field gets its signed
default, the way a tool with no amount spec has ``amount_usd`` 0. Rules name fields with
``deny_if_fields``.

Values come only from the argument bytes, never from the agent's claim. The policy VM reads them with
``LOAD_FIELD`` from the derived mapping; nothing here ever reads ``Action.raw``.

Types: ``boolean``, ``integer`` (``min`` and ``max`` required, within +/-(2**53 - 1) so a float compare is
exact), ``enum`` (a declared list of values), and ``string`` (``max_length`` required). Enum and string
values use a character set:

- ``ascii`` (the default): printable ASCII, trimmed and lower-cased.
- ``unicode`` with ``scripts``: one writing system (``latin``, ``cyrillic``, ``arabic``, ...) or one of the
  combinations ``japanese``, ``korean``, ``chinese``. Values are compared after NFKC normalization and case
  folding (NFKC_Casefold). A letter outside the declared scripts, a control or format character, a
  private-use or unassigned code point, a generic combining mark, and non-ASCII punctuation that does not
  belong to a declared script are refused. ZWJ and ZWNJ are allowed only with a script that uses them.

A ``description`` is an annotation: signed, never compiled, never sent to a judge, never in a deny reason.

All limits are module constants. Raising one is backward compatible; lowering one can make a signed
constitution refuse to load. See HOWTO "Changing a limit".
"""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Mapping

# --- Limits -----------------------------------------------------------------------------------------------
MAX_FIELDS = 64                    # custom fields in the registry
MAX_FIELDS_PER_TOOL = 64           # fields one tool spec maps
MAX_FIELD_NAME_CHARS = 48
MAX_DESCRIPTION_CHARS = 2000
MAX_ENUM_VALUES = 1024
MAX_VALUE_CHARS = 256              # one enum member, or one string literal in a rule
MAX_VALUE_BYTES = 1024
MAX_STRING_LENGTH = 1024           # the largest max_length a string field may declare
MAX_STRING_BYTES = 4096
MAX_LIST_ITEMS = 1024              # items in an in / not_in list
MAX_CONDITIONS = 16                # operator conditions in one deny_if_fields rule
MAX_SAFE_INT = 2 ** 53 - 1
MAX_PATH_SEGMENTS = 16
MAX_PATH_CHARS = 512

FIELD_NAME = re.compile(r"[a-z][a-z0-9_]{0,%d}" % (MAX_FIELD_NAME_CHARS - 1))
# Names a custom field can never take: the built-in form and action fields, and the keys around them.
RESERVED_NAMES = frozenset({
    "tool", "amount_usd", "currency", "counterparty", "counterparties", "data_class", "destination",
    "duration_hours", "irreversible", "tags", "raw", "tool_args", "fields",
})
RESERVED_PREFIXES = ("two_key",)

FIELD_TYPES = ("boolean", "integer", "enum", "string")
CHARSETS = ("ascii", "unicode")
_COMMON_KEYS = {"type", "default", "description"}
_TYPE_KEYS = {
    "boolean": _COMMON_KEYS,
    "integer": _COMMON_KEYS | {"min", "max"},
    "enum": _COMMON_KEYS | {"values", "charset", "scripts"},
    "string": _COMMON_KEYS | {"max_length", "charset", "scripts"},
}
OPS = {
    "boolean": ("eq",),
    "integer": ("eq", "neq", "gt", "gte", "lt", "lte"),
    "enum": ("eq", "neq", "in", "not_in"),
    "string": ("eq", "neq", "in", "not_in"),
}

# Unicode character-name prefixes that identify each supported script. Python's standard library has no
# Script property, so the name decides; a character no prefix claims is refused, never guessed.
SCRIPT_PREFIXES: dict[str, tuple[str, ...]] = {
    "latin": ("LATIN ",),
    "greek": ("GREEK ",),
    "cyrillic": ("CYRILLIC ",),
    "armenian": ("ARMENIAN ",),
    "georgian": ("GEORGIAN ",),
    "hebrew": ("HEBREW ",),
    "arabic": ("ARABIC ", "ARABIC-INDIC ", "EXTENDED ARABIC-INDIC "),
    "devanagari": ("DEVANAGARI ",),
    "bengali": ("BENGALI ",),
    "gurmukhi": ("GURMUKHI ",),
    "gujarati": ("GUJARATI ",),
    "tamil": ("TAMIL ",),
    "telugu": ("TELUGU ",),
    "kannada": ("KANNADA ",),
    "malayalam": ("MALAYALAM ",),
    "sinhala": ("SINHALA ",),
    "thai": ("THAI ",),
    "lao": ("LAO ",),
    "khmer": ("KHMER ",),
    "ethiopic": ("ETHIOPIC ",),
    "hangul": ("HANGUL ",),
    "han": ("CJK UNIFIED IDEOGRAPH", "CJK COMPATIBILITY IDEOGRAPH", "IDEOGRAPHIC "),
    "hiragana": ("HIRAGANA ", "KATAKANA-HIRAGANA "),
    "katakana": ("KATAKANA ", "KATAKANA-HIRAGANA "),
    "bopomofo": ("BOPOMOFO ",),
}
# A field declares one script, or one of these combinations (after Unicode TS #39, "highly restrictive").
SCRIPT_SETS: dict[str, frozenset[str]] = {name: frozenset({name}) for name in SCRIPT_PREFIXES
                                          if name not in ("hiragana", "katakana", "bopomofo")}
SCRIPT_SETS.update({
    "japanese": frozenset({"latin", "han", "hiragana", "katakana"}),
    "korean": frozenset({"latin", "hangul", "han"}),
    "chinese": frozenset({"latin", "han", "bopomofo"}),
})
# Scripts whose spelling needs ZERO WIDTH JOINER / NON-JOINER.
JOINING_SCRIPTS = frozenset({"arabic", "devanagari", "bengali", "gurmukhi", "gujarati", "tamil", "telugu",
                             "kannada", "malayalam", "sinhala"})
_ZWNJ, _ZWJ = "\u200c", "\u200d"
# Format characters a description may keep: joiners and the directional marks (not embeddings or overrides).
_DESCRIPTION_FORMAT_OK = frozenset({_ZWNJ, _ZWJ, "\u200e", "\u200f", "\u061c"})


class FieldError(ValueError):
    """A field definition, mapping, or rule literal is invalid. Such a constitution does not load."""


class FieldValueError(ValueError):
    """A value read from the arguments is not a valid value of its field. ``kind`` is the deny reason stem."""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind     # field_unreadable or field_not_allowed


# --- Text values ------------------------------------------------------------------------------------------

def _script_of(ch: str) -> str | None:
    name = unicodedata.name(ch, "")
    for script, prefixes in SCRIPT_PREFIXES.items():
        if name.startswith(prefixes):
            return script
    return None


MAX_COMBINING_RUN = 3     # generic combining marks allowed in a row after a letter (Turkish i + dot above)


def _unreadable() -> FieldValueError:
    return FieldValueError("field_unreadable")


def _ascii_char(ch: str, scripts: frozenset[str]) -> tuple[bool, bool]:
    """Printable ASCII only; a letter needs ``latin``. Returns (prev_ok, prev_letter) for the next character."""
    if not 0x20 <= ord(ch) < 0x7F:
        raise _unreadable()
    if ch.isalpha():
        if "latin" not in scripts:
            raise _unreadable()
        return True, True
    return ch.isdigit(), False


def _generic_combining(ch: str) -> bool:
    """A combining mark of no particular script (inherited), such as COMBINING DOT ABOVE."""
    return (unicodedata.category(ch)[0] == "M" and _script_of(ch) is None
            and unicodedata.name(ch, "").startswith("COMBINING "))


def _script_char(ch: str, scripts: frozenset[str]) -> tuple[bool, bool]:
    """A non-ASCII character of a declared script. Returns (prev_ok, prev_letter) for the next character."""
    cat = unicodedata.category(ch)
    if cat[0] in "CZ":   # control, format, surrogate, private use, unassigned, non-ASCII separators
        raise _unreadable()
    script = _script_of(ch)
    if script is None or script not in scripts:
        raise _unreadable()
    return cat[0] in "LMN", cat[0] in "LM"


def _check_unicode(text: str, scripts: frozenset[str]) -> None:
    joiners = bool(scripts & JOINING_SCRIPTS)
    prev_ok = False          # the previous character was a letter, mark, or digit of a declared script
    prev_letter = False      # the previous character was a letter of a declared script, or a mark on one
    run = 0                  # generic combining marks since that letter
    for i, ch in enumerate(text):
        if ord(ch) < 0x80:
            prev_ok, prev_letter = _ascii_char(ch, scripts)
            run = 0
        elif ch in (_ZWJ, _ZWNJ):
            if not (joiners and prev_ok and i + 1 < len(text)):
                raise _unreadable()
            prev_ok = prev_letter = False
            run = 0
        elif _generic_combining(ch):
            # A generic combining mark (inherited script) only sits on a letter of a declared script.
            run += 1
            if not prev_letter or run > MAX_COMBINING_RUN:
                raise _unreadable()
        else:
            prev_ok, prev_letter = _script_char(ch, scripts)
            run = 0


def normalize_text(value: Any, charset: str, scripts: str | None = None) -> str:
    """The canonical form of a text value, or ``FieldValueError``. Never reads past the declared rules."""
    if not isinstance(value, str):
        raise FieldValueError("field_unreadable")
    if len(value) > 4 * MAX_STRING_BYTES:      # bounded before any normalization work
        raise FieldValueError("field_not_allowed")
    if charset == "ascii":
        if any(not 0x20 <= ord(c) < 0x7F for c in value):
            raise FieldValueError("field_unreadable")
        return value.strip().lower()
    if charset != "unicode" or scripts not in SCRIPT_SETS:
        raise FieldValueError("field_unreadable")
    text = unicodedata.normalize("NFKC", unicodedata.normalize("NFKC", value).casefold()).strip()
    _check_unicode(text, SCRIPT_SETS[scripts])
    return text


def _text_within(text: str, max_chars: int, max_bytes: int) -> bool:
    return len(text) <= max_chars and len(text.encode("utf-8")) <= max_bytes


def coerce_value(defn: Mapping[str, Any], raw: Any) -> Any:
    """Read one argument value as a value of the field ``defn``. Raises ``FieldValueError``."""
    kind = defn["type"]
    if kind == "boolean":
        if not isinstance(raw, bool):
            raise FieldValueError("field_unreadable")
        return raw
    if kind == "integer":
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise FieldValueError("field_unreadable")
        if not defn["min"] <= raw <= defn["max"]:
            raise FieldValueError("field_not_allowed")
        return int(raw)
    text = normalize_text(raw, defn["charset"], defn.get("scripts"))
    if kind == "enum":
        if text not in defn["values"]:
            raise FieldValueError("field_not_allowed")
        return text
    if not _text_within(text, defn["max_length"], MAX_STRING_BYTES):
        raise FieldValueError("field_not_allowed")
    return text


# --- Registry ---------------------------------------------------------------------------------------------

def _description(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise FieldError(f"{where}.description: expected a string")
    text = unicodedata.normalize("NFC", value)
    if not text or text != text.strip():
        raise FieldError(f"{where}.description: must be non-empty with no leading or trailing whitespace")
    if len(text) > MAX_DESCRIPTION_CHARS:
        raise FieldError(f"{where}.description: longer than {MAX_DESCRIPTION_CHARS} characters")
    for ch in text:
        if ch == "\n":
            continue
        cat = unicodedata.category(ch)
        if cat == "Cf" and ch in _DESCRIPTION_FORMAT_OK:
            continue
        if cat[0] == "C" or cat in ("Zl", "Zp"):
            raise FieldError(f"{where}.description: control, format, or unassigned character U+{ord(ch):04X}")
    return text


def _safe_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or abs(value) > MAX_SAFE_INT:
        raise FieldError(f"{where}: expected an integer within +/-{MAX_SAFE_INT}")
    return value


def _text_member(defn: Mapping[str, Any], value: Any, where: str) -> str:
    try:
        text = normalize_text(value, defn["charset"], defn.get("scripts"))
    except FieldValueError:
        raise FieldError(f"{where}: not a valid {defn['charset']} value for this field") from None
    if not _text_within(text, MAX_VALUE_CHARS, MAX_VALUE_BYTES):
        raise FieldError(f"{where}: longer than {MAX_VALUE_CHARS} characters or {MAX_VALUE_BYTES} bytes")
    return text


def field_name(name: Any, where: str) -> str:
    if not isinstance(name, str) or not FIELD_NAME.fullmatch(name):
        raise FieldError(f"{where}: field name must match {FIELD_NAME.pattern}")
    if name in RESERVED_NAMES or name.startswith(RESERVED_PREFIXES):
        raise FieldError(f"{where}: {name!r} is reserved")
    return name


def _integer_bounds(out: dict, defn: Mapping[str, Any], where: str) -> None:
    if "min" not in defn or "max" not in defn:
        raise FieldError(f"{where}: integer needs min and max")
    out["min"] = _safe_int(defn["min"], f"{where}.min")
    out["max"] = _safe_int(defn["max"], f"{where}.max")
    if out["min"] > out["max"]:
        raise FieldError(f"{where}: min is greater than max")


def _text_charset(out: dict, defn: Mapping[str, Any], where: str) -> None:
    charset = defn.get("charset", "ascii")
    if charset not in CHARSETS:
        raise FieldError(f"{where}.charset: expected ascii or unicode")
    out["charset"] = charset
    if charset == "unicode":
        scripts = defn.get("scripts")
        if scripts not in SCRIPT_SETS:
            raise FieldError(f"{where}.scripts: expected one of {sorted(SCRIPT_SETS)}")
        out["scripts"] = scripts
    elif "scripts" in defn:
        raise FieldError(f"{where}.scripts: only valid with charset: unicode")


def _enum_values(out: dict, defn: Mapping[str, Any], where: str) -> None:
    values = defn.get("values")
    if not isinstance(values, list) or not values:
        raise FieldError(f"{where}.values: expected a non-empty list")
    if len(values) > MAX_ENUM_VALUES:
        raise FieldError(f"{where}.values: more than {MAX_ENUM_VALUES} values")
    members = [_text_member(out, v, f"{where}.values[{i}]") for i, v in enumerate(values)]
    if any(not m for m in members):
        raise FieldError(f"{where}.values: an empty value is not allowed")
    if len(set(members)) != len(members):
        raise FieldError(f"{where}.values: two values are the same after normalization")
    out["values"] = sorted(members)


def _string_limit(out: dict, defn: Mapping[str, Any], where: str) -> None:
    limit = defn.get("max_length")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_STRING_LENGTH:
        raise FieldError(f"{where}.max_length: expected an integer from 1 to {MAX_STRING_LENGTH}")
    out["max_length"] = limit


def _definition(name: str, defn: Any) -> dict:
    where = f"fields.{name}"
    if not isinstance(defn, Mapping):
        raise FieldError(f"{where}: expected a mapping")
    kind = defn.get("type")
    if kind not in FIELD_TYPES:
        raise FieldError(f"{where}.type: expected one of {list(FIELD_TYPES)}")
    extra = set(defn) - _TYPE_KEYS[kind]
    if extra:
        raise FieldError(f"{where}: unknown key(s) {sorted(map(str, extra))} for type {kind}")
    if "default" not in defn:
        raise FieldError(f"{where}.default: required (the value for tools that do not map this field)")
    out: dict[str, Any] = {"type": kind}
    if kind == "integer":
        _integer_bounds(out, defn, where)
    if kind in ("enum", "string"):
        _text_charset(out, defn, where)
    if kind == "enum":
        _enum_values(out, defn, where)
    if kind == "string":
        _string_limit(out, defn, where)
    try:
        out["default"] = coerce_value(out, defn["default"])
    except FieldValueError:
        raise FieldError(f"{where}.default: not a valid value of this field") from None
    if "description" in defn:
        out["description"] = _description(defn["description"], where)
    return out


def validate_fields(registry: Any) -> dict:
    """Canonical field registry. ``None`` and an empty mapping both mean no custom fields."""
    if registry is None:
        return {}
    if not isinstance(registry, Mapping):
        raise FieldError("fields must be a mapping")
    if len(registry) > MAX_FIELDS:
        raise FieldError(f"fields: more than {MAX_FIELDS} custom fields")
    return {field_name(name, "fields"): _definition(name, defn) for name, defn in registry.items()}


def check_path(path: str, where: str) -> str:
    if len(path) > MAX_PATH_CHARS or path.count(".") + 1 > MAX_PATH_SEGMENTS:
        raise FieldError(f"{where}: field path longer than {MAX_PATH_SEGMENTS} segments or {MAX_PATH_CHARS} chars")
    return path


def defaults(registry: Mapping[str, Mapping[str, Any]]) -> dict:
    return {name: defn["default"] for name, defn in registry.items()}


# --- Rules ------------------------------------------------------------------------------------------------

def _literal(defn: Mapping[str, Any], op: str, value: Any, where: str) -> Any:
    kind = defn["type"]
    if op in ("in", "not_in"):
        if not isinstance(value, list) or not value:
            raise FieldError(f"{where}: expected a non-empty list")
        if len(value) > MAX_LIST_ITEMS:
            raise FieldError(f"{where}: more than {MAX_LIST_ITEMS} items")
        return sorted({_literal(defn, "eq", item, f"{where}[{i}]") for i, item in enumerate(value)})
    if kind == "boolean":
        if not isinstance(value, bool):
            raise FieldError(f"{where}: expected a boolean")
        return value
    if kind == "integer":
        value = _safe_int(value, where)
        if not defn["min"] <= value <= defn["max"]:
            raise FieldError(f"{where}: outside the field's min and max, so the rule could never apply")
        return value
    text = _text_member(defn, value, where)
    if kind == "enum" and text not in defn["values"]:
        raise FieldError(f"{where}: {text!r} is not one of the field's values")
    if kind == "string" and len(text) > defn["max_length"]:
        raise FieldError(f"{where}: longer than the field's max_length")
    return text


def validate_condition(body: Any, registry: Mapping[str, Mapping[str, Any]], where: str) -> dict:
    """Canonical ``deny_if_fields`` body: {field: {op: literal}}. Every condition must hold to deny."""
    if not isinstance(body, Mapping) or not body:
        raise FieldError(f"{where}: expected a non-empty mapping of field to conditions")
    out: dict[str, dict] = {}
    count = 0
    for name, ops in body.items():
        if not isinstance(name, str) or name not in registry:
            raise FieldError(f"{where}: {name!r} is not a declared field")
        defn = registry[name]
        if not isinstance(ops, Mapping) or not ops:
            raise FieldError(f"{where}.{name}: expected a non-empty mapping of operator to value")
        allowed = OPS[defn["type"]]
        bad = [op for op in ops if op not in allowed]
        if bad:
            raise FieldError(f"{where}.{name}: operator(s) {sorted(map(str, bad))} not valid for "
                             f"{defn['type']}; allowed {list(allowed)}")
        count += len(ops)
        out[name] = {op: _literal(defn, op, value, f"{where}.{name}.{op}") for op, value in ops.items()}
    if count > MAX_CONDITIONS:
        raise FieldError(f"{where}: more than {MAX_CONDITIONS} conditions")
    return out


_HOLDS = {
    "eq": lambda v, lit: v == lit, "neq": lambda v, lit: v != lit,
    "gt": lambda v, lit: v > lit, "gte": lambda v, lit: v >= lit,
    "lt": lambda v, lit: v < lit, "lte": lambda v, lit: v <= lit,
    "in": lambda v, lit: v in lit, "not_in": lambda v, lit: v not in lit,
}


def unmapped_rule_field_warnings(rules: list, tool_specs: Mapping[str, Mapping[str, Any]],
                                 registry: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Advice for the signer, not a check: each tool that does not map a field a deny_if_fields rule reads.

    That tool gets the field's signed default. When every condition of the rule reads a default, the rule
    either always or never denies the tool, and a forgotten mapping is otherwise silent (HOWTO "Known
    trade-offs by configuration"). Takes the canonical rules, specs, and registry of a signed document.
    """
    out: list[str] = []
    for rule in rules:
        body = rule.get("deny_if_fields") if isinstance(rule, Mapping) else None
        if not body:
            continue
        for tool in sorted(tool_specs):
            missing = sorted(set(body) - set(tool_specs[tool].get("fields") or {}))
            if not missing:
                continue
            given = ", ".join(f"{n}={json.dumps(registry[n]['default'])}" for n in missing)
            if len(missing) == len(body):
                denies = all(_HOLDS[op](registry[n]["default"], lit) for n in body for op, lit in body[n].items())
                effect = "always denies it" if denies else "never denies it"
            else:
                effect = "reads that default"
            out.append(f"rule {rule.get('id')!r}: tool {tool!r} does not map {', '.join(missing)} "
                       f"(default {given}), so the rule {effect}")
    return out


"""
Two-Key: one signed constitution, two compilations (PRIOR_ART.md §4 (ii))
===============================================================================
Selected by the author on 2026-09-30 (CONCEPTION_NOTES.md Entry 2, "B").

The principal signs ONE constitution document. This module compiles that
single document deterministically into both enforcement inputs:

* Path A: structured rules -> stack bytecode (policy_vm.compile_constitution).
  ``verify_structured_only`` statically checks that the program LOADs only
  structured action fields and uses only comparison and boolean opcodes. It
  never reads a natural-language field and performs no string operations on
  NL text, so the prose cannot steer Path A.
* Path B: the prose -> the judge prompt text.

Both outputs are hashed with Two-Key's digest algorithm:
``bytecode_hash = H(canonical bytecode)`` and ``nl_hash = H(judge prompt text)``.
Two-Key records both in the ledger's ``constitution_loaded`` entry and binds
them into every ballot and capability token. The gateway checks them against
the latest ``constitution_loaded`` entry before any tool runs. Both come from
the same principal-signed document. A document signed by any other key (for
example, a model vendor) is refused before compilation, so neither output can
be replaced without the principal's signature.

Source formats:
  two-key-constitution/1  prose and rules in separate fields of one
                                 signed document (the original format).
  two-key-constitution/2  a single signed Markdown ``source``. Exactly one
                                 fenced block with the info string ``twokey-rules``
                                 holds the rules as JSON. Everything else is prose.
                                 See ``split_source``.

Open points (DESIGN_OPTIONS.md §7): whether the judges should also see the
rule block, YAML inside the fence, and how prose is normalized.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .action import KNOWN_FIELDS
from .canonical import canonical_bytes, digest_hex
from .crypto.provider import CryptoProvider
from .policy_vm import DEFAULT_MAX_STEPS, ConstitutionError, Op, compile_constitution

COMPILER_ID = "two-key-compiler/1"
RULES_FENCE = "twokey-rules"
# Fields Path A may read: the structured, normalized action fields. "raw" (free-form
# extension data) is excluded, and so is anything natural-language.
STRUCTURED_FIELDS = frozenset(KNOWN_FIELDS - {"raw"})
# Opcodes the compiler emits. CONTAINS (substring/list search) is deliberately excluded.
ALLOWED_OPS = frozenset({Op.PUSH, Op.LOAD, Op.EQ, Op.NEQ, Op.LT, Op.LTE, Op.GT, Op.GTE, Op.AND, Op.OR,
                         Op.NOT, Op.IN, Op.ASSERT, Op.PASS, Op.FAIL, Op.HALT})

_FENCE_RE = re.compile(r"^(`{3,})[ \t]*([^\s`]*)[^\n]*$")


@dataclass(frozen=True)
class CompiledConstitution:
    bytecode: list
    bytecode_hash: str
    judge_text: str
    nl_hash: str
    rules: list
    source_format: str
    digest_alg: str
    compiler: str = COMPILER_ID

    def hashes(self) -> dict:
        return {"bytecode_hash": self.bytecode_hash, "nl_hash": self.nl_hash}


def split_source(source: str) -> tuple[str, list]:
    """Deterministically split a /2 source into (prose, rules).

    The source must contain exactly one fenced block whose info string is
    ``twokey-rules``. Its body is parsed as JSON: a list of rules, or
    {"hard_rules": [...]}. The prose is the source with that block (including
    its fence lines) removed, and with leading and trailing whitespace stripped.
    Other fenced blocks are prose. An unterminated fence is an error.
    """
    if not isinstance(source, str) or not source.strip():
        raise ConstitutionError("constitution source is empty")
    lines = source.replace("\r\n", "\n").split("\n")
    prose: list[str] = []
    blocks: list[str] = []
    i = 0
    while i < len(lines):
        m = _FENCE_RE.match(lines[i])
        if not m:
            prose.append(lines[i])
            i += 1
            continue
        fence, info = m.group(1), m.group(2)
        j = i + 1
        while j < len(lines) and not re.match(r"^" + fence + r"`*[ \t]*$", lines[j]):
            j += 1
        if j == len(lines):
            raise ConstitutionError(f"unterminated code fence at line {i + 1}")
        if info == RULES_FENCE:
            blocks.append("\n".join(lines[i + 1:j]))
        else:
            prose.extend(lines[i:j + 1])
        i = j + 1
    if len(blocks) != 1:
        raise ConstitutionError(f"expected exactly one ```{RULES_FENCE} block, found {len(blocks)}")
    try:
        rules: Any = json.loads(blocks[0])
    except json.JSONDecodeError as e:
        raise ConstitutionError(f"{RULES_FENCE} block is not valid JSON: {e.msg}") from None
    if isinstance(rules, dict) and set(rules) == {"hard_rules"}:
        rules = rules["hard_rules"]
    text = "\n".join(prose).strip()
    if not text:
        raise ConstitutionError("constitution prose (the Path B text) is empty")
    return text, rules


def bytecode_digest(bytecode: list, alg: str = "sha384", provider: CryptoProvider | None = None) -> str:
    """H(canonical serialization of the bytecode): [[opcode name, operands...], ...]."""
    ser = [[Op(ins[0]).name, *ins[1:]] for ins in bytecode]
    return digest_hex(canonical_bytes(ser), alg, provider)


def nl_digest(text: str, alg: str = "sha384", provider: CryptoProvider | None = None) -> str:
    return digest_hex(text.encode("utf-8"), alg, provider)


def verify_structured_only(bytecode: list) -> None:
    """Static check: only structured-field LOADs, only allowed opcodes, only scalar/list constants."""
    for n, ins in enumerate(bytecode):
        try:
            op = Op(ins[0])
        except (ValueError, IndexError, TypeError):
            raise ConstitutionError(f"bytecode[{n}]: invalid opcode") from None
        if op not in ALLOWED_OPS:
            raise ConstitutionError(f"bytecode[{n}]: opcode {op.name} not permitted in Path A")
        if op is Op.LOAD:
            if len(ins) != 2 or ins[1] not in STRUCTURED_FIELDS:
                raise ConstitutionError(f"bytecode[{n}]: LOAD of non-structured field {ins[1:]!r}")
        elif op is Op.PUSH:
            v = ins[1] if len(ins) == 2 else None
            vals = v if isinstance(v, list) else [v]
            if len(ins) != 2 or any(not isinstance(x, (str, int, float, bool)) for x in vals):
                raise ConstitutionError(f"bytecode[{n}]: PUSH operand must be a scalar or list of scalars")
    if not bytecode or Op(bytecode[-1][0]) is not Op.PASS:
        raise ConstitutionError("bytecode must end in PASS")


def compile_both(constitution: Any, *, max_steps: int = DEFAULT_MAX_STEPS, digest_alg: str = "sha384",
                 provider: CryptoProvider | None = None) -> CompiledConstitution:
    """Compile one verified Constitution into (bytecode, judge prompt text) plus both hashes."""
    bytecode = compile_constitution(constitution.hard_rules, max_steps=max_steps)
    verify_structured_only(bytecode)
    text = constitution.text
    if not isinstance(text, str) or not text.strip():
        raise ConstitutionError("constitution prose (the Path B text) is empty")
    return CompiledConstitution(
        bytecode=bytecode, bytecode_hash=bytecode_digest(bytecode, digest_alg, provider),
        judge_text=text, nl_hash=nl_digest(text, digest_alg, provider), rules=constitution.hard_rules,
        source_format=constitution.document.get("format", ""), digest_alg=digest_alg)

"""
Two-Key: Path A, the deterministic Policy VM
===================================================
A tiny stack machine that evaluates the principal's hard constraints.
The constitution's hard rules are compiled ahead of time into bytecode.
At decision time the VM only loads fields of a *normalized* action record
(see action.py). It never interprets natural language.

Changes from the original prototype (see CHANGES.md):
- Each rule compiles to a block that ends in ASSERT <rule label>. The first
  failing rule is reported as the deny reason.
- The compiler is strict. Unknown rule types, unknown deny_if keys, typos,
  wrong value types, and empty constitutions are rejected (fail closed).
- Any runtime fault (type error, stack underflow, bad opcode, step limit)
  becomes an explicit deny with a reason. It never becomes an allow.
- The step limit is configurable and checked at compile time.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Iterable, Mapping

from .action import DATA_CLASSES, Action, canon_str

DEFAULT_MAX_STEPS = 4096


class Op(IntEnum):
    PUSH = 1
    LOAD = 2          # load a field from the normalized action
    EQ = 3
    NEQ = 4
    LT = 5
    LTE = 6
    GT = 7
    GTE = 8
    AND = 9
    OR = 10
    NOT = 11
    IN = 12           # needle in haystack(list)
    CONTAINS = 13     # haystack(list/str) contains needle
    HALT = 14
    FAIL = 15
    PASS = 16
    ASSERT = 17       # pop bool; if False -> deny with label arg


class ConstitutionError(ValueError):
    """Hard-rule set is invalid. Such a constitution must not be loaded."""


class VMFault(RuntimeError):
    pass


@dataclass(frozen=True)
class VMResult:
    allowed: bool
    reason: str
    steps: int
    denied_by: str | None = None   # label of the rule that denied, if any


def _num(a: Any) -> float:
    if isinstance(a, bool) or not isinstance(a, (int, float)) or math.isnan(float(a)):
        raise VMFault(f"non-numeric operand {a!r}")
    return float(a)


class PolicyVM:
    """Deterministic interpreter. Same bytecode + same action => same result."""

    def __init__(self, bytecode: list[tuple], max_steps: int = DEFAULT_MAX_STEPS):
        if max_steps < 1:
            raise ValueError("max_steps must be >= 1")
        self.bytecode = [tuple(i) for i in bytecode]
        self.max_steps = max_steps

    def eval(self, action: Action) -> VMResult:
        steps = 0
        try:
            stack: list[Any] = []

            def pop() -> Any:
                if not stack:
                    raise VMFault("stack underflow")
                return stack.pop()

            for instr in self.bytecode:
                steps += 1
                if steps > self.max_steps:
                    return VMResult(False, "resource_limit", steps, "vm")
                op, *args = instr
                if op == Op.PUSH:
                    stack.append(args[0])
                elif op == Op.LOAD:
                    stack.append(action.field_value(args[0]))
                elif op in (Op.EQ, Op.NEQ):
                    b, a = pop(), pop()
                    stack.append((a == b) if op == Op.EQ else (a != b))
                elif op in (Op.LT, Op.LTE, Op.GT, Op.GTE):
                    b, a = _num(pop()), _num(pop())
                    stack.append({Op.LT: a < b, Op.LTE: a <= b, Op.GT: a > b, Op.GTE: a >= b}[op])
                elif op in (Op.AND, Op.OR):
                    b, a = pop(), pop()
                    if not isinstance(a, bool) or not isinstance(b, bool):
                        raise VMFault("AND/OR on non-boolean")
                    stack.append((a and b) if op == Op.AND else (a or b))
                elif op == Op.NOT:
                    a = pop()
                    if not isinstance(a, bool):
                        raise VMFault("NOT on non-boolean")
                    stack.append(not a)
                elif op == Op.IN:
                    hay, needle = pop(), pop()
                    if not isinstance(hay, (list, tuple)):
                        raise VMFault("IN haystack is not a list")
                    stack.append(needle in hay)
                elif op == Op.CONTAINS:
                    needle, hay = pop(), pop()
                    if not isinstance(hay, (list, tuple, str)):
                        raise VMFault("CONTAINS haystack is not a list/str")
                    stack.append(needle in hay)
                elif op == Op.ASSERT:
                    v = pop()
                    if not isinstance(v, bool):
                        raise VMFault("ASSERT on non-boolean")
                    if not v:
                        label = str(args[0]) if args else "assert"
                        return VMResult(False, f"rule_denied:{label}", steps, label)
                elif op == Op.FAIL:
                    label = str(args[0]) if args else "fail"
                    return VMResult(False, f"rule_denied:{label}", steps, label)
                elif op == Op.PASS:
                    return VMResult(True, "pass", steps, None)
                elif op == Op.HALT:
                    break
                else:
                    raise VMFault(f"unknown opcode {op!r}")
            # Fell off the end or HALT without PASS: fail closed.
            return VMResult(False, "no_pass", steps, "vm")
        except VMFault as e:
            return VMResult(False, f"vm_fault:{e}", steps, "vm")
        except Exception as e:  # defensive: any interpreter bug is a deny
            return VMResult(False, f"vm_fault:{type(e).__name__}:{e}", steps, "vm")


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------

RULE_TYPES = ("allow_only_tools", "deny_counterparties", "deny_if", "deny_if_irreversible_over")
DENY_IF_KEYS = ("tool", "amount_usd_gt", "data_class_in", "irreversible")
RULE_META_KEYS = ("id",)


def _nonneg_number(v: Any, where: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ConstitutionError(f"{where}: expected a number")
    f = float(v)
    if math.isnan(f) or math.isinf(f) or f < 0:
        raise ConstitutionError(f"{where}: must be a finite number >= 0")
    return f


def _str_list(v: Any, where: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        raise ConstitutionError(f"{where}: expected a list of strings")
    out = [x.strip().casefold() for x in v]
    if any(not x for x in out):
        raise ConstitutionError(f"{where}: empty string not allowed")
    if not out and not allow_empty:
        raise ConstitutionError(f"{where}: list must not be empty")
    return sorted(set(out))


def validate_rules(rules: Any, *, require_allow_list: bool = True) -> list[dict]:
    """Validate and canonicalize a hard-rule list. Raises ConstitutionError."""
    if not isinstance(rules, list):
        raise ConstitutionError("hard rules must be a list")
    if not rules:
        raise ConstitutionError("empty constitution: at least one hard rule is required")
    out: list[dict] = []
    seen_ids: set[str] = set()
    for i, rule in enumerate(rules):
        where = f"rule[{i}]"
        if not isinstance(rule, Mapping):
            raise ConstitutionError(f"{where}: expected a mapping")
        keys = set(rule)
        types = keys & set(RULE_TYPES)
        extra = keys - set(RULE_TYPES) - set(RULE_META_KEYS)
        if extra:
            raise ConstitutionError(f"{where}: unknown key(s) {sorted(extra)}; allowed {list(RULE_TYPES)}")
        if len(types) != 1:
            raise ConstitutionError(f"{where}: exactly one rule type required, got {sorted(types)}")
        rtype = types.pop()
        rid = rule.get("id", f"{where}:{rtype}")
        if not isinstance(rid, str) or not rid.strip():
            raise ConstitutionError(f"{where}: id must be a non-empty string")
        if rid in seen_ids:
            raise ConstitutionError(f"{where}: duplicate id {rid!r}")
        seen_ids.add(rid)
        body = rule[rtype]
        if rtype == "allow_only_tools":
            val: Any = _str_list(body, f"{where}.allow_only_tools")
        elif rtype == "deny_counterparties":
            val = _str_list(body, f"{where}.deny_counterparties")
        elif rtype == "deny_if_irreversible_over":
            val = _nonneg_number(body, f"{where}.deny_if_irreversible_over")
        else:  # deny_if
            if not isinstance(body, Mapping) or not body:
                raise ConstitutionError(f"{where}.deny_if: expected a non-empty mapping")
            bad = set(body) - set(DENY_IF_KEYS)
            if bad:
                raise ConstitutionError(f"{where}.deny_if: unknown key(s) {sorted(bad)}; allowed {list(DENY_IF_KEYS)}")
            val = {}
            if "tool" in body:
                if not isinstance(body["tool"], str) or not body["tool"].strip():
                    raise ConstitutionError(f"{where}.deny_if.tool: expected non-empty string")
                val["tool"] = canon_str(body["tool"], "tool")
            if "amount_usd_gt" in body:
                val["amount_usd_gt"] = _nonneg_number(body["amount_usd_gt"], f"{where}.deny_if.amount_usd_gt")
            if "data_class_in" in body:
                dcs = _str_list(body["data_class_in"], f"{where}.deny_if.data_class_in")
                badc = [d for d in dcs if d not in DATA_CLASSES]
                if badc:
                    raise ConstitutionError(f"{where}.deny_if.data_class_in: unknown class(es) {badc}")
                val["data_class_in"] = dcs
            if "irreversible" in body:
                if not isinstance(body["irreversible"], bool):
                    raise ConstitutionError(f"{where}.deny_if.irreversible: expected boolean")
                val["irreversible"] = body["irreversible"]
        out.append({"id": rid, rtype: val})
    if require_allow_list and not any("allow_only_tools" in r for r in out):
        raise ConstitutionError(
            "no allow_only_tools rule: an allow-list is required so unknown tools fail closed "
            "(pass require_allow_list=False to override)"
        )
    return out


def compile_constitution(
    rules: Iterable[Mapping] | list,
    *,
    max_steps: int = DEFAULT_MAX_STEPS,
    require_allow_list: bool = True,
) -> list[tuple]:
    """Compile validated hard rules to bytecode. Raises ConstitutionError."""
    canon = validate_rules(list(rules) if not isinstance(rules, list) else rules,
                           require_allow_list=require_allow_list)
    bc: list[tuple] = []
    for rule in canon:
        rid = rule["id"]
        if "allow_only_tools" in rule:
            bc += [(Op.LOAD, "tool"), (Op.PUSH, rule["allow_only_tools"]), (Op.IN,)]
        elif "deny_counterparties" in rule:
            bc += [(Op.LOAD, "counterparty"), (Op.PUSH, rule["deny_counterparties"]), (Op.IN,), (Op.NOT,)]
        elif "deny_if_irreversible_over" in rule:
            # allowed iff (not irreversible) OR (amount <= limit)
            bc += [(Op.LOAD, "irreversible"), (Op.NOT,),
                   (Op.LOAD, "amount_usd"), (Op.PUSH, rule["deny_if_irreversible_over"]), (Op.LTE,),
                   (Op.OR,)]
        else:
            cond = rule["deny_if"]
            parts: list[list[tuple]] = []
            if "tool" in cond:
                parts.append([(Op.LOAD, "tool"), (Op.PUSH, cond["tool"]), (Op.EQ,)])
            if "amount_usd_gt" in cond:
                parts.append([(Op.LOAD, "amount_usd"), (Op.PUSH, cond["amount_usd_gt"]), (Op.GT,)])
            if "data_class_in" in cond:
                parts.append([(Op.LOAD, "data_class"), (Op.PUSH, cond["data_class_in"]), (Op.IN,)])
            if "irreversible" in cond:
                parts.append([(Op.LOAD, "irreversible"), (Op.PUSH, cond["irreversible"]), (Op.EQ,)])
            for j, p in enumerate(parts):
                bc += p
                if j:
                    bc.append((Op.AND,))
            bc.append((Op.NOT,))  # rule passes iff NOT(all conditions)
        bc.append((Op.ASSERT, rid))
    bc.append((Op.PASS,))
    if len(bc) > max_steps:
        raise ConstitutionError(
            f"compiled program has {len(bc)} instructions, exceeding max_steps={max_steps}"
        )
    return bc

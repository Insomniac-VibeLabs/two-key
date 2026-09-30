"""
Compact Kernel — Deterministic Policy VM
========================================
A tiny stack machine that evaluates hard constitutional constraints.
It cannot be jailbroken by natural-language prompt injection because it
does not interpret English at runtime. The constitution is compiled
ahead of time into bytecode.

This is Path A of dual-path enforcement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Op(IntEnum):
    PUSH = 1
    LOAD = 2          # load field from proposed action
    EQ = 3
    NEQ = 4
    LT = 5
    LTE = 6
    GT = 7
    GTE = 8
    AND = 9
    OR = 10
    NOT = 11
    IN = 12           # haystack contains needle
    CONTAINS = 13
    HALT = 14
    FAIL = 15
    PASS = 16


@dataclass
class Action:
    """Normalized proposed tool invocation."""
    tool: str
    amount_usd: float = 0.0
    currency: str = "USD"
    counterparty: str = ""
    data_class: str = "public"          # public | personal | medical | financial | classified
    destination: str = ""
    duration_hours: float = 0.0
    irreversible: bool = False
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def field(self, name: str) -> Any:
        if hasattr(self, name):
            return getattr(self, name)
        return self.raw.get(name)


@dataclass
class VMResult:
    allowed: bool
    reason: str
    steps: int


class PolicyVM:
    """Deterministic interpreter. Same bytecode + same action => same result."""

    MAX_STEPS = 256

    def __init__(self, bytecode: list[tuple]):
        self.bytecode = bytecode

    def eval(self, action: Action) -> VMResult:
        stack: list[Any] = []
        steps = 0
        ip = 0
        n = len(self.bytecode)

        while ip < n:
            steps += 1
            if steps > self.MAX_STEPS:
                return VMResult(False, "resource_limit", steps)

            op, *args = self.bytecode[ip]
            ip += 1

            if op == Op.PUSH:
                stack.append(args[0])
            elif op == Op.LOAD:
                stack.append(action.field(args[0]))
            elif op == Op.EQ:
                b, a = stack.pop(), stack.pop()
                stack.append(a == b)
            elif op == Op.NEQ:
                b, a = stack.pop(), stack.pop()
                stack.append(a != b)
            elif op == Op.LT:
                b, a = stack.pop(), stack.pop()
                stack.append(a < b)
            elif op == Op.LTE:
                b, a = stack.pop(), stack.pop()
                stack.append(a <= b)
            elif op == Op.GT:
                b, a = stack.pop(), stack.pop()
                stack.append(a > b)
            elif op == Op.GTE:
                b, a = stack.pop(), stack.pop()
                stack.append(a >= b)
            elif op == Op.AND:
                b, a = stack.pop(), stack.pop()
                stack.append(bool(a) and bool(b))
            elif op == Op.OR:
                b, a = stack.pop(), stack.pop()
                stack.append(bool(a) or bool(b))
            elif op == Op.NOT:
                stack.append(not bool(stack.pop()))
            elif op == Op.IN:
                hay, needle = stack.pop(), stack.pop()
                stack.append(needle in hay)
            elif op == Op.CONTAINS:
                needle, hay = stack.pop(), stack.pop()
                stack.append(needle in hay if hay is not None else False)
            elif op == Op.FAIL:
                return VMResult(False, str(args[0]) if args else "denied", steps)
            elif op == Op.PASS:
                return VMResult(True, "pass", steps)
            elif op == Op.HALT:
                break
            else:
                return VMResult(False, f"unknown_op:{op}", steps)

        allowed = bool(stack[-1]) if stack else False
        return VMResult(allowed, "halt", steps)


def compile_constitution(rules: list[dict]) -> list[tuple]:
    """
    Compile a list of hard rules into bytecode.

    Rule shapes:
      {"deny_if": {"tool": "wire_transfer", "amount_usd_gt": 500}}
      {"deny_if": {"data_class_in": ["medical", "classified"]}}
      {"allow_only_tools": ["search", "calendar", "email_draft"]}
      {"deny_counterparties": ["acme-scam.example"]}
      {"deny_if_irreversible_over": 50}
    """
    bc: list[tuple] = []

    for rule in rules:
        if "allow_only_tools" in rule:
            allowed = list(rule["allow_only_tools"])
            bc += [(Op.LOAD, "tool"), (Op.PUSH, allowed), (Op.IN,)]
            bc += [(Op.NOT,), (Op.PUSH, False), (Op.EQ,)]  # if tool NOT in allowed -> fail path
            # if result of (tool in allowed) is False, deny
            # We'll use a guard pattern: push deny flag
            # Simpler: if tool not in list, FAIL
            # Rebuild cleanly:
            bc = bc[:-5]
            bc += [
                (Op.LOAD, "tool"),
                (Op.PUSH, allowed),
                (Op.IN,),
                # if False, we want to fail. We'll check after all rules via conjunction.
            ]
            # Mark this as a conjunct by leaving bool on stack. We'll AND them later.
            continue

        if "deny_counterparties" in rule:
            blocked = list(rule["deny_counterparties"])
            bc += [
                (Op.LOAD, "counterparty"),
                (Op.PUSH, blocked),
                (Op.IN,),
                (Op.NOT,),
            ]
            continue

        if "deny_if_irreversible_over" in rule:
            limit = float(rule["deny_if_irreversible_over"])
            # allowed if (not irreversible) OR (amount <= limit)
            bc += [
                (Op.LOAD, "irreversible"),
                (Op.NOT,),
                (Op.LOAD, "amount_usd"),
                (Op.PUSH, limit),
                (Op.LTE,),
                (Op.OR,),
            ]
            continue

        cond = rule.get("deny_if") or {}
        parts = []

        if "tool" in cond:
            parts.append([
                (Op.LOAD, "tool"),
                (Op.PUSH, cond["tool"]),
                (Op.EQ,),
            ])
        if "amount_usd_gt" in cond:
            parts.append([
                (Op.LOAD, "amount_usd"),
                (Op.PUSH, float(cond["amount_usd_gt"])),
                (Op.GT,),
            ])
        if "data_class_in" in cond:
            parts.append([
                (Op.LOAD, "data_class"),
                (Op.PUSH, list(cond["data_class_in"])),
                (Op.IN,),
            ])
        if "irreversible" in cond:
            parts.append([
                (Op.LOAD, "irreversible"),
                (Op.PUSH, bool(cond["irreversible"])),
                (Op.EQ,),
            ])

        if not parts:
            continue

        # deny_if means: if ALL listed conditions true, then this rule fails.
        # We emit (NOT conjunction) so True on stack means "this rule does not deny".
        first = True
        for p in parts:
            bc += p
            if not first:
                bc.append((Op.AND,))
            first = False
        bc.append((Op.NOT,))

    # Conjunction of every leftover boolean on the stack.
    # Count how many bool-producing rules we added by wrapping with AND fold.
    # We don't know stack depth statically if mixed; fold remaining with AND
    # by a convention: start with True then AND each rule result.
    # Easier: prepend True and AND after each rule in a second pass.
    wrapped: list[tuple] = [(Op.PUSH, True)]
    # Recompile using explicit AND after each rule block — redo cleanly.
    return _compile_with_ands(rules)


def _compile_with_ands(rules: list[dict]) -> list[tuple]:
    bc: list[tuple] = [(Op.PUSH, True)]

    def and_in():
        bc.append((Op.AND,))

    for rule in rules:
        if "allow_only_tools" in rule:
            bc += [
                (Op.LOAD, "tool"),
                (Op.PUSH, list(rule["allow_only_tools"])),
                (Op.IN,),
            ]
            and_in()
            continue

        if "deny_counterparties" in rule:
            bc += [
                (Op.LOAD, "counterparty"),
                (Op.PUSH, list(rule["deny_counterparties"])),
                (Op.IN,),
                (Op.NOT,),
            ]
            and_in()
            continue

        if "deny_if_irreversible_over" in rule:
            limit = float(rule["deny_if_irreversible_over"])
            bc += [
                (Op.LOAD, "irreversible"),
                (Op.NOT,),
                (Op.LOAD, "amount_usd"),
                (Op.PUSH, limit),
                (Op.LTE,),
                (Op.OR,),
            ]
            and_in()
            continue

        cond = rule.get("deny_if") or {}
        emitted = False
        conjuncts = 0

        def emit_cond(ops):
            nonlocal emitted, conjuncts
            bc.extend(ops)
            if emitted:
                bc.append((Op.AND,))
            emitted = True
            conjuncts += 1

        if "tool" in cond:
            emit_cond([(Op.LOAD, "tool"), (Op.PUSH, cond["tool"]), (Op.EQ,)])
        if "amount_usd_gt" in cond:
            emit_cond([
                (Op.LOAD, "amount_usd"),
                (Op.PUSH, float(cond["amount_usd_gt"])),
                (Op.GT,),
            ])
        if "data_class_in" in cond:
            emit_cond([
                (Op.LOAD, "data_class"),
                (Op.PUSH, list(cond["data_class_in"])),
                (Op.IN,),
            ])
        if "irreversible" in cond:
            emit_cond([
                (Op.LOAD, "irreversible"),
                (Op.PUSH, bool(cond["irreversible"])),
                (Op.EQ,),
            ])

        if emitted:
            # deny_if: NOT (all conditions)
            bc.append((Op.NOT,))
            and_in()

    bc.append((Op.HALT,))
    return bc

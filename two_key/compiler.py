# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Compile one constitution into Path A bytecode and Path B prose."""

from __future__ import annotations

from dataclasses import dataclass, field

from .canonical import canonical_hash
from .constitution import validate_tool_specs
from .fields import FieldError, validate_fields
from .policy_vm import ConstitutionError, compile_constitution


@dataclass(frozen=True)
class CompiledConstitution:
    bytecode: list[tuple]
    bytecode_hash: str
    judge_text: str
    nl_hash: str
    rules: list[dict]
    tool_specs: dict
    specs_enforced: bool
    spec_hash: str
    fields: dict = field(default_factory=dict)   # canonical custom-field registry


def compile_both(prose: str, rules: list, tool_specs: dict | None = None, *,
                 specs_enforced: bool = False, max_steps: int = 4096,
                 fields: dict | None = None) -> CompiledConstitution:
    """``spec_hash`` covers the tool specs and, when there is one, the custom-field registry: the field
    types and defaults decide the derived form, so a token binds them. Without a registry it is the hash
    of the specs alone, as before."""
    if not isinstance(prose, str) or not prose.strip():
        raise ConstitutionError("constitution prose (the Path B text) is empty")
    try:
        registry = validate_fields(fields)
    except FieldError as e:
        raise ConstitutionError(str(e)) from None
    if specs_enforced:
        specs = validate_tool_specs(tool_specs or {}, rules, registry)
        spec_hash = canonical_hash({"fields": registry, "tool_specs": specs}) if registry else canonical_hash(specs)
    else:
        specs = {}
        spec_hash = ""
    bytecode = compile_constitution(rules, max_steps=max_steps, fields=registry)
    return CompiledConstitution(
        bytecode=bytecode,
        bytecode_hash=canonical_hash([[op, *rest] for op, *rest in bytecode]),
        judge_text=prose,
        nl_hash=canonical_hash(prose),
        rules=list(rules),
        tool_specs=specs,
        specs_enforced=specs_enforced,
        spec_hash=spec_hash,
        fields=registry,
    )
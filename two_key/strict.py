# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Strict parsers for every JSON and YAML document two-key reads.

A repeated key is refused, never resolved last-one-wins: with two values,
the one a check reads could differ from the one a tool, a judge, or an
operator reads. A YAML merge key (``<<``) is refused for the same reason: the
value it resolves to depends on precedence rules the text does not show
(#52). Anchors and aliases without ``<<`` still load. JSON's non-standard constants (NaN, Infinity) are refused
too. Every config, constitution, rules file, proposal, ballot, provider
response, and token payload goes through here. (The ledger reads only
records it wrote and sealed itself.)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .canonical import MAX_INT_DIGITS, _int_too_large

__all__ = ["StrictParseError", "DuplicateKeyError", "loads_json", "load_yaml", "load_file_strict"]


class StrictParseError(ValueError):
    """The document is not valid, or repeats a key in one mapping."""


class DuplicateKeyError(StrictParseError):
    """A key repeated in one mapping."""

    def __init__(self, key, where: str = ""):
        self.key = key
        super().__init__(f"duplicate key {str(key)[:80]!r}{where}")


def _no_duplicate_keys(pairs: list) -> dict:
    obj: dict = {}
    for k, v in pairs:
        if k in obj:
            raise DuplicateKeyError(k)
        obj[k] = v
    return obj


def _no_constants(name: str):
    raise StrictParseError(f"non-standard JSON constant {name}")


def _integer_too_large() -> StrictParseError:
    return StrictParseError(f"integer too large (more than {MAX_INT_DIGITS} digits)")


def _bounded_int(text: str) -> int:
    """A JSON integer literal of at most MAX_INT_DIGITS digits, on every Python version (#51)."""
    if len(text) - text.startswith("-") > MAX_INT_DIGITS:     # a JSON integer is -?digits
        raise _integer_too_large()
    return int(text)


def loads_json(text: str | bytes) -> Any:
    """``json.loads`` that refuses duplicate keys at any depth and NaN/Infinity."""
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constants,
                          parse_int=_bounded_int)
    except StrictParseError:
        raise
    except json.JSONDecodeError as e:
        raise StrictParseError(f"not valid JSON: {e.msg}") from None
    except ValueError:   # an interpreter whose int limit is under MAX_INT_DIGITS (PYTHONINTMAXSTRDIGITS)
        raise _integer_too_large() from None
    except RecursionError:
        raise StrictParseError("JSON nests too deeply") from None


_LOADER = None


def _strict_loader():
    global _LOADER
    if _LOADER is not None:
        return _LOADER
    import yaml

    class StrictSafeLoader(yaml.SafeLoader):
        """SafeLoader that refuses a key repeated in one mapping (YAML 1.2 says keys are unique)."""

    def construct_mapping(loader, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise StrictParseError(f"YAML merge key '<<' at line {key_node.start_mark.line + 1} is refused: "
                                       "which value wins is not visible in the text; write the keys out")
            key = loader.construct_object(key_node, deep=True)
            try:
                if key in seen:
                    raise DuplicateKeyError(key, f" at line {key_node.start_mark.line + 1}")
                seen.add(key)
            except TypeError:
                pass  # unhashable key: construct_mapping refuses it below
        return loader.construct_mapping(node, deep=deep)

    def construct_int(loader, node):
        # Count digits before converting (a long decimal raises ValueError on 3.11+), then bound the value
        # (hex, octal, and binary forms convert without that limit).
        if sum(c.isdigit() for c in loader.construct_scalar(node)) > MAX_INT_DIGITS:
            raise _integer_too_large()
        value = yaml.SafeLoader.construct_yaml_int(loader, node)
        if _int_too_large(value):
            raise _integer_too_large()
        return value

    StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
    StrictSafeLoader.add_constructor("tag:yaml.org,2002:int", construct_int)
    _LOADER = StrictSafeLoader
    return _LOADER


def load_yaml(text: str) -> Any:
    """``yaml.safe_load`` that refuses a key repeated in one mapping, and any merge key (``<<``)."""
    loader = _strict_loader()
    import yaml
    try:
        # The loader is a SafeLoader subclass, so bandit's B506 does not apply.
        return yaml.load(text, Loader=loader)  # nosec B506
    except StrictParseError:
        raise
    except yaml.YAMLError as e:
        raise StrictParseError(f"not valid YAML: {str(e).splitlines()[0][:200]}") from None
    except ValueError:   # as in loads_json
        raise _integer_too_large() from None
    except RecursionError:
        raise StrictParseError("YAML nests too deeply") from None


def load_file_strict(path: Path | str) -> Any:
    """Read a ``.json`` file as strict JSON and anything else as strict YAML."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return loads_json(text)
    return load_yaml(text)

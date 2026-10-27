# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Search, filter, and sort ledger entries for an audit: ``two-key ledger-view``.

The ledger is opened the way ``two-key audit`` opens it, so the chain, the signed head, and both witness pins
are checked first, and a ledger that does not verify is not shown. Nothing here appends to the ledger or writes
a file: the window (two_key/ledger_gui.py) and ``--print`` (JSON Lines on stdout) only read.

Each entry is one row. Its fields are ``seq``, ``kind``, ``prev``, ``entry_hash``, and every value in its body
under a dotted path (``subject.tool``, ``history_basis.ledger_size``). A list adds ``[]`` to the path and keeps
every element, so ``ballots[].judge_id`` holds each judge's id and a filter matches when any element does. A
body key that shares a name with one of the four entry fields is shown as ``body.<key>``::

    from two_key.ledger_view import Filter, Query, rows_from_entries, select
    rows = rows_from_entries(e.to_json() for e in ledger.entries)
    query = Query(search="wire", filters=(Filter("kind", "equals", "decision"),
                                          Filter("allowed", "equals", "false")),
                  sort=(("seq", True),))
    for row in select(rows, query):
        print(row.entry)

Text tests ignore case. ``gt``, ``ge``, ``lt`` and ``le`` compare as numbers when both sides are numbers, and
as text otherwise, so ISO times such as ``at`` compare in time order. A missing field is empty: it matches
``empty``, ``not-contains`` and ``not-equals``, and nothing else. Rows with no value for a sort field go last
whichever way that field is sorted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Sequence

ENTRY_FIELDS = ("seq", "kind", "prev", "entry_hash")
ANY_FIELD = "*"
# Shown first when a ledger has them; every other field can be added from the window's Columns list.
DEFAULT_COLUMNS = ("seq", "kind", "at", "agent.id", "tool", "subject.tool", "allowed", "passed", "reason",
                   "ballots[].judge_id", "ballots[].vote", "jti")
MAX_REGEX = 500


class ViewError(ValueError):
    """A filter or sort that cannot be applied, with the reason in words."""


def _casefold(value: Any) -> str:
    return text_of(value).casefold()


def _number(value: Any) -> float | None:
    """The value as a number, or None. Booleans are not numbers here; numeric text is."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except ValueError:
        return None


def _compare(value: Any, wanted: str) -> int:
    """-1, 0, or 1: ``value`` against ``wanted``, as numbers when both are, as case-folded text otherwise."""
    left, right = _number(value), _number(wanted)
    if left is not None and right is not None:
        return (left > right) - (left < right)
    text, other = _casefold(value), wanted.casefold()
    return (text > other) - (text < other)


# Each test takes one stored value and the filter's text (or compiled pattern).
_POSITIVE: dict[str, Callable[[Any, Any], bool]] = {
    "contains": lambda v, w: w.casefold() in _casefold(v),
    "equals": lambda v, w: _casefold(v) == w.casefold(),
    "starts-with": lambda v, w: _casefold(v).startswith(w.casefold()),
    "ends-with": lambda v, w: _casefold(v).endswith(w.casefold()),
    "regex": lambda v, w: w.search(text_of(v)) is not None,
    "gt": lambda v, w: v is not None and _compare(v, w) > 0,
    "ge": lambda v, w: v is not None and _compare(v, w) >= 0,
    "lt": lambda v, w: v is not None and _compare(v, w) < 0,
    "le": lambda v, w: v is not None and _compare(v, w) <= 0,
}
_NEGATED = {"not-contains": "contains", "not-equals": "equals"}
_UNARY = ("empty", "not-empty")
OPS = ("contains", "not-contains", "equals", "not-equals", "starts-with", "ends-with", "regex",
       "gt", "ge", "lt", "le", "empty", "not-empty")
# Symbols the command line also takes for the same tests.
OP_ALIASES = {"=": "equals", "==": "equals", "!=": "not-equals", ">": "gt", ">=": "ge", "<": "lt", "<=": "le",
              "~": "contains", "!~": "not-contains"}


def text_of(value: Any) -> str:
    """One stored value as the table shows it: JSON spelling for null and booleans, text for the rest."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass(frozen=True)
class Row:
    """One ledger entry: the entry as JSON, and each field path with every value found under it."""
    entry: Mapping[str, Any]
    values: Mapping[str, tuple]

    @property
    def seq(self) -> int:
        return self.entry["seq"]

    def text(self, name: str) -> str:
        """The field as one line of text; several values are joined with ", "."""
        return ", ".join(text_of(v) for v in self.values.get(name, ()))


def _walk(value: Any, path: str, out: dict[str, tuple]) -> None:
    if isinstance(value, Mapping):
        if not value:
            out.setdefault(path, ())
        for key, item in value.items():
            _walk(item, f"{path}.{key}" if path else str(key), out)
    elif isinstance(value, (list, tuple)):
        if not value:
            out.setdefault(f"{path}[]", ())
        for item in value:
            _walk(item, f"{path}[]", out)
    else:
        out[path] = out.get(path, ()) + (value,)


def flatten(entry: Mapping[str, Any]) -> Row:
    """The row for one entry as ``Entry.to_json()`` gives it."""
    values: dict[str, tuple] = {name: (entry.get(name),) for name in ENTRY_FIELDS}
    body = entry.get("body")
    if isinstance(body, Mapping):
        for key, item in body.items():
            _walk(item, f"body.{key}" if key in ENTRY_FIELDS else str(key), values)
    return Row(entry, values)


def rows_from_entries(entries: Iterable[Mapping[str, Any]]) -> list[Row]:
    """One row per entry, in ledger order."""
    return [flatten(e) for e in entries]


def field_names(rows: Iterable[Row]) -> list[str]:
    """Every field any row has: ``seq`` and ``kind`` first, then the rest by name."""
    names: set[str] = set()
    for row in rows:
        names.update(row.values)
    rest = sorted(names - {"seq", "kind"})
    return ["seq", "kind", *rest]


def default_columns(fields: Sequence[str]) -> list[str]:
    """The columns a new window shows: ``DEFAULT_COLUMNS`` that the ledger has, in that order."""
    present = set(fields)
    return [name for name in DEFAULT_COLUMNS if name in present]


@dataclass(frozen=True)
class Filter:
    """One test on one field (``*`` for any field). ``op`` is one of ``OPS`` or ``OP_ALIASES``."""
    name: str
    op: str
    value: str = ""

    def compiled(self) -> "_Compiled":
        op = OP_ALIASES.get(self.op, self.op)
        if op not in OPS:
            raise ViewError(f"unknown test {self.op!r}; use one of: {', '.join(OPS)}")
        if op == "regex":
            if len(self.value) > MAX_REGEX:
                raise ViewError(f"regex longer than {MAX_REGEX} characters")
            try:
                return _Compiled(self.name, op, re.compile(self.value, re.IGNORECASE))
            except re.error as e:
                raise ViewError(f"regex {self.value!r}: {e}") from None
        return _Compiled(self.name, op, self.value)


@dataclass(frozen=True)
class _Compiled:
    name: str
    op: str
    wanted: Any

    def _values(self, row: Row) -> tuple:
        if self.name == ANY_FIELD:
            return tuple(v for values in row.values.values() for v in values)
        return row.values.get(self.name, ())

    def matches(self, row: Row) -> bool:
        values = self._values(row)
        if self.op in _UNARY:
            empty = all(v is None or v == "" for v in values)
            return empty if self.op == "empty" else not empty
        if self.op in _NEGATED:
            test = _POSITIVE[_NEGATED[self.op]]
            return not any(test(v, self.wanted) for v in values)
        test = _POSITIVE[self.op]
        return any(test(v, self.wanted) for v in values)


@dataclass(frozen=True)
class Query:
    """What to show: ``search`` across every field's value (and, with ``search_names``, its name too),
    ``filters`` combined with all (or ``match_any``), and the sort as ``(field, descending)`` pairs, the first
    one deciding first."""
    search: str = ""
    filters: Sequence[Filter] = ()
    match_any: bool = False
    search_names: bool = False
    sort: Sequence[tuple[str, bool]] = field(default_factory=lambda: (("seq", False),))


def _sort_key(row: Row, name: str) -> tuple:
    values = row.values.get(name, ())
    if len(values) == 1 and _number(values[0]) is not None and not isinstance(values[0], str):
        return (0, _number(values[0]), "")
    return (1, 0.0, row.text(name).casefold())


def _has(row: Row, name: str) -> bool:
    return any(v is not None for v in row.values.get(name, ()))


def sort_rows(rows: Sequence[Row], sort: Sequence[tuple[str, bool]]) -> list[Row]:
    """Rows sorted by each ``(field, descending)`` in turn; a row with no value for a field goes last."""
    out = list(rows)
    for name, descending in reversed(list(sort)):
        present = [r for r in out if _has(r, name)]
        present.sort(key=lambda r, n=name: _sort_key(r, n), reverse=descending)
        out = present + [r for r in out if not _has(r, name)]
    return out


def _search_test(query: Query) -> Callable[[Row], bool] | None:
    """The search as a test on one row, or None for an empty search box."""
    if not query.search:
        return None
    values = Filter(ANY_FIELD, "contains", query.search).compiled()
    if not query.search_names:
        return values.matches
    # A name such as tools.pay_bill.irreversible holds a tool id that no value does.
    wanted = query.search.casefold()
    return lambda row: values.matches(row) or any(wanted in name.casefold() for name in row.values)


def select(rows: Sequence[Row], query: Query) -> list[Row]:
    """The rows ``query`` keeps, in its order. Raises ``ViewError`` for a filter that cannot be applied."""
    tests = [f.compiled() for f in query.filters]
    search = _search_test(query)
    combine = any if query.match_any else all
    kept = [r for r in rows
            if (search is None or search(r)) and (not tests or combine(t.matches(r) for t in tests))]
    return sort_rows(kept, query.sort)


def parse_where(parts: Sequence[str]) -> Filter:
    """``FIELD OP [VALUE...]`` from the command line; the value's words are joined with one space."""
    if len(parts) < 2:
        raise ViewError("--where needs FIELD OP [VALUE], for example: --where kind equals decision")
    name, op, value = parts[0], parts[1], " ".join(parts[2:])
    op = OP_ALIASES.get(op, op)
    if op not in OPS:
        raise ViewError(f"--where: unknown test {parts[1]!r}; use one of: {', '.join(OPS)}")
    if op not in _UNARY and len(parts) < 3:
        raise ViewError(f"--where {name} {op}: needs a value")
    return Filter(name, op, value)


def parse_sort(text: str) -> tuple[str, bool]:
    """``FIELD`` or ``FIELD:asc`` or ``FIELD:desc`` from the command line."""
    name, descending = text, False
    for suffix in (":asc", ":desc"):
        if text.endswith(suffix):
            name, descending = text[:-len(suffix)], suffix == ":desc"
    if not name:
        raise ViewError("--sort needs a field name")
    return name, descending


def query_from_args(args) -> Query:
    """The ``Query`` that ``ledger-view``'s --search, --search-names, --where, --any, and --sort describe."""
    filters = tuple(parse_where(parts) for parts in args.where or ())
    sort = tuple(parse_sort(s) for s in args.sort or ()) or (("seq", False),)
    return Query(search=args.search or "", filters=filters, match_any=args.any, sort=sort,
                 search_names=args.search_names)


def integrity(ledger) -> dict:
    """What was checked when the ledger opened, and the decision digest check (``two-key audit``'s first part)."""
    from .audit import check_decision_digests
    problems = check_decision_digests(ledger)
    return {"ok": not problems, "size": ledger.size(), "decision_digest_problems": problems}


def print_rows(rows: Sequence[Row], out) -> None:
    """Each row's entry as one JSON line, in order."""
    for row in rows:
        out.write(json.dumps(row.entry) + "\n")

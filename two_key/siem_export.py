"""``two-key siem-export`` and ``two-key siem-verify`` (0.7.0).

``siem-export`` opens the ledger the way ``two-key audit`` does, so the chain, the signed head, and both
witness pins are checked before anything is written; a ledger that does not verify is not exported. It
then writes one allowlisted event per line (JSON Lines, or CEF lines), from the same projection the live
sinks use, and ends with a ``siem_export_summary`` line naming the range and the head it was taken from.
Use it to backfill a new SIEM, or to replay a range.

``siem-verify`` reads events back (the native JSON schema, from the export or pulled out of a SIEM) and
checks each one against the ledger: the sequence number exists, the entry hash matches, and the fields are
the ones the ledger would produce, so an event edited after export is caught. It reports missing, extra,
mismatched, and duplicated sequence numbers, and with ``--require-complete`` it also wants the whole
ledger, from 0 to the current head.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from . import _platform
from .siem import ENVELOPE_KEYS, SCHEMA_FORMAT, Event, Renderer, event_for, now_text, project, to_json
from .strict import StrictParseError, loads_json

EXPORT_FORMAT = "two-key-siem-export-v1"
SUMMARY_KIND = "siem_export_summary"
# The envelope an event carries around its allowlisted fields. Everything else is a field to check.
ENVELOPE = frozenset(ENVELOPE_KEYS)


class ExportError(RuntimeError):
    """The export or the check could not be done."""


def events(ledger: Any, *, from_seq: int = 0, to_seq: int | None = None) -> Iterator[Event]:
    """Every entry in the range as an allowlisted event, oldest first."""
    size = ledger.size()
    last = size - 1 if to_seq is None else min(to_seq, size - 1)
    for seq in range(max(0, from_seq), last + 1):
        yield event_for(ledger.entries[seq])


def summary(ledger: Any, first: int | None, last: int | None, count: int, *, sent_at: str) -> dict:
    """The last line of an export: the range, and the head it was taken from."""
    head = ledger.checkpoint()
    return {"format": EXPORT_FORMAT, "kind": SUMMARY_KIND, "exported_at": sent_at, "count": count,
            "first_seq": first, "last_seq": last, "ledger_size": head["size"],
            "merkle_root": head["merkle_root"], "tip": head["tip"], "signature": head["signature"],
            "witness_signature": head["witness_signature"]}


def lines(ledger: Any, *, schema: str = "native", fmt: str = "json", from_seq: int = 0,
          to_seq: int | None = None, clock=time.time) -> Iterator[str]:
    """The export, line by line, including the summary line."""
    renderer = Renderer(schema, fmt)
    sent_at = now_text(clock)
    first = last = None
    count = 0
    for event in events(ledger, from_seq=from_seq, to_seq=to_seq):
        stamped = event.at(sent_at, replay=True)        # an export is always a copy taken later
        first = event.seq if first is None else first
        last, count = event.seq, count + 1
        yield renderer.body(stamped)
    yield to_json(summary(ledger, first, last, count, sent_at=sent_at))


def write(ledger: Any, out: Path | str | None, **kw) -> dict:
    """Write the export to a new file (never over an existing one), or to stdout when ``out`` is None."""
    produced = lines(ledger, **kw)
    if out is None:
        last = ""
        count = 0
        for line in produced:
            print(line)
            last, count = line, count + 1
        return {"written": None, "lines": count, "summary": _summary_of(last)}
    path = Path(out)
    try:
        fd = _platform.create_new(path)
    except FileExistsError:
        raise ExportError(f"refusing to overwrite {path}") from None
    except OSError as e:
        raise ExportError(f"{path}: {e.strerror}") from None
    count, last = 0, ""
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        for line in produced:
            fh.write(line + "\n")
            last, count = line, count + 1
        fh.flush()
        os.fsync(fh.fileno())
    return {"written": str(path), "lines": count, "summary": _summary_of(last)}


def _summary_of(line: str) -> dict | None:
    try:
        parsed = loads_json(line)
    except (StrictParseError, ValueError):
        return None
    return parsed if isinstance(parsed, Mapping) and parsed.get("kind") == SUMMARY_KIND else None


def _read_lines(path: Path | str) -> list[str]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ExportError(f"{path}: {e.strerror}") from None
    return [line for line in text.splitlines() if line.strip()]


def _parsed(line: str, number: int, problems: list) -> Mapping[str, Any] | None:
    try:
        parsed = loads_json(line)
    except (StrictParseError, ValueError) as e:
        problems.append({"line": number, "problem": f"not readable JSON ({e})"})
        return None
    if not isinstance(parsed, Mapping):
        problems.append({"line": number, "problem": "not a JSON object"})
        return None
    return parsed


def check_event(ledger: Any, obj: Mapping[str, Any], number: int) -> dict | None:
    """One event against the ledger: the sequence number, the entry hash, and every allowlisted field."""
    seq = obj.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool):
        return {"line": number, "problem": "no sequence number"}
    if seq < 0 or seq >= ledger.size():
        return {"line": number, "seq": seq, "problem": "not in the ledger"}
    entry = ledger.entries[seq]
    if obj.get("entry_hash") != entry.entry_hash:
        return {"line": number, "seq": seq, "problem": "entry_hash does not match the ledger"}
    if obj.get("kind") != entry.kind:
        return {"line": number, "seq": seq, "problem": "kind does not match the ledger"}
    expected = project(entry.kind, entry.body)
    got = {k: v for k, v in obj.items() if k not in ENVELOPE}
    if obj.get("truncated") is True:
        extra = {k: v for k, v in got.items() if k not in expected or expected[k] != v}
        return None if not extra else {"line": number, "seq": seq, "problem": "fields were changed",
                                       "fields": sorted(extra)}
    if got != expected:
        changed = sorted(set(got) ^ set(expected)) or sorted(k for k in got if got[k] != expected[k])
        return {"line": number, "seq": seq, "problem": "fields were changed", "fields": changed}
    return None


def verify(ledger: Any, path: Path | str, *, require_complete: bool = False) -> dict:
    """Check an exported (or pulled back) event file against the ledger."""
    problems: list[dict] = []
    seen: list[int] = []
    unledgered = 0
    summary_line = None
    for number, line in enumerate(_read_lines(path), start=1):
        obj = _parsed(line, number, problems)
        if obj is None:
            continue
        if obj.get("kind") == SUMMARY_KIND:
            summary_line = obj
            continue
        if obj.get("ledgered") is False:
            unledgered += 1
            continue
        if obj.get("schema") != SCHEMA_FORMAT:
            problems.append({"line": number, "problem": f"not a {SCHEMA_FORMAT} event; "
                                                        "siem-verify reads the native JSON schema"})
            continue
        problem = check_event(ledger, obj, number)
        if problem is not None:
            problems.append(problem)
        else:
            seen.append(obj["seq"])
    result = _coverage(ledger, seen, require_complete)
    problems.extend(result.pop("problems"))
    return {"ok": not problems, "events": len(seen), "unledgered_events": unledgered,
            "ledger_size": ledger.size(), "summary": summary_line, "problems": problems, **result}


def _coverage(ledger: Any, seen: Sequence[int], require_complete: bool) -> dict:
    """Which sequence numbers the file holds, and what is missing, repeated, or short of the head."""
    problems: list[dict] = []
    duplicates = sorted({seq for seq in seen if seen.count(seq) > 1})
    if duplicates:
        problems.append({"problem": "repeated sequence numbers", "seqs": duplicates[:20]})
    order = sorted(set(seen))
    missing: list[int] = []
    if order:
        missing = [seq for seq in range(order[0], order[-1] + 1) if seq not in set(order)]
        if missing:
            problems.append({"problem": "gap in the exported range", "seqs": missing[:20]})
    if require_complete:
        problems.extend(_completeness(ledger, order))
    return {"first_seq": order[0] if order else None, "last_seq": order[-1] if order else None,
            "missing": len(missing), "duplicates": len(duplicates), "problems": problems}


def _completeness(ledger: Any, order: Sequence[int]) -> list[dict]:
    size = ledger.size()
    if not order:
        return [{"problem": "no events, and --require-complete was given"}]
    out = []
    if order[0] != 0:
        out.append({"problem": "does not start at the first entry", "seq": order[0]})
    if order[-1] != size - 1:
        out.append({"problem": "does not reach the ledger head", "seq": order[-1], "ledger_size": size})
    return out


__all__ = ["ENVELOPE", "EXPORT_FORMAT", "ExportError", "SUMMARY_KIND", "check_event", "events", "lines",
           "summary", "verify", "write"]

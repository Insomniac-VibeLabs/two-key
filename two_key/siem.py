"""Ledger export to a SIEM (0.7.0): the event allowlist, the schemas, and delivery.

The ledger stays the record. A SIEM gets a copy of each entry, built from an allowlist, so an operator
sees decisions where the rest of their security events are, and an analyst can check any event against
``two-key audit``.

- **Nothing here can change a decision.** ``Ledger.observe`` calls :meth:`Delivery.notify` after an entry
  is on disk; it only puts a sequence number on a bounded queue. A sender thread does the formatting and
  the network, and reads the entries from the ledger itself, so a full queue costs nothing but a little
  delay, and a collector that is down or slow never holds the ledger lock (maintainer's decision,
  2026-10-16).
- **The allowlist is explicit** (:data:`KINDS`): for every ledger kind, the keys that are sent, the keys
  whose text is replaced by a size and a digest, and the keys that are never sent. Argument values, the
  proposal text, the derived amount and counterparty, custom field values, judge rationales, a decline
  reason, credentials, token text, and file content are in the last group, and no setting moves them
  (``tests/test_siem.py``). A new ledger field is not exported until it is added here on purpose.
- **Every event carries ``seq`` and ``entry_hash``**, so a SIEM can see a gap and ``two-key siem-verify``
  can check a copy against the ledger.
- Ledger entries carry no time, so an event carries ``sent_at``, the time it was sent, and ``replay`` when
  it was sent late (a catch-up after a start or an outage).

Schemas: ``native`` (this module's own field names, the default), ``ecs`` (Elastic Common Schema), and
``ocsf``. Formats: ``json`` (the default) and ``cef``. Both mappings are built from the allowlisted event,
so neither can carry more than ``native`` does. Sinks (``two_key/siem_sinks.py``) are syslog over UDP, TCP,
or TLS, and an HTTPS webhook; ``two-key siem-export`` writes the same events to a file.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import math
import os
import queue
import stat
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import _platform
from .strict import StrictParseError, loads_json

SCHEMA_FORMAT = "two-key-siem-v1"
CURSOR_FORMAT = "two-key-siem-cursor-v1"
SCHEMAS = ("native", "ecs", "ocsf")
FORMATS = ("json", "cef")
REPLAY_FROM = ("cursor", "start", "now")

# Syslog severities (RFC 5424) this export uses.
INFORMATIONAL = 6
NOTICE = 5
WARNING = 4

DEFAULT_QUEUE_MAX = 10000
DEFAULT_BATCH_MAX = 100
DEFAULT_FLUSH_SECONDS = 2.0
DEFAULT_REFUSED_INTERVAL_SECONDS = 60.0
MAX_TEXT_CHARS = 200
MAX_LIST_ITEMS = 64
MAX_SECRET_BYTES = 4096
MAX_PENDING_EVENTS = 256
# Longest a sender waits before it looks at the ledger again without being notified.
TICK_SECONDS = 1.0
BACKOFF_START_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 60.0
# One line per sink state change, no more often than this.
REPORT_SECONDS = 60.0
# What a close waits for: one more pass over every sink that is not already in backoff, so the last events
# go out instead of dying with the thread. A sink that declares no timeout counts as the sink default.
CLOSE_MAX_SECONDS = 15.0
CLOSE_SINK_SECONDS = 5.0


class SiemError(RuntimeError):
    """A sink could not take this batch. The cursor stays where it was and the sender tries again."""


class SiemConfigError(ValueError):
    """Two-Key refuses to start with this SIEM configuration."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def text_record(value: Any, name: str) -> dict:
    """The size and digest of a text the export never sends."""
    data = value.encode("utf-8", "surrogatepass") if isinstance(value, str) else json.dumps(
        value, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8", "surrogatepass")
    return {f"{name}_size": len(data), f"{name}_digest": _digest(data)}


def _scrub(value: Any, depth: int = 0) -> Any:
    """A value fit for an event: text capped and without control characters, short lists, shallow maps."""
    if isinstance(value, str):
        return "".join(c for c in value[:MAX_TEXT_CHARS] if c.isprintable())
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None   # a NaN or an infinity is not JSON
    if depth >= 2:
        return None
    if isinstance(value, Mapping):
        return {str(k)[:64]: _scrub(v, depth + 1) for k, v in list(value.items())[:MAX_LIST_ITEMS]}
    if isinstance(value, (list, tuple)):
        return [_scrub(v, depth + 1) for v in value[:MAX_LIST_ITEMS]]
    return None


def _pick(body: Mapping[str, Any], keys: Iterable[str]) -> dict:
    return {k: _scrub(body[k]) for k in keys if k in body}


_SIZE_SUFFIXES = ("_size", "_digest", "_omitted")


def _size_keys(body: Mapping[str, Any], excluded: frozenset) -> dict:
    """The ledger's own size, digest, and omitted keys, checked by shape so no text rides along."""
    out = {}
    for key, value in body.items():
        if not key.endswith(_SIZE_SUFFIXES) or key in excluded or not isinstance(key, str):
            continue
        if key.endswith("_size") and isinstance(value, int) and not isinstance(value, bool):
            out[key] = value
        elif key.endswith("_digest") and (value is None or _is_digest(value)):
            out[key] = value
        elif key.endswith("_omitted") and isinstance(value, bool):
            out[key] = value
    return out


def _is_digest(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    rest = value[len("sha256:"):]
    return len(rest) == 64 and all(c in "0123456789abcdef" for c in rest)


def _agent_fields(body: Mapping[str, Any]) -> dict:
    agent = body.get("agent")
    if not isinstance(agent, Mapping):
        return {}
    out = {}
    for key in ("id", "hosting"):
        if isinstance(agent.get(key), str):
            out[f"agent_{key}"] = _scrub(agent[key])
    return out


def _form_fields(body: Mapping[str, Any]) -> dict:
    """From the normalized form: the data class and the irreversible flag. Never the amount, the
    counterparty, or a custom field value."""
    form = body.get("form")
    if not isinstance(form, Mapping):
        return {}
    out = {}
    if isinstance(form.get("data_class"), str):
        out["data_class"] = _scrub(form["data_class"])
    if isinstance(form.get("irreversible"), bool):
        out["irreversible"] = form["irreversible"]
    return out


def _witness_fields(body: Mapping[str, Any]) -> dict:
    """Witness key fingerprints. Never a key."""
    from .ledger import witness_key_fingerprint
    out = {}
    for key, name in (("witness_public_key", "witness_fingerprint"),
                      ("old_witness_public_key", "old_witness_fingerprint"),
                      ("new_witness_public_key", "new_witness_fingerprint")):
        raw = body.get(key)
        if isinstance(raw, str):
            try:
                out[name] = witness_key_fingerprint(raw)
            except Exception:       # a body this ledger would not have written: no fingerprint, no key
                continue
    return out


def _constitution_fields(body: Mapping[str, Any]) -> dict:
    out = {}
    separation = body.get("judge_agent_separation")
    if isinstance(separation, Mapping) and isinstance(separation.get("identities_digest"), str):
        out["identities_digest"] = _scrub(separation["identities_digest"])
    scanner = body.get("scanner")
    if isinstance(scanner, Mapping):
        for key in ("label", "field", "stance"):
            if isinstance(scanner.get(key), str):
                out[f"scanner_{key}"] = _scrub(scanner[key])
    return out


def _proxy_fields(body: Mapping[str, Any]) -> dict:
    tools = body.get("tools")
    if isinstance(tools, Mapping):
        return {"tools_offered": sorted(str(t)[:64] for t in list(tools)[:MAX_LIST_ITEMS])}
    return {}


def _scan_parts(body: Mapping[str, Any]) -> dict:
    """Each scanned part by name, size, and digest. Never its content."""
    parts = body.get("parts")
    if not isinstance(parts, (list, tuple)):
        return {}
    out = []
    for part in parts[:MAX_LIST_ITEMS]:
        if isinstance(part, Mapping):
            out.append({"part": _scrub(part.get("part")), "bytes": _scrub(part.get("bytes")),
                        "sha256": _scrub(part.get("sha256"))})
    return {"parts": out}


def _config_files(body: Mapping[str, Any]) -> dict:
    """Each file a config change wrote, by role, name, and the digests before and after. Never its content."""
    files = body.get("files")
    if not isinstance(files, (list, tuple)):
        return {}
    out = []
    for item in files[:MAX_LIST_ITEMS]:
        if isinstance(item, Mapping):
            out.append({"role": _scrub(item.get("role")), "file": _scrub(item.get("file")),
                        "old_sha256": item.get("old_sha256") if _is_digest(item.get("old_sha256")) else None,
                        "new_sha256": item.get("new_sha256") if _is_digest(item.get("new_sha256")) else None})
    return {"files": out}


@dataclass(frozen=True)
class KindSpec:
    """What an event carries for one ledger kind, and what it never carries."""
    sent: tuple[str, ...] = ()
    hashed: tuple[str, ...] = ()        # text replaced by <key>_size and <key>_digest
    excluded: tuple[str, ...] = ()      # never sent, in any schema or format
    extract: Callable[[Mapping[str, Any]], dict] | None = None
    severity: int = INFORMATIONAL


# The allowlist. Every key of every ledger body is in exactly one of sent, hashed, or excluded; a key that
# is in none of them is a test failure (tests/test_siem.py), so a new ledger field is never exported by
# accident. The keys the ledger writes as a size, a digest, or an omitted flag ride along by shape.
KINDS: dict[str, KindSpec] = {
    "witness_pinned": KindSpec(sent=("source",), excluded=("witness_public_key",),
                               extract=_witness_fields, severity=NOTICE),
    # The rotation statement repeats the entry's own format, seq, and prev, which the envelope carries.
    "witness_rotated": KindSpec(
        hashed=("reason",),
        excluded=("format", "seq", "prev", "old_witness_public_key", "new_witness_public_key",
                  "principal_signature", "old_witness_signature", "new_witness_signature"),
        extract=_witness_fields, severity=NOTICE),
    "ledger_recovered": KindSpec(
        sent=("dropped_bytes", "dropped_sha256", "dropped_nonempty_lines", "tail_torn", "head_size"),
        excluded=("tail_file",), severity=NOTICE),
    "constitution_loaded": KindSpec(
        sent=("digest", "bytecode_hash", "nl_hash", "spec_hash", "policy_digest",
              "capability_key_fingerprint"),
        excluded=("quorum_policy", "judge_agent_separation", "scanner", "same_model_tenant_optin",
                  "same_model_tenant_optin_pairs"),
        extract=_constitution_fields),
    "proposal": KindSpec(sent=("tool",), hashed=("proposal",), excluded=("agent",),
                         extract=_agent_fields),
    "action_normalized": KindSpec(
        sent=("tool", "claimed_data_class", "deny_reason", "fact_fields"),
        excluded=("form", "dropped_keys"), extract=_form_fields),
    "scan": KindSpec(
        sent=("tool", "scanner", "version", "verdict", "categories", "stance", "elapsed_ms",
              "scanner_available", "error"),
        excluded=("parts",), extract=_scan_parts),
    "scanner_unavailable": KindSpec(sent=("scanner", "error", "stance"), severity=WARNING),
    "scanner_available": KindSpec(sent=("scanner", "stance")),
    "path_a": KindSpec(sent=("allowed", "reason", "denied_by")),
    "path_b": KindSpec(sent=("passed", "reason", "yes", "no", "abstain", "skipped")),
    "capability_issued": KindSpec(sent=("jti", "token_hash", "ledger_root")),
    "decision": KindSpec(
        sent=("allowed", "reason", "origin", "policy_digest", "identities_digest", "proposal_text_type"),
        excluded=("agent", "decline", "detail", "got", "field", "value"),
        extract=_agent_fields),
    "gateway_denied": KindSpec(sent=("reason", "jti", "tool"), severity=WARNING),
    "redemption_started": KindSpec(sent=("jti", "tool"), excluded=("dropped_keys",)),
    "redemption": KindSpec(sent=("jti", "tool")),
    "redemption_aborted": KindSpec(sent=("jti", "tool"), severity=WARNING),
    "revocation": KindSpec(hashed=("reason",), severity=NOTICE),
    "mcp_proxy_started": KindSpec(
        sent=("upstream_program", "upstream_command_digest", "schema_digest_pinned", "schema_digest_seen",
              "on_schema_change", "allow_unresolved_identity", "signed_tools_not_listed"),
        excluded=("tools",), extract=_proxy_fields),
    "tool_not_offered": KindSpec(sent=("origin", "tool"), severity=WARNING),
    "siem_configured": KindSpec(sent=("event_schema", "event_format", "replay_from", "sinks")),
    # two-key setup, config set and config undo (two_key/config_set.py): which settings and files changed,
    # never a value. The account is in the ledger only.
    "config_changed": KindSpec(
        sent=("command", "settings", "signed", "weaker", "confirmed", "constitution_hash"),
        excluded=("account", "files"), extract=_config_files, severity=NOTICE),
}

# Events this module sends that are not ledger entries. A token that does not verify is refused without a
# ledger entry, so an unauthenticated caller cannot grow the ledger; the count is all that leaves.
UNLEDGERED = {
    "gateway_token_refused": KindSpec(
        sent=("bad_signature", "expired", "malformed", "other", "total", "interval_seconds"),
        severity=WARNING),
}

_DENY_KINDS = frozenset({"gateway_denied", "tool_not_offered", "redemption_aborted", "gateway_token_refused",
                         "scanner_unavailable"})


def spec_for(kind: str) -> KindSpec:
    """The allowlist entry for ``kind``. An unknown kind sends nothing but ``seq``, ``entry_hash``, and
    ``kind``: a ledger written by a newer Two-Key does not leak through an older exporter."""
    return KINDS.get(kind) or UNLEDGERED.get(kind) or KindSpec()


def project(kind: str, body: Mapping[str, Any]) -> dict:
    """The allowlisted fields of one ledger body."""
    spec = spec_for(kind)
    if not isinstance(body, Mapping):
        return {}
    out = _pick(body, spec.sent)
    for key in spec.hashed:
        if key in body:
            out.update(text_record(body[key], key))
    out.update(_size_keys(body, frozenset(spec.excluded)))
    if spec.extract is not None:
        out.update(spec.extract(body))
    return out


def severity_of(kind: str, fields: Mapping[str, Any]) -> int:
    spec = spec_for(kind)
    if fields.get("allowed") is False or fields.get("passed") is False or kind in _DENY_KINDS:
        return min(spec.severity, WARNING)
    return spec.severity


def outcome_of(kind: str, fields: Mapping[str, Any]) -> str:
    """``success``, ``failure``, or ``unknown`` for the common schemas."""
    allowed = fields.get("allowed", fields.get("passed"))
    if kind in _DENY_KINDS or allowed is False:
        return "failure"
    if allowed is True:
        return "success"
    return "unknown"


@dataclass(frozen=True)
class Event:
    """One ledger entry (or one unledgered count) as it leaves for a SIEM."""
    seq: int
    entry_hash: str
    prev: str
    kind: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    sent_at: str = ""
    replay: bool = False
    ledgered: bool = True
    truncated: bool = False

    @property
    def severity(self) -> int:
        return severity_of(self.kind, self.fields)

    def at(self, sent_at: str, *, replay: bool = False) -> "Event":
        return Event(self.seq, self.entry_hash, self.prev, self.kind, self.fields, sent_at, replay,
                     self.ledgered, self.truncated)

    def minimal(self) -> "Event":
        """The same event with only the fields that identify it, for a datagram that cannot hold the rest."""
        keep = {k: v for k, v in self.fields.items() if k in ("reason", "allowed", "tool", "jti")}
        return Event(self.seq, self.entry_hash, self.prev, self.kind, keep, self.sent_at, self.replay,
                     self.ledgered, True)


def event_for(entry: Any) -> Event:
    """The event for a ledger entry (``two_key.ledger.Entry``)."""
    return Event(seq=entry.seq, entry_hash=entry.entry_hash, prev=entry.prev, kind=entry.kind,
                 fields=project(entry.kind, entry.body))


def unledgered_event(kind: str, fields: Mapping[str, Any]) -> Event:
    """An event with no ledger entry behind it, such as the refused-token count."""
    return Event(seq=-1, entry_hash="", prev="", kind=kind, fields=project(kind, fields), ledgered=False)


def now_text(clock: Callable[[], float] = time.time) -> str:
    """RFC 3339 UTC with milliseconds, as RFC 5424 wants it."""
    seconds = clock()
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))
    return f"{base}.{int((seconds % 1) * 1000):03d}Z"


# ---------------------------------------------------------------------------- schemas


# The envelope every event carries. A field name may not be one of these (tests/test_siem.py), and the
# envelope is written last, so a ledger field can never shadow the identity of the event.
ENVELOPE_KEYS = ("schema", "kind", "seq", "entry_hash", "prev", "severity", "sent_at", "ledgered",
                 "replay", "truncated")


def as_native(event: Event) -> dict:
    """This module's own field names. Nothing is renamed or dropped, so it has no lossy mapping."""
    out = dict(event.fields)
    out.update({"schema": SCHEMA_FORMAT, "kind": event.kind, "seq": event.seq,
                "entry_hash": event.entry_hash, "prev": event.prev, "severity": event.severity,
                "sent_at": event.sent_at, "ledgered": event.ledgered})
    if event.replay:
        out["replay"] = True
    if event.truncated:
        out["truncated"] = True
    return out


def _version() -> str:
    from . import __version__
    return __version__


def as_ecs(event: Event) -> dict:
    """Elastic Common Schema 8.x. The allowlisted fields that ECS has no home for stay under ``two_key``."""
    native = as_native(event)
    reason = native.get("reason")
    out = {
        "@timestamp": event.sent_at,
        "ecs": {"version": "8.11.0"},
        "event": {"kind": "event", "category": ["iam"], "type": ["info"], "action": event.kind,
                  "outcome": outcome_of(event.kind, event.fields), "sequence": event.seq,
                  "module": "two_key", "dataset": "two_key.ledger", "provider": "two-key",
                  "id": event.entry_hash or None, "severity": event.severity},
        "observer": {"product": "Two-Key", "vendor": "Insomniac-VibeLabs", "version": _version()},
        "message": " ".join(str(x) for x in (event.kind, reason) if x),
        "two_key": {k: v for k, v in native.items() if k not in ("kind", "seq", "entry_hash", "sent_at")},
    }
    if isinstance(reason, str):
        out["event"]["reason"] = reason
    if isinstance(event.fields.get("agent_id"), str):
        out["user"] = {"id": event.fields["agent_id"]}
    return out


_OCSF_SEVERITY = {INFORMATIONAL: 1, NOTICE: 2, WARNING: 3}
_OCSF_STATUS = {"success": 1, "failure": 2, "unknown": 0}


def as_ocsf(event: Event) -> dict:
    """OCSF 1.1, class Authorize Session (3003), activity Other: the event is a policy decision, not a
    login. The allowlisted fields stay under ``unmapped``."""
    native = as_native(event)
    outcome = outcome_of(event.kind, event.fields)
    reason = native.get("reason")
    out = {
        "class_uid": 3003, "class_name": "Authorize Session", "category_uid": 3,
        "category_name": "Identity & Access Management", "activity_id": 99, "activity_name": event.kind,
        "type_uid": 300399, "time": int(time.time() * 1000) if not event.sent_at else _millis(event.sent_at),
        "severity_id": _OCSF_SEVERITY.get(event.severity, 0),
        "status": outcome.capitalize(), "status_id": _OCSF_STATUS[outcome],
        "metadata": {"version": "1.1.0", "sequence": event.seq, "uid": event.entry_hash or None,
                     "logged_time": event.sent_at,
                     "product": {"name": "Two-Key", "vendor_name": "Insomniac-VibeLabs",
                                 "version": _version(), "feature": {"name": "ledger-export"}}},
        "message": " ".join(str(x) for x in (event.kind, reason) if x),
        "unmapped": {k: v for k, v in native.items() if k not in ("kind", "seq", "entry_hash", "sent_at")},
    }
    if isinstance(reason, str):
        out["status_detail"] = reason
    return out


def _millis(sent_at: str) -> int:
    try:
        parsed = time.strptime(sent_at[:19], "%Y-%m-%dT%H:%M:%S")
    except (ValueError, TypeError):
        return int(time.time() * 1000)
    import calendar
    return calendar.timegm(parsed) * 1000 + int(sent_at[20:23] or 0)


SCHEMA_FUNCTIONS: dict[str, Callable[[Event], dict]] = {"native": as_native, "ecs": as_ecs, "ocsf": as_ocsf}


# ---------------------------------------------------------------------------- formats


_CEF_HEADER_ESCAPE = str.maketrans({"\\": "\\\\", "|": "\\|", "\n": " ", "\r": " "})
_CEF_VALUE_ESCAPE = str.maketrans({"\\": "\\\\", "=": "\\=", "\n": "\\n", "\r": " "})
# CEF severity 0-10 from the syslog severity.
_CEF_SEVERITY = {INFORMATIONAL: 2, NOTICE: 4, WARNING: 6}
# Where an allowlisted field goes in CEF. Anything else becomes a labelled custom string (cs1..cs6).
_CEF_KEYS = {"reason": "reason", "tool": "act", "seq": "cn1", "agent_id": "suser", "origin": "cat",
             "jti": "cs1", "entry_hash": "cs2", "data_class": "cs3", "verdict": "cs4"}
_CEF_LABELS = {"cn1": "seq", "cs1": "jti", "cs2": "entryHash", "cs3": "dataClass", "cs4": "scanVerdict"}


def to_json(obj: Mapping[str, Any]) -> str:
    """One compact line. ``json.dumps`` escapes every newline, so an event is always one line."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, default=str)


def to_cef(event: Event) -> str:
    """ArcSight CEF:0 for one event. Only the native schema maps to CEF."""
    native = as_native(event)
    name = f"{event.kind} {outcome_of(event.kind, event.fields)}"
    header = "|".join(part.translate(_CEF_HEADER_ESCAPE) for part in (
        "CEF:0", "Insomniac-VibeLabs", "Two-Key", _version(), event.kind, name,
        str(_CEF_SEVERITY.get(event.severity, 2))))
    return header + "|" + _cef_extension(native)


def _cef_extension(native: Mapping[str, Any]) -> str:
    pairs, spare = [], 5
    for key, value in native.items():
        if value is None or key in ("schema", "severity"):
            continue
        name = _CEF_KEYS.get(key)
        if name is None and spare <= 6 and isinstance(value, (str, int, float, bool)):
            name, spare = f"cs{spare}", spare + 1
            pairs.append((f"{name}Label", key))
        if name is None:
            continue
        if name in _CEF_LABELS:
            pairs.append((f"{name}Label", _CEF_LABELS[name]))
        pairs.append((name, value))
    pairs.append(("end", native.get("sent_at") or ""))
    return " ".join(f"{k}={_cef_value(v)}" for k, v in pairs)


def _cef_value(value: Any) -> str:
    if isinstance(value, bool):
        value = "true" if value else "false"
    return str(value).translate(_CEF_VALUE_ESCAPE)


class Renderer:
    """Turns an event into the text one sink sends: a schema, then a format."""

    def __init__(self, schema: str = "native", fmt: str = "json"):
        if schema not in SCHEMAS:
            raise SiemConfigError(f"siem.schema: expected one of {list(SCHEMAS)}")
        if fmt not in FORMATS:
            raise SiemConfigError(f"siem.format: expected one of {list(FORMATS)}")
        if fmt == "cef" and schema != "native":
            raise SiemConfigError("siem.format: cef maps the native schema only; set schema: native")
        self.schema, self.format = schema, fmt

    @property
    def content_type(self) -> str:
        return "application/x-ndjson" if self.format == "json" else "text/plain; charset=utf-8"

    def body(self, event: Event) -> str:
        if self.format == "cef":
            return to_cef(event)
        return to_json(SCHEMA_FUNCTIONS[self.schema](event))


@dataclass(frozen=True)
class Message:
    """One rendered event, ready for a sink: its severity, the ledger kind, the time it was sent, and the
    text the renderer made."""
    severity: int
    msgid: str
    body: str
    sent_at: str = ""


# ---------------------------------------------------------------------------- secrets and the cursor


def read_secret_file(path: Path | str, label: str) -> str:
    """A secret an operator keeps in a file (a webhook token, an HMAC key). Owner-only, like a key file.

    The value is never written to the ledger, a log line, or an event.
    """
    try:
        fd = _platform.open_nofollow(os.fspath(path))
    except OSError as e:
        raise SiemConfigError(f"{label}: {path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SiemConfigError(f"{label}: {path} is not a regular file")
        problem = _platform.access_problem(fd, st)
        if problem:
            raise SiemConfigError(f"{label}: {_platform.insecure(path, problem)}")
        data = os.read(fd, MAX_SECRET_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_SECRET_BYTES:
        raise SiemConfigError(f"{label}: {path} is longer than {MAX_SECRET_BYTES} bytes")
    value = data.decode("utf-8", "replace").strip()
    if not value:
        raise SiemConfigError(f"{label}: {path} is empty")
    return value


class Cursor:
    """The last sequence number each sink took, so a restart or an outage replays from the ledger.

    It is not a secret and not signed: a wrong cursor can only repeat or delay the copy, never change the
    ledger. A missing file means a first start.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._seqs: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError:
            return          # no cursor file: a first start, which replay_from decides
        try:
            data = loads_json(text)
        except (StrictParseError, ValueError):
            data = None
        if not isinstance(data, Mapping) or data.get("format") != CURSOR_FORMAT:
            # A file that is there but cannot be read is not a first start: say so, because the copy then
            # begins where replay_from says and the entries in between are only in the ledger
            # (live run 8x, C72). two-key siem-export backfills them.
            print(f"two-key: WARNING: the SIEM cursor at {self.path} is not readable; the copy starts where "
                  "replay_from says and the entries in between are in the ledger only (docs/SIEM.md)",
                  file=sys.stderr)
            return
        sinks = data.get("sinks")
        if isinstance(sinks, Mapping):
            self._seqs = {str(k): v for k, v in sinks.items() if isinstance(v, int) and not isinstance(v, bool)}

    @property
    def exists(self) -> bool:
        return bool(self._seqs)

    def get(self, label: str, default: int = -1) -> int:
        value = self._seqs.get(label)
        return default if value is None else value

    def set(self, label: str, seq: int) -> None:
        self._seqs[label] = seq

    def save(self) -> None:
        """Write the whole file again, through a new file and a rename, so a reader never sees half of it."""
        body = {"format": CURSOR_FORMAT, "sinks": dict(sorted(self._seqs.items()))}
        tmp = self.path.parent / f".{self.path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
        try:
            # 0o700 is owner-only, the strictest useful mode for a directory; the rule's suggestion
            # would make it readable by everyone.
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            _platform.owner_only_dir(self.path.parent)
            with os.fdopen(_platform.create_new(tmp), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(body, indent=2, sort_keys=True) + "\n")
            _platform.replace(tmp, self.path)
        except OSError as e:
            print(f"two-key: siem: could not write the delivery cursor {self.path}: {e.strerror}",
                  file=sys.stderr)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)


# ---------------------------------------------------------------------------- configuration


@dataclass(frozen=True)
class SiemConfig:
    """Where the copy goes and in what shape. Deployment, not policy: it is not in the constitution."""
    sinks: tuple[Any, ...] = ()
    schema: str = "native"
    format: str = "json"
    replay_from: str = "cursor"
    batch_max: int = DEFAULT_BATCH_MAX
    queue_max: int = DEFAULT_QUEUE_MAX
    flush_seconds: float = DEFAULT_FLUSH_SECONDS
    refused_token_interval_seconds: float = DEFAULT_REFUSED_INTERVAL_SECONDS
    cursor_path: Path | None = None

    def __post_init__(self):
        if not self.sinks:
            raise SiemConfigError("siem.sinks: configure at least one sink, or leave siem= out")
        if self.replay_from not in REPLAY_FROM:
            raise SiemConfigError(f"siem.replay_from: expected one of {list(REPLAY_FROM)}")
        labels = [s.label for s in self.sinks]
        if len(set(labels)) != len(labels):
            raise SiemConfigError("siem.sinks: two sinks have the same label; give each one a label")
        Renderer(self.schema, self.format)      # refuse an impossible pair at start, not at the first event

    @property
    def plaintext_sinks(self) -> list[str]:
        return [s.label for s in self.sinks if getattr(s, "plaintext", False)]

    def record(self) -> dict:
        """For the ``siem_configured`` ledger entry: where the copy goes, never a secret."""
        # event_schema and event_format, not schema and format: a field never shares a name with the
        # envelope every event carries (ENVELOPE_KEYS).
        return {"event_schema": self.schema, "event_format": self.format, "replay_from": self.replay_from,
                "sinks": [s.record() for s in self.sinks]}


# ---------------------------------------------------------------------------- delivery


class _SinkState:
    """One sink's cursor, backoff, and the events it has not taken yet."""

    def __init__(self, sink: Any, seq: int, replay_until: int):
        self.sink = sink
        self.seq = seq                      # last ledger seq this sink took
        self.replay_until = replay_until    # entries below this were sent late
        self.pending: list[Event] = []       # unledgered events waiting for this sink
        self.failed_at: float | None = None
        self.backoff = 0.0
        self.next_try = 0.0
        self.reported = 0.0
        self.dropped = 0

    @property
    def label(self) -> str:
        return self.sink.label

    def ready(self, now: float) -> bool:
        return now >= self.next_try

    def ok(self) -> None:
        self.failed_at = None
        self.backoff = 0.0
        self.next_try = 0.0

    def fail(self, now: float) -> None:
        self.failed_at = self.failed_at or now
        self.backoff = min(BACKOFF_MAX_SECONDS, max(BACKOFF_START_SECONDS, self.backoff * 2))
        self.next_try = now + self.backoff


class Delivery:
    """Sends ledger entries to the configured sinks from a sender thread.

    ``notify`` is what the ledger calls, under its own lock: it only puts a sequence number on a bounded
    queue, so a slow or dead collector never delays a decision. The thread reads the entries from the
    ledger itself, so a notice the queue had no room for costs nothing but a little delay.
    """

    def __init__(self, config: SiemConfig, ledger: Any, *, cursor_path: Path | str | None = None,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic):
        self.config = config
        self.ledger = ledger
        self.renderer = Renderer(config.schema, config.format)
        self._clock, self._monotonic = clock, monotonic
        self._queue: queue.Queue = queue.Queue(maxsize=config.queue_max)
        self._stop = threading.Event()
        self._idle = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False
        self.cursor = Cursor(cursor_path or config.cursor_path or default_cursor_path(ledger))
        self.states = [_SinkState(sink, *self._start_at(sink)) for sink in config.sinks]

    def _start_at(self, sink: Any) -> tuple[int, int]:
        """Where this sink starts, and which entries count as a replay."""
        size = self.ledger.size()
        if self.config.replay_from == "start":
            return -1, size
        if self.config.replay_from == "now" or not self.cursor.exists:
            return size - 1, size
        return min(self.cursor.get(sink.label, size - 1), size - 1), size

    # -- the ledger's side -------------------------------------------------

    def notify(self, seq: int) -> None:
        """Called by the ledger after an entry is on disk. Never raises, never blocks."""
        if self._closed:
            return
        try:
            self._queue.put_nowait(seq)
        except queue.Full:
            pass        # the sender reads the ledger, so it finds this entry on its next pass

    def report(self, kind: str, fields: Mapping[str, Any]) -> None:
        """Send an event that has no ledger entry behind it, such as the refused-token count."""
        if self._closed:
            return
        event = unledgered_event(kind, fields)
        for state in self.states:
            if len(state.pending) < MAX_PENDING_EVENTS:
                state.pending.append(event)
        self.notify(-1)

    # -- the sender --------------------------------------------------------

    def start(self) -> "Delivery":
        if self._thread is not None:
            return self
        self._thread = threading.Thread(target=self._run, name="two-key-siem", daemon=True)
        self._thread.start()
        atexit.register(self.close)
        return self

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wait()
            self._pass()
        self._pass()

    def _wait(self) -> None:
        try:
            self._queue.get(timeout=TICK_SECONDS)
        except queue.Empty:
            return
        while True:         # take whatever else is waiting; the ledger is the source either way
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def _pass(self) -> None:
        now = self._monotonic()
        for state in self.states:
            if state.ready(now):
                self._flush(state, now)
        self._idle.set()

    def _flush(self, state: _SinkState, now: float) -> None:
        size = self.ledger.size()
        if state.seq >= size:       # a recovered ledger dropped a tail this sink already took
            state.seq = size - 1
        batch = self._batch(state, size)
        if not batch:
            return
        try:
            state.sink.send(self._messages(state.sink, batch))
        except SiemError as e:
            state.fail(now)
            self._note(state, f"unreachable: {e}", now)
            return
        self._took(state, batch)
        if state.failed_at is not None:
            state.ok()
            state.replay_until = size
            self._note(state, "delivering again", now, force=True)

    def _batch(self, state: _SinkState, size: int) -> list[Event]:
        """The next events for this sink: its unledgered events first, then entries after its cursor."""
        batch = state.pending[: self.config.batch_max]
        room = self.config.batch_max - len(batch)
        entries = self.ledger.entries
        for seq in range(state.seq + 1, min(size, state.seq + 1 + room)):
            try:
                batch.append(event_for(entries[seq]))
            except IndexError:      # the ledger shrank under us (recover); the next pass re-reads it
                break
        sent_at = now_text(self._clock)
        return [e.at(sent_at, replay=e.ledgered and e.seq < state.replay_until) for e in batch]

    def _took(self, state: _SinkState, batch: Sequence[Event]) -> None:
        taken = len([e for e in batch if not e.ledgered])
        state.pending = state.pending[taken:]
        ledgered = [e.seq for e in batch if e.ledgered]
        if ledgered:
            state.seq = max(ledgered)
            self.cursor.set(state.label, state.seq)
            self.cursor.save()

    def _messages(self, sink: Any, events: Sequence[Event]) -> list[Message]:
        out = []
        for event in events:
            body = self.renderer.body(event)
            limit = getattr(sink, "max_body_bytes", None)
            if limit and len(body.encode("utf-8", "replace")) > limit:
                body = self.renderer.body(event.minimal())
            out.append(Message(event.severity, event.kind, body, event.sent_at))
        return out

    def _note(self, state: _SinkState, what: str, now: float, *, force: bool = False) -> None:
        if not force and now - state.reported < REPORT_SECONDS:
            return
        state.reported = now
        behind = max(0, self.ledger.size() - 1 - state.seq)
        print(f"two-key: siem: {state.label}: {what} ({behind} entries behind)", file=sys.stderr)

    # -- shutdown ----------------------------------------------------------

    def drain(self, timeout: float = DEFAULT_FLUSH_SECONDS) -> bool:
        """Wait (briefly) for one pass over every sink. For tests and for ``close``."""
        self._idle.clear()
        self.notify(-1)
        return self._idle.wait(timeout)

    def _close_wait(self) -> float:
        """How long ``close`` waits for the sender's last pass: what one try at every sink can take, with a
        ceiling. A sink already in backoff is skipped by that pass, so a collector known to be down costs
        nothing here."""
        each = sum(float(getattr(state.sink, "timeout_seconds", CLOSE_SINK_SECONDS) or CLOSE_SINK_SECONDS)
                   for state in self.states)
        return min(CLOSE_MAX_SECONDS, self.config.flush_seconds + each)

    def close(self) -> None:
        """Stop the sender, giving its last pass time to finish. Whatever is still left goes out on the next
        start, from the cursor."""
        if self._closed:
            return
        self._closed = True
        self._stop.set()
        self.notify(-1)
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(self._close_wait())
        for state in self.states:
            try:
                state.sink.close()
            except Exception:       # closing a socket is never a reason to fail a shutdown
                pass
        self.cursor.save()


def default_cursor_path(ledger: Any) -> Path:
    """``<ledger>.siem/cursor.json``, beside the ledger directory and never inside it.

    Takes a ``Ledger`` or the ledger path itself, so the start-up writable-path check can name the cursor
    before anything is opened (two_key/mcp_proxy/core.py).
    """
    path = Path(getattr(ledger, "path", None) or ledger or ".")
    return path.parent / f"{path.name}.siem" / "cursor.json"


def start_delivery(config: SiemConfig, ledger: Any, **kw) -> Delivery:
    """Check every sink, attach to the ledger, and start the sender. A sink that cannot be reached is a
    warning: the copy catches up from the cursor, and no decision waits on it."""
    delivery = Delivery(config, ledger, **kw)
    for sink in config.sinks:
        try:
            sink.check()
        except SiemError as e:
            print(f"two-key: WARNING: siem: {sink.label}: {e}; entries are kept in the ledger and sent "
                  "when it answers", file=sys.stderr)
    ledger.observe(delivery.notify)
    return delivery.start()


# ---------------------------------------------------------------------------- refused tokens


_REFUSAL_CLASSES = {"bad_signature": "bad_signature", "expired": "expired", "issued_in_future": "expired",
                    "malformed_token": "malformed"}
REFUSAL_COUNTS = ("bad_signature", "expired", "malformed", "other")


class RefusedTokens:
    """Counts tokens the gateway refused without a ledger entry, and reports the counts now and then.

    A token that does not verify is refused before anything is written, so an unauthenticated caller
    cannot fill the ledger -- and until 0.7.0 such a refusal left no trace at all. The counts here are the
    trace: a class and a number, never the token, its digest, or its jti (an unverified jti is caller
    text). Reported at most once per interval, so a flood of probes cannot flood the log either.
    """

    def __init__(self, *, interval_seconds: float = DEFAULT_REFUSED_INTERVAL_SECONDS,
                 report: Callable[[dict], None] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.interval_seconds = float(interval_seconds)
        self._report = report
        self._clock = clock
        self._lock = threading.Lock()
        self._counts = dict.fromkeys(REFUSAL_COUNTS, 0)
        self._window_start: float | None = None     # when counting for the next report began
        self._last_report: float | None = None

    def note(self, reason: Any) -> None:
        """Count one refusal. ``reason`` is the library's own ``TokenError`` code, never caller text."""
        name = _REFUSAL_CLASSES.get(str(reason).strip(), "other")
        with self._lock:
            self._counts[name] += 1
            now = self._clock()
            if self._window_start is None:
                self._window_start = now
            # The first refusal after a quiet interval is reported at once, so one probe is seen promptly;
            # the ones after it fold into the interval, so a flood cannot flood the log.
            if self._last_report is not None and now - self._last_report < self.interval_seconds:
                return
            counts = self._take(now)
        self._emit(counts)

    def counts(self) -> dict:
        """The counts not reported yet, for tests and integrations."""
        with self._lock:
            return dict(self._counts)

    def flush(self) -> dict | None:
        """Report whatever is counted now. Returns what was reported, or None."""
        with self._lock:
            if not any(self._counts.values()):
                return None
            counts = self._take(self._clock())
        self._emit(counts)
        return counts

    def _take(self, now: float) -> dict:
        counts = dict(self._counts)
        counts["total"] = sum(counts.values())
        counts["interval_seconds"] = round(max(0.0, now - (self._window_start or now)), 3)
        self._counts = dict.fromkeys(REFUSAL_COUNTS, 0)
        self._window_start = None
        self._last_report = now
        return counts

    def _emit(self, counts: dict) -> None:
        said = ", ".join(f"{name}={counts[name]}" for name in REFUSAL_COUNTS if counts[name])
        print(f"two-key: gateway refused {counts['total']} token(s) that did not verify in "
              f"{counts['interval_seconds']:g} s: {said}; no ledger entry (see docs/SIEM.md)",
              file=sys.stderr)
        if self._report is not None:
            try:
                self._report(counts)
            except Exception as e:      # the count is a report, never a reason to fail a call
                print(f"two-key: siem: could not report the refused-token count: {type(e).__name__}",
                      file=sys.stderr)


__all__ = ["Cursor", "Delivery", "ENVELOPE_KEYS", "Event", "KINDS", "KindSpec", "Message", "RefusedTokens", "Renderer",
           "SCHEMAS", "FORMATS", "SCHEMA_FORMAT", "SiemConfig", "SiemConfigError", "SiemError",
           "as_ecs", "as_native", "as_ocsf", "default_cursor_path", "event_for", "now_text", "project",
           "read_secret_file", "severity_of", "spec_for", "start_delivery", "to_cef", "to_json",
           "unledgered_event"]

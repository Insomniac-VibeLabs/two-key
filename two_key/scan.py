"""Content scanning (0.6.0): an antivirus or DLP product looks at a call before the two keys decide.

Two-Key starts every scan. The signed constitution says which tools are scanned (a tool that maps the scan
field, ``scan`` by default, as a caller-supplied field) and what the verdict does (a ``deny_if_fields`` rule:
the stance). The operator says which scanner to call and which arguments hold a file (``Scanner(files=)``,
or ``proxy.yaml``). Nothing the agent writes turns a scan on or off, picks what is scanned, or sets the
verdict: the verdict is a caller fact only Two-Key fills.

For each call to a scanned tool, after the call is read under its spec and before Path A evaluates it,
Two-Key sends the scanner (an ``Inspector``):

- ``arguments``: every argument, as canonical JSON, with each declared file shown as its digest. Keys the
  tool will not receive are included, because the judges can see them.
- ``proposal``: the proposal text, when there is one.
- ``file:<path>``: each declared file's bytes, decoded from base64 or read from its declared folder.

The answer is ``clean``, ``flagged``, or ``unavailable``. Two-Key, not the adapter, sets it when the scan
fails: a timeout, an exception, or an invalid result is ``unavailable``, so the fact is never missing and
never ``clean`` by accident. A result that names ``limits_exceeded`` (the scanner could not finish),
``unreadable``, or ``encrypted`` (it could not look inside) is ``flagged``. The one exception is signed: on a
tool whose spec maps the scan field with ``encrypted: pass``, a call whose only finding is ``encrypted`` gets
the fourth verdict ``encrypted``, which the stance rules do not deny; any other finding with it is still
``flagged``.

Every declared file states ``max_bytes``, the largest file the tool needs. A call whose files Two-Key cannot
read, or that is over a file limit, is not well-formed and within limits, so it is denied before the scanner
and both paths, under every stance (monitor too), and nothing is read past a limit: ``file_unreadable`` (bad
base64, a value of the wrong type, a path outside its folder, a link, a missing file, not a regular file),
``file_too_large`` (a file above its ``max_bytes``), ``too_many_files`` (more than ``MAX_FILES_PER_CALL``),
``call_files_too_large`` (more than ``MAX_CALL_FILE_BYTES`` together).

The judges get the verdict, never content: each file is replaced by its digest and size, and when the
verdict is ``flagged`` the arguments and proposal are withheld unless ``tool_args_on_scan_flag`` is set. The
ledger gets each part's size and SHA-256, never content. The token binds the verdict and each file's
SHA-256; the gateway checks the files again just before the tool runs (``file_changed``) and does not scan
twice.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import stat
import sys
import threading
import time
from dataclasses import dataclass
from functools import cached_property
from typing import Any, Iterable, Mapping, Protocol

from . import _platform
from .action import MAX_TOOL_NAME_CHARS, TOOL_NAME
from .agent_meta import type_tag
from .canonical import canonical_bytes, digest_hex
from .derive import MAX_ARGS_BYTES, caller_fields
from .fields import FIELD_NAME

VERDICTS = ("clean", "flagged", "unavailable")      # what an Inspector may answer
# The fourth verdict, only on a tool whose signed spec says encrypted: pass, and only Two-Key sets it.
ENCRYPTED = "encrypted"
CALL_VERDICTS = VERDICTS + (ENCRYPTED,)               # what a call's verdict may be
CATEGORIES = ("malware", "secret", "credential", "card_number", "personal_data", "health_data",
              "limits_exceeded", "policy", "unreadable", ENCRYPTED)
# Categories that mean the content was not fully scanned: flagged (could-not-finish is flagged), except
# ``encrypted`` alone on a tool that passes encrypted files.
_INCOMPLETE = ("limits_exceeded", "unreadable", ENCRYPTED)
FILE_KINDS = ("base64", "base64url", "path")
STANCES = ("strict", "default", "monitor")

DEFAULT_FIELD = "scan"
DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 300.0
MAX_FILE_BYTES = 100 * 1024 * 1024           # the most a path file's max_bytes may be
# A base64 file arrives inside the call, which is at most MAX_ARGS_BYTES (256 KiB): 196608 decoded bytes.
MAX_INLINE_FILE_BYTES = MAX_ARGS_BYTES * 3 // 4
MAX_FILES_PER_CALL = 32
MAX_CALL_FILE_BYTES = 100 * 1024 * 1024      # every declared file in one call, together
MAX_LABEL_CHARS = 64
MAX_FILES_PER_TOOL = 32
# Above this, scan time plus the judges' deadline can outlast an MCP client's tool-call timeout.
CLIENT_BUDGET_SECONDS = 60.0

_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[\])?")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


class ScanConfigError(ValueError):
    """Two-Key refuses this scanner configuration."""


class FileDeniedError(Exception):
    """A call with a declared file Two-Key cannot read, or over a file limit: denied before the scanner and
    both paths, under every stance. ``reason`` is the deny code; ``record`` (the file's argument path, why,
    and sizes, never content) goes to the ledger."""

    def __init__(self, reason: str, record: dict):
        super().__init__(reason)
        self.reason = reason
        self.record = record


class _Unreadable(Exception):
    """A declared file Two-Key cannot read. ``why`` is for the ledger: never the value."""

    def __init__(self, why: str):
        super().__init__(why)
        self.why = why


class _Over(Exception):
    """A file larger than the bytes left for it. ``size`` is what Two-Key saw: exact, or at least that."""

    def __init__(self, size: int):
        super().__init__(size)
        self.size = size


@dataclass(frozen=True)
class ScanPart:
    """One thing to scan: ``arguments``, ``proposal``, or ``file:<declared path>``."""
    name: str
    data: bytes

    @property
    def kind(self) -> str:
        return "file" if self.name.startswith("file:") else self.name

    @cached_property
    def sha256(self) -> str:
        return "sha256:" + digest_hex(self.data)


@dataclass(frozen=True)
class ScanRequest:
    """What an ``Inspector`` scans. ``deadline`` is a ``time.monotonic()`` value; answer before it."""
    tool: str
    parts: tuple[ScanPart, ...]
    deadline: float

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())


@dataclass(frozen=True)
class ScanResult:
    """An Inspector's answer. Never carries matched text or content.

    ``verdict`` is clean, flagged, or unavailable; ``categories`` come from ``CATEGORIES``. Use
    ``limits_exceeded`` when the scanner could not finish (size or time limits): Two-Key treats it as
    flagged. Use ``ScanResult.flagged("encrypted")`` when the product could not look inside because the content
    is encrypted. ``scanner`` and ``version`` label the product (printable ASCII, cut to 64 characters).
    """
    verdict: str
    categories: tuple[str, ...] = ()
    scanner: str = ""
    version: str = ""

    @classmethod
    def clean(cls, scanner: str = "", version: str = "") -> "ScanResult":
        return cls("clean", (), scanner, version)

    @classmethod
    def flagged(cls, *categories: str, scanner: str = "", version: str = "") -> "ScanResult":
        return cls("flagged", tuple(categories) or ("policy",), scanner, version)

    @classmethod
    def unavailable(cls, scanner: str = "", version: str = "") -> "ScanResult":
        return cls("unavailable", (), scanner, version)


class Inspector(Protocol):
    """A scanner adapter. ``inspect`` is called from a worker thread, possibly while an earlier call that ran
    out of time is still running: it must be thread-safe. Return within ``request.remaining()`` seconds.
    Raise, or return ``unavailable``, when the scanner cannot answer. Never return content."""

    def inspect(self, request: ScanRequest) -> ScanResult:
        ...


def combine(results: Iterable[ScanResult]) -> ScanResult:
    """One result for several parts: flagged if any part is, else unavailable if any is, else clean.

    When the only finding is ``encrypted`` and another part could not be scanned, the result is unavailable
    with the category ``encrypted``, so a tool that passes encrypted files still sees the part that was not
    scanned (and any other tool still sees the encrypted finding)."""
    results = list(results)
    if not results:
        return ScanResult.unavailable()
    first = results[0]
    flagged = [r for r in results if r.verdict == "flagged"]
    if flagged:
        cats = sorted({c for r in flagged for c in (r.categories or ("policy",))})
        if cats == [ENCRYPTED] and any(r.verdict == "unavailable" for r in results):
            return ScanResult("unavailable", (ENCRYPTED,), first.scanner, first.version)
        return ScanResult("flagged", tuple(cats), first.scanner, first.version)
    if any(r.verdict != "clean" for r in results):
        return ScanResult.unavailable(first.scanner, first.version)
    return ScanResult.clean(first.scanner, first.version)


def _label(value: Any) -> str:
    """Printable ASCII, at most MAX_LABEL_CHARS: a scanner label is the product's text, kept small and plain."""
    if not isinstance(value, str):
        return ""
    return "".join(ch for ch in value if " " <= ch <= "~")[:MAX_LABEL_CHARS].strip()


@dataclass(frozen=True)
class FileArg:
    """An argument that holds a file. ``path`` is a dotted argument path where ``[]`` means each item of a
    list (``attachments[].content``). ``kind``: ``base64``, ``base64url``, or ``path`` (a file path the tool
    reads, which must lie in ``folder``, an absolute directory the operator names). ``max_bytes`` (required)
    is the largest file the tool needs: at most ``MAX_INLINE_FILE_BYTES`` for base64, which arrives inside
    the call, and ``MAX_FILE_BYTES`` for a path."""
    path: str
    kind: str = "base64"
    folder: str | None = None
    max_bytes: int | None = None

    def segments(self) -> list[tuple[str, bool]]:
        return [(seg[:-2], True) if seg.endswith("[]") else (seg, False) for seg in self.path.split(".")]

    def key_path(self) -> str:
        """The path without ``[]``: the argument a payload path must cover."""
        return ".".join(name for name, _ in self.segments())

    def to_record(self) -> dict:
        rec = {"path": self.path, "kind": self.kind, "max_bytes": self.max_bytes}
        if self.folder is not None:
            rec["folder"] = self.folder
        return rec


_FILE_KEYS = ("folder", "kind", "max_bytes", "path")


def file_arg(value: Any, where: str) -> FileArg:
    """A checked ``FileArg`` from a ``FileArg`` or ``{path, kind, folder, max_bytes}``. Raises
    ``ScanConfigError``."""
    if isinstance(value, FileArg):
        item = value
    elif isinstance(value, Mapping):
        extra = sorted(str(k) for k in set(value) - set(_FILE_KEYS))
        if extra:
            raise ScanConfigError(f"{where}: unknown key(s) {extra}; allowed: {list(_FILE_KEYS)}")
        item = FileArg(value.get("path"), value.get("kind", "base64"), value.get("folder"), value.get("max_bytes"))
    else:
        raise ScanConfigError(f"{where}: expected {{path: ..., kind: base64|base64url|path, max_bytes: ...}}")
    if not isinstance(item.path, str) or not item.path or len(item.path) > 512:
        raise ScanConfigError(f"{where}.path: expected an argument path such as attachments[].content")
    if not all(_SEGMENT.fullmatch(seg) for seg in item.path.split(".")) or item.path.count(".") >= 16:
        raise ScanConfigError(f"{where}.path: {item.path[:80]!r} is not an argument path (names joined by '.', "
                              "'[]' after a name for each item of a list)")
    if item.kind not in FILE_KINDS:
        raise ScanConfigError(f"{where}.kind: expected one of {list(FILE_KINDS)}")
    if item.kind == "path":
        if not isinstance(item.folder, (str, os.PathLike)) or not os.fspath(item.folder):
            raise ScanConfigError(f"{where}.folder: a path file needs the folder it must be in")
        folder = os.fspath(item.folder)
        if not os.path.isabs(folder):
            raise ScanConfigError(f"{where}.folder: expected an absolute path")
        if not os.path.isdir(folder):
            raise ScanConfigError(f"{where}.folder: {folder} is not a directory")
        item = FileArg(item.path, item.kind, os.path.normpath(folder), item.max_bytes)
    elif item.folder is not None:
        raise ScanConfigError(f"{where}.folder: only a kind: path file has a folder")
    # Required, with no default: the operator says how large a file the tool needs.
    limit = MAX_FILE_BYTES if item.kind == "path" else MAX_INLINE_FILE_BYTES
    size = item.max_bytes
    if size is None:
        raise ScanConfigError(f"{where}.max_bytes: required: the largest file this argument needs, in bytes "
                              f"(at most {limit} for kind {item.kind})")
    if isinstance(size, bool) or not isinstance(size, int) or size < 1:
        raise ScanConfigError(f"{where}.max_bytes: expected a whole number of bytes from 1 to {limit}")
    if size > limit:
        if item.kind == "path":
            raise ScanConfigError(f"{where}.max_bytes: at most {MAX_FILE_BYTES} (100 MiB) for a path file")
        raise ScanConfigError(f"{where}.max_bytes: a {item.kind} file arrives inside the call, which is at most "
                              f"{MAX_ARGS_BYTES // 1024} KiB, so at most {MAX_INLINE_FILE_BYTES} bytes; a tool that "
                              "needs larger files takes a path (kind: path)")
    return item


def stance_of(rules: list, field_name: str) -> str:
    """``strict`` when a signed rule on the scan field alone denies both flagged and unavailable, ``default``
    when one denies flagged, else ``monitor``. A rule with other conditions does not count, so a stance that
    depends on them reads as the weaker one."""
    denies = set()
    for rule in rules:
        body = rule.get("deny_if_fields") if isinstance(rule, Mapping) else None
        if not isinstance(body, Mapping) or set(body) != {field_name}:
            continue
        ops = body[field_name]
        for verdict in ("flagged", "unavailable"):
            if all(_holds(op, verdict, lit) for op, lit in ops.items()):
                denies.add(verdict)
    if {"flagged", "unavailable"} <= denies:
        return "strict"
    return "default" if "flagged" in denies else "monitor"


def denies_encrypted(rules: list, field_name: str) -> bool:
    """True when a signed rule on the scan field alone denies the verdict ``encrypted``."""
    for rule in rules:
        body = rule.get("deny_if_fields") if isinstance(rule, Mapping) else None
        if isinstance(body, Mapping) and set(body) == {field_name} and \
                all(_holds(op, ENCRYPTED, lit) for op, lit in body[field_name].items()):
            return True
    return False


def _holds(op: str, value: str, literal: Any) -> bool:
    if isinstance(literal, str):
        literal = literal.strip().casefold()
    elif isinstance(literal, list):
        literal = [x.strip().casefold() if isinstance(x, str) else x for x in literal]
    if op == "eq":
        return value == literal
    if op == "neq":
        return value != literal
    if op == "in":
        return value in literal
    if op == "not_in":
        return value not in literal
    return False


@dataclass
class Prepared:
    """A call made ready to scan: the parts, what the judges may see, and each file's record."""
    parts: tuple[ScanPart, ...]
    judge_args: Any
    files: list[dict]


@dataclass(frozen=True)
class Outcome:
    """The verdict for one call, as Two-Key settled it, and the records built from it."""
    tool: str
    verdict: str
    categories: tuple[str, ...]
    scanner: str
    version: str
    elapsed_ms: int
    available: bool
    error: str | None
    parts: tuple[dict, ...]
    files: tuple[dict, ...]
    judge_args: Any = None

    def token_claim(self) -> dict:
        """Bound into the token: the verdict and each file's digest, checked again at redemption."""
        return {"verdict": self.verdict, "files": [dict(f) for f in self.files]}

    def ledger_record(self, stance: str) -> dict:
        rec = {"tool": self.tool, "scanner": self.scanner, "version": self.version, "verdict": self.verdict,
               "categories": list(self.categories), "stance": stance, "elapsed_ms": self.elapsed_ms,
               "scanner_available": self.available, "parts": [dict(p) for p in self.parts]}
        if self.error:
            rec["error"] = self.error
        return rec

    def judge_summary(self, withheld: bool) -> dict:
        return {"scanner": " ".join(x for x in (self.scanner, self.version) if x), "verdict": self.verdict,
                "categories": list(self.categories), "files": len(self.files), "arguments_withheld": withheld}


class Scanner:
    """The scanner Two-Key calls, and how: ``TwoKey(..., scanner=Scanner(inspector, files=...))``.

    ``files`` maps a signed tool id to its file arguments (``FileArg`` or ``{path, kind, folder,
    max_bytes}``); each states ``max_bytes``. ``timeout_seconds`` bounds each scan (15 by default).
    ``field`` names the caller-supplied enum field that holds the verdict (``scan``). ``label`` names the
    scanner in the ledger when its results do not.
    """

    def __init__(self, inspector: Inspector, *, files: Mapping[str, Iterable[Any]] | None = None,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS, field: str = DEFAULT_FIELD,
                 label: str | None = None):
        if not callable(getattr(inspector, "inspect", None)):
            raise ScanConfigError("scanner: the inspector needs an inspect(request) method")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise ScanConfigError(f"timeout_seconds: expected a number in (0, {MAX_TIMEOUT_SECONDS:g}]")
        if not isinstance(field, str) or not FIELD_NAME.fullmatch(field):
            raise ScanConfigError("field: expected a field name")
        self.inspector = inspector
        self.timeout_seconds = float(timeout_seconds)
        self.field = field
        self.label = _label(label if label is not None else getattr(inspector, "label", type(inspector).__name__))
        self.files: dict[str, tuple[FileArg, ...]] = {}
        for tool, items in (files or {}).items():
            if not isinstance(tool, str) or len(tool) > MAX_TOOL_NAME_CHARS or not TOOL_NAME.fullmatch(tool):
                raise ScanConfigError(f"files: {str(tool)[:80]!r} is not a signed tool id")
            if isinstance(items, (str, bytes, Mapping)) or not isinstance(items, Iterable):
                raise ScanConfigError(f"files.{tool}: expected a list of file arguments")
            parsed = tuple(file_arg(item, f"files.{tool}[{i}]") for i, item in enumerate(items))
            if len(parsed) > MAX_FILES_PER_TOOL:
                raise ScanConfigError(f"files.{tool}: more than {MAX_FILES_PER_TOOL} file arguments")
            if len({f.path for f in parsed}) != len(parsed):
                raise ScanConfigError(f"files.{tool}: a path is declared twice")
            self.files[tool] = parsed
        self._lock = threading.Lock()
        self._down = False
        self._stance = "monitor"
        self._encrypted_tools: tuple[str, ...] = ()

    # -- start-up ------------------------------------------------------------------------------------------
    def bind(self, compiled) -> list[str]:
        """Check this configuration against the signed constitution. Returns notes for stderr."""
        registry = compiled.fields or {}
        defn = registry.get(self.field)
        if defn is None:
            raise ScanConfigError(f"scan_field_missing: the constitution declares no field {self.field!r}; declare "
                                  f"{self.field}: {{type: enum, values: [clean, flagged, unavailable], default: "
                                  "clean, source: caller}} and map it on each tool to scan")
        specs = compiled.tool_specs or {}
        self._check_encrypted_marks(specs)
        passing = sorted(t for t, s in specs.items() if self.passes_encrypted(s))
        values = set(defn.get("values") or ())
        if defn.get("type") != "enum" or defn.get("source") != "caller" or not set(VERDICTS) <= values <= set(CALL_VERDICTS):
            raise ScanConfigError(f"scan_field_invalid: {self.field!r} must be a caller-supplied enum (source: caller) "
                                  "with exactly the values clean, flagged, unavailable (and encrypted when a tool "
                                  "passes encrypted files)")
        if passing and ENCRYPTED not in values:
            raise ScanConfigError(f"scan_field_invalid: {', '.join(passing)} pass encrypted files (encrypted: pass), so "
                                  f"{self.field!r} needs the values clean, flagged, unavailable, encrypted")
        if ENCRYPTED in values and not passing:
            raise ScanConfigError(f"scan_field_invalid: the value encrypted is only for a tool that passes encrypted "
                                  f"files; mark one {self.field}: {{source: caller, encrypted: pass}} or remove the "
                                  "value")
        for tool, items in self.files.items():
            spec = specs.get(tool)
            if spec is None:
                raise ScanConfigError(f"files.{tool}: not a tool in the signed constitution")
            if not self.scans(spec):
                raise ScanConfigError(f"files.{tool}: the tool does not map {self.field!r}, so it is not scanned; "
                                      f"map {self.field}: {{source: caller}} in its spec")
            payload = [e["json_path"] for e in spec.get("payload") or []
                       if isinstance(e, Mapping) and isinstance(e.get("json_path"), str)]
            for item in items:
                key = item.key_path()
                if not any(key == p or key.startswith(p + ".") for p in payload):
                    raise ScanConfigError(f"files.{tool}: {item.path!r} is not under a payload path the signed spec "
                                          "passes to the tool")
        self._stance = stance_of(compiled.rules, self.field)
        self._encrypted_tools = tuple(passing)
        scanned = sorted(t for t, s in specs.items() if self.scans(s))
        unscanned = sorted(set(specs) - set(scanned))
        notes = [f"scanner {self.label or 'configured'}: stance {self._stance}; scans {len(scanned)} of "
                 f"{len(specs)} tool(s)"]
        if unscanned:
            notes.append(f"not scanned (they do not map {self.field}): {', '.join(unscanned)}")
        if passing:
            notes.append(f"encrypted files pass without a look inside (encrypted: pass): {', '.join(passing)}")
            if denies_encrypted(compiled.rules, self.field):
                notes.append(f"a rule on {self.field} alone denies encrypted, so encrypted: pass lets nothing more "
                             "through")
        return notes

    def _check_encrypted_marks(self, specs: Mapping[str, Any]) -> None:
        """``encrypted: pass`` belongs on the scan field only: on any other field it would mean nothing."""
        for tool in sorted(specs):
            for name, entry in sorted((specs[tool].get("fields") or {}).items()):
                if isinstance(entry, Mapping) and "encrypted" in entry and name != self.field:
                    raise ScanConfigError(f"tool_specs.{tool}.fields.{name}: encrypted: pass is only valid on the scan "
                                          f"field {self.field!r}")

    @property
    def stance(self) -> str:
        return self._stance

    def scans(self, spec: Mapping[str, Any] | None) -> bool:
        """Whether calls to a tool with this spec are scanned: it maps the scan field as a caller field."""
        return isinstance(spec, Mapping) and self.field in caller_fields(spec)

    def passes_encrypted(self, spec: Mapping[str, Any] | None) -> bool:
        """Whether the principal signed this tool to pass encrypted files: ``encrypted: pass`` on the scan field."""
        entry = (spec.get("fields") or {}).get(self.field) if isinstance(spec, Mapping) else None
        return (isinstance(entry, Mapping) and entry.get("source") == "caller"
                and entry.get("encrypted") == "pass")

    def to_record(self) -> dict:
        """For ``constitution_loaded``: the configuration, never a secret (an adapter's address is not one)."""
        rec = {"field": self.field, "label": self.label, "stance": self._stance,
               "timeout_seconds": self.timeout_seconds,
               "files": {tool: [f.to_record() for f in items] for tool, items in sorted(self.files.items())}}
        if self._encrypted_tools:
            rec["encrypted_pass"] = list(self._encrypted_tools)
        return rec

    # -- one call ------------------------------------------------------------------------------------------
    def _occurrences(self, arguments: Any, item: FileArg) -> list[tuple[str, Any, list]]:
        """Each value at ``item.path``: (concrete name, value, location to replace it). A missing key is no
        file; a value of the wrong type on the way (a list where a name is expected) is unreadable."""
        found: list[tuple[str, Any, list]] = []

        def walk(node: Any, segs: list[tuple[str, bool]], name: str, parent: Any, key: Any) -> None:
            if not segs:
                found.append((name, node, [parent, key]))
                return
            seg, each = segs[0]
            if not isinstance(node, dict):
                found.append((name, _Unreadable("not_an_object"), [parent, key]))
                return
            if seg not in node:
                return
            child_name = f"{name}.{seg}" if name else seg
            child = node[seg]
            if not each:
                walk(child, segs[1:], child_name, node, seg)
                return
            if not isinstance(child, list):
                found.append((child_name, _Unreadable("not_a_list"), [node, seg]))
                return
            for i, value in enumerate(child):
                walk(value, segs[1:], f"{child_name}[{i}]", child, i)

        walk(arguments, item.segments(), "", None, None)
        return found

    def _decode(self, value: Any, kind: str) -> bytes:
        if not isinstance(value, str):
            raise _Unreadable("not_a_string")
        text = value.replace("\r", "").replace("\n", "")
        pattern = _BASE64URL if kind == "base64url" else _BASE64
        if not pattern.fullmatch(text) or len(text.rstrip("=")) % 4 == 1:
            raise _Unreadable(f"bad_{kind}")
        text += "=" * (-len(text) % 4)
        try:
            data = (base64.urlsafe_b64decode(text) if kind == "base64url"
                    else base64.b64decode(text, validate=True))
        except (binascii.Error, ValueError):
            raise _Unreadable(f"bad_{kind}") from None
        return data

    def read_confined(self, value: Any, folder: str, limit: int) -> bytes:
        """The file at ``value``, which must be an absolute path inside ``folder`` with no link or junction
        below the folder. Opened without following a link; a regular file of at most ``limit`` bytes (``_Over``
        past it: nothing beyond ``limit`` is kept, and a file whose size says it is larger is not read)."""
        if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
            raise _Unreadable("not_a_path")
        if not os.path.isabs(value) or any(p in (".", "..") for p in re.split(r"[\\/]", value)):
            raise _Unreadable("not_absolute")
        norm = os.path.normpath(value)
        base = os.path.normpath(folder)
        if os.path.normcase(norm) == os.path.normcase(base) or not os.path.normcase(norm).startswith(
                os.path.normcase(base).rstrip("\\/") + os.sep):
            raise _Unreadable("outside_folder")
        expected = os.path.join(os.path.realpath(base), os.path.relpath(norm, base))
        if os.path.normcase(os.path.realpath(norm)) != os.path.normcase(expected):
            raise _Unreadable("link")      # a link or junction inside the folder: the tool could be sent elsewhere
        try:
            fd = _platform.open_nofollow(norm)
        except OSError:
            raise _Unreadable("cannot_open") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise _Unreadable("not_a_file")
            if st.st_size > limit:
                raise _Over(st.st_size)
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:      # it grew after fstat
                    raise _Over(total)
            return b"".join(chunks)
        except OSError:
            raise _Unreadable("cannot_read") from None
        finally:
            os.close(fd)

    def _files(self, tool: str, arguments: Any) -> list[tuple[str, FileArg, Any, bytes, list]]:
        """(name, declaration, raw value, bytes, location) per declared file in the call.

        Raises ``FileDeniedError`` for a file Two-Key cannot read or a call over a file limit. The files are
        counted before any is read, and each read stops at the smaller of its ``max_bytes`` and what the call
        has left."""
        found = [(item, occ) for item in self.files.get(tool, ()) for occ in self._occurrences(arguments, item)]
        if len(found) > MAX_FILES_PER_CALL:
            raise FileDeniedError("too_many_files", {"files": len(found), "max_files": MAX_FILES_PER_CALL})
        out = []
        total = 0
        for item, (name, value, where) in found:
            limit = min(item.max_bytes, MAX_CALL_FILE_BYTES - total)
            try:
                if isinstance(value, _Unreadable):
                    raise value
                if item.kind == "path":
                    data = self.read_confined(value, item.folder, limit)
                else:
                    data = self._decode(value, item.kind)
                    if len(data) > limit:
                        raise _Over(len(data))
            except _Unreadable as e:
                raise FileDeniedError("file_unreadable", {"file": name, "kind": item.kind, "why": e.why}) from None
            except _Over as over:
                if over.size > item.max_bytes:
                    raise FileDeniedError("file_too_large", {"file": name, "bytes": over.size,
                                                             "max_bytes": item.max_bytes}) from None
                raise FileDeniedError("call_files_too_large", {"file": name, "bytes": total + over.size,
                                                               "max_bytes": MAX_CALL_FILE_BYTES}) from None
            total += len(data)
            out.append((name, item, value, data, where))
        return out

    def prepare(self, tool: str, arguments: Any, proposal: Any) -> Prepared:
        """Build the parts for one call. ``arguments`` and ``proposal`` are Two-Key's plain copies. Raises
        ``FileDeniedError`` when a declared file cannot be read or the call is over a file limit."""
        judge_args = _deep_copy(arguments)
        files = self._files(tool, judge_args)
        parts: list[ScanPart] = []
        records: list[dict] = []
        for name, item, value, data, where in files:
            part = ScanPart(f"file:{name}", data)
            parts.append(part)
            descriptor = {"sha256": part.sha256, "bytes": len(data)}
            records.append({"part": name, "sha256": part.sha256})
            if item.kind == "path":
                descriptor["path"] = value
            parent, key = where
            if parent is not None:
                parent[key] = {"two_key_file": descriptor}
        text = canonical_bytes(judge_args)
        head = [ScanPart("arguments", text)]
        if isinstance(proposal, str):
            if proposal:
                head.append(ScanPart("proposal", proposal.encode("utf-8", "surrogatepass")))
        elif proposal is not None:
            head.append(ScanPart("proposal", canonical_bytes(proposal)))
        return Prepared(tuple(head + parts), judge_args, records)

    def _inspect(self, request: ScanRequest) -> tuple[ScanResult | None, str | None]:
        """Run the inspector under the deadline. (result, None) or (None, why it is unavailable)."""
        box: dict[str, Any] = {}
        done = threading.Event()

        def run() -> None:
            try:
                box["result"] = self.inspector.inspect(request)
            except Exception as e:      # an adapter that failed: unavailable, never clean
                box["error"] = f"exception:{type_tag(e)}"
            finally:
                done.set()

        threading.Thread(target=run, name="twokey-scan", daemon=True).start()
        if not done.wait(self.timeout_seconds):
            return None, "timeout"
        if "error" in box:
            return None, box["error"]
        return _valid(box.get("result"))

    def run(self, tool: str, prepared: Prepared, *, encrypted_pass: bool = False) -> Outcome:
        """Scan one call. Never raises: every scanner failure is an ``unavailable`` outcome.

        ``encrypted_pass`` is the tool's signed ``encrypted: pass``: a call whose only finding is ``encrypted``
        then gets the verdict ``encrypted`` (or ``unavailable`` when another part could not be scanned)."""
        started = time.monotonic()
        request = ScanRequest(tool, prepared.parts, started + self.timeout_seconds)
        try:
            result, error = self._inspect(request)
        except Exception as e:          # starting the worker failed: still an answer, never an allow by accident
            result, error = None, f"exception:{type_tag(e)}"
        elapsed = int((time.monotonic() - started) * 1000)
        available = result is not None and result.verdict != "unavailable"
        if result is None:
            result = ScanResult.unavailable()
        verdict, categories = result.verdict, set(result.categories)
        if encrypted_pass and categories == {ENCRYPTED}:
            # Signed for this tool: encryption alone is not a finding. A part that could not be scanned still is
            # unavailable, so the strict stance still denies it.
            if verdict != "unavailable":
                verdict = ENCRYPTED
        elif categories & set(_INCOMPLETE):
            verdict = "flagged"           # the scanner could not finish: flagged, not clean or unavailable
        if verdict not in ("flagged", ENCRYPTED):
            categories = set()
        elif not categories:
            categories = {"policy"}
        parts = tuple({"part": p.name, "bytes": len(p.data), "sha256": p.sha256} for p in prepared.parts)
        return Outcome(tool, verdict, tuple(sorted(categories)), _label(result.scanner) or self.label,
                       _label(result.version), elapsed, available, error, parts, tuple(prepared.files),
                       prepared.judge_args)

    def transition(self, available: bool) -> str | None:
        """``down`` the first time the scanner cannot answer, ``up`` when it answers again, else None."""
        with self._lock:
            if not available and not self._down:
                self._down = True
                return "down"
            if available and self._down:
                self._down = False
                return "up"
        return None

    def file_digests(self, tool: str, arguments: Any) -> list[dict]:
        """Each declared file's digest, read again (for the gateway, just before the tool runs). A file it cannot
        read, or one over a limit, raises, and the gateway denies ``file_changed``: not the file that was
        scanned."""
        out = []
        for name, _item, _value, data, _where in self._files(tool, _deep_copy(arguments)):
            out.append({"part": name, "sha256": "sha256:" + digest_hex(data)})
        return out


def _valid(result: Any) -> tuple[ScanResult | None, str | None]:
    """A result Two-Key can use, or why not. Unknown verdicts or categories make the answer unavailable."""
    if not isinstance(result, ScanResult):
        return None, "invalid_result"
    if result.verdict not in VERDICTS:
        return None, "invalid_result"
    cats = result.categories
    if isinstance(cats, (str, bytes)) or not isinstance(cats, (tuple, list)) or \
            any(c not in CATEGORIES for c in cats):
        return None, "invalid_result"
    return ScanResult(result.verdict, tuple(cats), result.scanner, result.version), None


def _deep_copy(value: Any) -> Any:
    """A copy of plain JSON data (dicts and lists), so replacing a file value never touches the original."""
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


def warn(message: str) -> None:
    print(f"two-key: {message}", file=sys.stderr)


__all__ = ["CALL_VERDICTS", "CATEGORIES", "ENCRYPTED", "FILE_KINDS", "FileArg", "FileDeniedError", "file_arg", "Inspector", "Outcome", "ScanConfigError", "ScanPart",
           "ScanRequest", "ScanResult", "Scanner", "VERDICTS", "combine", "denies_encrypted", "stance_of"]

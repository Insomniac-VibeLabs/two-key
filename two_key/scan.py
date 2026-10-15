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
never ``clean`` by accident. A result that names ``limits_exceeded`` (the scanner could not finish) or
``unreadable`` is ``flagged``, and so is any call with a declared file Two-Key could not read (bad base64,
a path outside its folder, a link, a missing file, one over ``max_file_bytes``).

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
from .derive import caller_fields
from .fields import FIELD_NAME

VERDICTS = ("clean", "flagged", "unavailable")
CATEGORIES = ("malware", "secret", "credential", "card_number", "personal_data", "health_data",
              "limits_exceeded", "policy", "unreadable")
# Categories that mean the content was not fully scanned: always flagged (could-not-finish is flagged).
_INCOMPLETE = ("limits_exceeded", "unreadable")
FILE_KINDS = ("base64", "base64url", "path")
STANCES = ("strict", "default", "monitor")

DEFAULT_FIELD = "scan"
DEFAULT_TIMEOUT_SECONDS = 15.0
MAX_TIMEOUT_SECONDS = 300.0
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_LABEL_CHARS = 64
MAX_FILES_PER_TOOL = 32
# Above this, scan time plus the judges' deadline can outlast an MCP client's tool-call timeout.
CLIENT_BUDGET_SECONDS = 60.0

_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[\])?")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


class ScanConfigError(ValueError):
    """Two-Key refuses this scanner configuration."""


class _Unreadable(Exception):
    def __init__(self, category: str = "unreadable"):
        super().__init__(category)
        self.category = category


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
    flagged. ``scanner`` and ``version`` label the product (printable ASCII, cut to 64 characters).
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
    """One result for several parts: flagged if any part is, else unavailable if any is, else clean."""
    results = list(results)
    if not results:
        return ScanResult.unavailable()
    first = results[0]
    flagged = [r for r in results if r.verdict == "flagged"]
    if flagged:
        cats = sorted({c for r in flagged for c in r.categories}) or ["policy"]
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
    reads, which must lie in ``folder``, an absolute directory the operator names)."""
    path: str
    kind: str = "base64"
    folder: str | None = None

    def segments(self) -> list[tuple[str, bool]]:
        return [(seg[:-2], True) if seg.endswith("[]") else (seg, False) for seg in self.path.split(".")]

    def key_path(self) -> str:
        """The path without ``[]``: the argument a payload path must cover."""
        return ".".join(name for name, _ in self.segments())

    def to_record(self) -> dict:
        rec = {"path": self.path, "kind": self.kind}
        if self.folder is not None:
            rec["folder"] = self.folder
        return rec


def _file_arg(value: Any, where: str) -> FileArg:
    if isinstance(value, FileArg):
        item = value
    elif isinstance(value, Mapping):
        extra = sorted(str(k) for k in set(value) - {"path", "kind", "folder"})
        if extra:
            raise ScanConfigError(f"{where}: unknown key(s) {extra}; allowed: ['folder', 'kind', 'path']")
        item = FileArg(value.get("path"), value.get("kind", "base64"), value.get("folder"))
    else:
        raise ScanConfigError(f"{where}: expected {{path: ..., kind: base64|base64url|path}}")
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
        item = FileArg(item.path, item.kind, os.path.normpath(folder))
    elif item.folder is not None:
        raise ScanConfigError(f"{where}.folder: only a kind: path file has a folder")
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
    forced: tuple[str, ...] = ()


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

    ``files`` maps a signed tool id to its file arguments (``FileArg`` or ``{path, kind, folder}``).
    ``timeout_seconds`` bounds each scan (15 by default); ``max_file_bytes`` bounds a file read from a
    folder (25 MiB by default, 100 MiB at most). ``field`` names the caller-supplied enum field that holds
    the verdict (``scan``). ``label`` names the scanner in the ledger when its results do not.
    """

    def __init__(self, inspector: Inspector, *, files: Mapping[str, Iterable[Any]] | None = None,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
                 field: str = DEFAULT_FIELD, label: str | None = None):
        if not callable(getattr(inspector, "inspect", None)):
            raise ScanConfigError("scanner: the inspector needs an inspect(request) method")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise ScanConfigError(f"timeout_seconds: expected a number in (0, {MAX_TIMEOUT_SECONDS:g}]")
        if isinstance(max_file_bytes, bool) or not isinstance(max_file_bytes, int) or \
                not 1 <= max_file_bytes <= MAX_FILE_BYTES:
            raise ScanConfigError(f"max_file_bytes: expected an integer from 1 to {MAX_FILE_BYTES}")
        if not isinstance(field, str) or not FIELD_NAME.fullmatch(field):
            raise ScanConfigError("field: expected a field name")
        self.inspector = inspector
        self.timeout_seconds = float(timeout_seconds)
        self.max_file_bytes = max_file_bytes
        self.field = field
        self.label = _label(label if label is not None else getattr(inspector, "label", type(inspector).__name__))
        self.files: dict[str, tuple[FileArg, ...]] = {}
        for tool, items in (files or {}).items():
            if not isinstance(tool, str) or len(tool) > MAX_TOOL_NAME_CHARS or not TOOL_NAME.fullmatch(tool):
                raise ScanConfigError(f"files: {str(tool)[:80]!r} is not a signed tool id")
            if isinstance(items, (str, bytes, Mapping)) or not isinstance(items, Iterable):
                raise ScanConfigError(f"files.{tool}: expected a list of file arguments")
            parsed = tuple(_file_arg(item, f"files.{tool}[{i}]") for i, item in enumerate(items))
            if len(parsed) > MAX_FILES_PER_TOOL:
                raise ScanConfigError(f"files.{tool}: more than {MAX_FILES_PER_TOOL} file arguments")
            if len({f.path for f in parsed}) != len(parsed):
                raise ScanConfigError(f"files.{tool}: a path is declared twice")
            self.files[tool] = parsed
        self._lock = threading.Lock()
        self._down = False
        self._stance = "monitor"

    # -- start-up ------------------------------------------------------------------------------------------
    def bind(self, compiled) -> list[str]:
        """Check this configuration against the signed constitution. Returns notes for stderr."""
        registry = compiled.fields or {}
        defn = registry.get(self.field)
        if defn is None:
            raise ScanConfigError(f"scan_field_missing: the constitution declares no field {self.field!r}; declare "
                                  f"{self.field}: {{type: enum, values: [clean, flagged, unavailable], default: "
                                  "clean, source: caller}} and map it on each tool to scan")
        if defn.get("type") != "enum" or defn.get("source") != "caller" or set(defn.get("values") or ()) != set(VERDICTS):
            raise ScanConfigError(f"scan_field_invalid: {self.field!r} must be a caller-supplied enum (source: caller) "
                                  "with exactly the values clean, flagged, unavailable")
        specs = compiled.tool_specs or {}
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
        scanned = sorted(t for t, s in specs.items() if self.scans(s))
        unscanned = sorted(set(specs) - set(scanned))
        notes = [f"scanner {self.label or 'configured'}: stance {self._stance}; scans {len(scanned)} of "
                 f"{len(specs)} tool(s)"]
        if unscanned:
            notes.append(f"not scanned (no {self.field} mapping): {', '.join(unscanned)}")
        return notes

    @property
    def stance(self) -> str:
        return self._stance

    def scans(self, spec: Mapping[str, Any] | None) -> bool:
        """Whether calls to a tool with this spec are scanned: it maps the scan field as a caller field."""
        return isinstance(spec, Mapping) and self.field in caller_fields(spec)

    def to_record(self) -> dict:
        """For ``constitution_loaded``: the configuration, never a secret (an adapter's address is not one)."""
        return {"field": self.field, "label": self.label, "stance": self._stance,
                "timeout_seconds": self.timeout_seconds, "max_file_bytes": self.max_file_bytes,
                "files": {tool: [f.to_record() for f in items] for tool, items in sorted(self.files.items())}}

    # -- one call ------------------------------------------------------------------------------------------
    def _occurrences(self, arguments: Any, item: FileArg) -> list[tuple[str, Any, list]]:
        """Each value at ``item.path``: (concrete name, value, location to replace it). A missing key is no
        file; a value of the wrong kind on the way (a list where a name is expected) is unreadable."""
        found: list[tuple[str, Any, list]] = []

        def walk(node: Any, segs: list[tuple[str, bool]], name: str, parent: Any, key: Any) -> None:
            if not segs:
                found.append((name, node, [parent, key]))
                return
            seg, each = segs[0]
            if not isinstance(node, dict):
                found.append((name, _Unreadable(), [parent, key]))
                return
            if seg not in node:
                return
            child_name = f"{name}.{seg}" if name else seg
            child = node[seg]
            if not each:
                walk(child, segs[1:], child_name, node, seg)
                return
            if not isinstance(child, list):
                found.append((child_name, _Unreadable(), [node, seg]))
                return
            for i, value in enumerate(child):
                walk(value, segs[1:], f"{child_name}[{i}]", child, i)

        walk(arguments, item.segments(), "", None, None)
        return found

    def _decode(self, value: Any, kind: str) -> bytes:
        if not isinstance(value, str):
            raise _Unreadable()
        text = value.replace("\r", "").replace("\n", "")
        pattern = _BASE64URL if kind == "base64url" else _BASE64
        if not pattern.fullmatch(text) or len(text.rstrip("=")) % 4 == 1:
            raise _Unreadable()
        text += "=" * (-len(text) % 4)
        try:
            data = (base64.urlsafe_b64decode(text) if kind == "base64url"
                    else base64.b64decode(text, validate=True))
        except (binascii.Error, ValueError):
            raise _Unreadable() from None
        if len(data) > self.max_file_bytes:
            raise _Unreadable("limits_exceeded")
        return data

    def read_confined(self, value: Any, folder: str) -> bytes:
        """The file at ``value``, which must be an absolute path inside ``folder`` with no link or junction
        below the folder. Opened without following a link; a regular file of at most ``max_file_bytes``."""
        if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
            raise _Unreadable()
        if not os.path.isabs(value) or any(p in (".", "..") for p in re.split(r"[\\/]", value)):
            raise _Unreadable()
        norm = os.path.normpath(value)
        base = os.path.normpath(folder)
        if os.path.normcase(norm) == os.path.normcase(base) or not os.path.normcase(norm).startswith(
                os.path.normcase(base).rstrip("\\/") + os.sep):
            raise _Unreadable()
        expected = os.path.join(os.path.realpath(base), os.path.relpath(norm, base))
        if os.path.normcase(os.path.realpath(norm)) != os.path.normcase(expected):
            raise _Unreadable()      # a link or junction inside the folder: the tool could be sent elsewhere
        try:
            fd = _platform.open_nofollow(norm)
        except OSError:
            raise _Unreadable() from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise _Unreadable()
            if st.st_size > self.max_file_bytes:
                raise _Unreadable("limits_exceeded")
            chunks, total = [], 0
            while True:
                chunk = os.read(fd, min(1024 * 1024, self.max_file_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self.max_file_bytes:
                    raise _Unreadable("limits_exceeded")
            return b"".join(chunks)
        except OSError:
            raise _Unreadable() from None
        finally:
            os.close(fd)

    def _files(self, tool: str, arguments: Any) -> list[tuple[str, FileArg, Any, bytes | None, str | None, list]]:
        """(name, declaration, raw value, bytes or None, problem category or None, location) per file."""
        out = []
        for item in self.files.get(tool, ()):
            for name, value, where in self._occurrences(arguments, item):
                if isinstance(value, _Unreadable):
                    out.append((name, item, None, None, value.category, where))
                    continue
                try:
                    data = (self.read_confined(value, item.folder) if item.kind == "path"
                            else self._decode(value, item.kind))
                except _Unreadable as e:
                    out.append((name, item, value, None, e.category, where))
                    continue
                out.append((name, item, value, data, None, where))
        return out

    def prepare(self, tool: str, arguments: Any, proposal: Any) -> Prepared:
        """Build the parts for one call. ``arguments`` and ``proposal`` are Two-Key's plain copies."""
        judge_args = _deep_copy(arguments)
        files = self._files(tool, judge_args)
        parts: list[ScanPart] = []
        records: list[dict] = []
        forced: list[str] = []
        for name, item, value, data, problem, where in files:
            if data is None:
                descriptor = {"unreadable": True}
                forced.append(problem or "unreadable")
                records.append({"part": name, "sha256": None})
            else:
                part = ScanPart(f"file:{name}", data)
                parts.append(part)
                descriptor = {"sha256": part.sha256, "bytes": len(data)}
                records.append({"part": name, "sha256": part.sha256})
            if item.kind == "path" and isinstance(value, str):
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
        return Prepared(tuple(head + parts), judge_args, records, tuple(sorted(set(forced))))

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

    def run(self, tool: str, prepared: Prepared) -> Outcome:
        """Scan one call. Never raises: every failure is an ``unavailable`` (or a ``flagged``) outcome."""
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
        if categories & set(_INCOMPLETE):
            verdict = "flagged"           # the scanner could not finish: flagged, not clean or unavailable
        if prepared.forced:
            verdict = "flagged"           # a declared file Two-Key could not read is flagged, whatever the scanner said
            categories |= set(prepared.forced)
        if verdict != "flagged":
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
        """Each declared file's digest, read again (for the gateway, just before the tool runs)."""
        out = []
        for name, _item, _value, data, _problem, _where in self._files(tool, _deep_copy(arguments)):
            out.append({"part": name, "sha256": None if data is None else "sha256:" + digest_hex(data)})
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


__all__ = ["CATEGORIES", "FILE_KINDS", "FileArg", "Inspector", "Outcome", "ScanConfigError", "ScanPart",
           "ScanRequest", "ScanResult", "Scanner", "VERDICTS", "combine", "stance_of"]

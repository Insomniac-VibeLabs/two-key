# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The archive file of a sealed ledger segment (0.9.1, ``two-key-ledger-archive/1``).

When the ledger rolls over (``Ledger.roll``), the entries of the active segment, its ``ledger_sealed`` entry last,
and the signed head that ends at that seal are written here as JSON lines. The lines are compressed once (zlib, or
none), then encrypted with AES-256-GCM in chunks of 1 MiB:

* The file starts with one plaintext header line: the format, the segment number, the chunk size, the compression
  and a random salt. The header is the associated data of every chunk, so changing it fails every chunk.
* The key is HKDF-SHA256 over the ledger's data key, with that salt, and ``two-key-ledger-archive/1`` and the
  segment number as info. Archive keys are apart from record keys, and no new secret is kept.
* Each chunk is a 4-byte big-endian length, then the ciphertext and tag. The nonce is the chunk counter and a flag
  for the last chunk, so a dropped, reordered, repeated or truncated chunk fails.
* The compressed stream is padded with zero bytes (inside the encryption) so the file length is a multiple of
  64 KiB. One length per segment is not a useful oracle for what an agent put into an entry.

Compression comes before encryption, and once per segment, never per entry: a per-entry length would leak how well
agent-chosen text compresses against secret values beside it (CRIME/BREACH).

The reader refuses (``ledger_archive_invalid``) an archive whose header is not this one, a chunk that is too large
or does not decrypt, output past the expected plaintext length (a decompression bomb), a missing last chunk, or
anything after it. It reads the file without following a link, and refuses a file that is not a regular file or
that another account can read (``ledger_archive_insecure``). Checking the entries' chain is the ledger's job.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zlib
from collections.abc import Iterator
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import _platform

ARCHIVE_FORMAT = "two-key-ledger-archive/1"
HEAD_LINE_FORMAT = "two-key-ledger-archive-head/1"
ARCHIVE_SUFFIX = ".tkla"
CHUNK_BYTES = 1 << 20
PAD_BYTES = 64 * 1024
COMPRESSIONS = ("zlib", "none")
_INFO = ARCHIVE_FORMAT.encode("ascii")
_MAX_HEADER = 1024
_TAG = 16
_LENGTH = 4
_SALT = 16


class ArchiveError(ValueError):
    """An archive that cannot be read. The message starts with ``ledger_archive_invalid`` or
    ``ledger_archive_insecure``."""


def archive_name(segment: int) -> str:
    return f"segment-{segment:06d}{ARCHIVE_SUFFIX}"


def _invalid(why: str) -> ArchiveError:
    return ArchiveError(f"ledger_archive_invalid: {why}")


def _key(data_key: bytes, segment: int, salt: bytes) -> AESGCM:
    info = _INFO + b"\0" + segment.to_bytes(8, "big")
    return AESGCM(HKDF(SHA256(), 32, salt=salt, info=info).derive(data_key))


def _nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _header(segment: int, salt: bytes, compression: str) -> bytes:
    fields = {"chunk_bytes": CHUNK_BYTES, "compression": compression, "format": ARCHIVE_FORMAT,
              "salt": salt.hex(), "segment": segment}
    return (json.dumps(fields, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def entry_line(record: dict) -> bytes:
    """One JSON line of the archive body: an entry (``Entry.to_json()``) or the head line."""
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def head_line(stored_head: dict) -> bytes:
    return entry_line({"format": HEAD_LINE_FORMAT, "head": stored_head})


class _ChunkWriter:
    """Encrypts what it is fed in chunks of ``CHUNK_BYTES``, and pads the end so the file length is a multiple of
    ``PAD_BYTES``."""

    def __init__(self, fh: BinaryIO, aead: AESGCM, header: bytes):
        self.fh, self.aead, self.header = fh, aead, header
        self.buffer = bytearray()
        self.counter = 0
        self.written = 0
        self.digest = hashlib.sha256()
        self._write(header)

    def _write(self, data: bytes) -> None:
        self.fh.write(data)
        self.digest.update(data)
        self.written += len(data)

    def _emit(self, plain: bytes, last: bool) -> None:
        sealed = self.aead.encrypt(_nonce(self.counter, last), plain, self.header)
        self._write(len(sealed).to_bytes(_LENGTH, "big") + sealed)
        self.counter += 1

    def feed(self, data: bytes) -> None:
        self.buffer += data
        while len(self.buffer) > CHUNK_BYTES:
            self._emit(bytes(self.buffer[:CHUNK_BYTES]), last=False)
            del self.buffer[:CHUNK_BYTES]

    def finish(self) -> None:
        rest = len(self.buffer)
        pad = 0
        for chunks in range(max(1, -(-rest // CHUNK_BYTES)), max(1, -(-rest // CHUNK_BYTES)) + 3):
            pad = -(self.written + rest + chunks * (_LENGTH + _TAG)) % PAD_BYTES
            if max(1, -(-(rest + pad) // CHUNK_BYTES)) == chunks:
                break
        self.buffer += bytes(pad)
        while len(self.buffer) > CHUNK_BYTES:
            self._emit(bytes(self.buffer[:CHUNK_BYTES]), last=False)
            del self.buffer[:CHUNK_BYTES]
        self._emit(bytes(self.buffer), last=True)
        self.buffer.clear()


def write_archive(fh: BinaryIO, data_key: bytes, segment: int, lines, compression: str = "zlib") -> dict:
    """Write an archive of ``lines`` (bytes, each ending in a newline) to ``fh``. Returns its length, SHA-256 and
    plaintext length. The caller creates the file owner-only, fsyncs it and moves it into place."""
    if compression not in COMPRESSIONS:
        raise ValueError(f"compression must be one of {', '.join(COMPRESSIONS)}")
    if type(segment) is not int or segment < 1:
        raise ValueError("segment must be a whole number from 1")
    salt = os.urandom(_SALT)
    writer = _ChunkWriter(fh, _key(data_key, segment, salt), _header(segment, salt, compression))
    packer = zlib.compressobj(9) if compression == "zlib" else None
    plain = 0
    for line in lines:
        plain += len(line)
        writer.feed(packer.compress(line) if packer is not None else line)
    if packer is not None:
        writer.feed(packer.flush())
    writer.finish()
    return {"bytes": writer.written, "sha256": "sha256:" + writer.digest.hexdigest(), "plain_bytes": plain,
            "compression": compression}


def open_archive_file(path) -> int:
    """An archive opened for reading: not through a link, a regular file, and readable by its owner only."""
    try:
        fd = _platform.open_nofollow(path, os.O_RDONLY | _platform.O_BINARY)
    except FileNotFoundError:
        raise _invalid(f"{path} is missing") from None
    except OSError as e:
        raise _invalid(f"{path}: {e.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _invalid(f"{path} is not a regular file")
        problem = _platform.access_problem(fd, st)
        if problem:
            raise ArchiveError(f"ledger_archive_insecure: {_platform.insecure(path, problem)}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def file_digest(path) -> tuple[int, str]:
    """An archive's length and ``sha256:`` digest, read as ``read_archive`` reads it."""
    fd = open_archive_file(path)
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(fd, "rb") as fh:
        while True:
            block = fh.read(CHUNK_BYTES)
            if not block:
                break
            digest.update(block)
            total += len(block)
    return total, "sha256:" + digest.hexdigest()


def _read_exact(fh: BinaryIO, size: int) -> bytes:
    data = fh.read(size)
    return data if data is not None else b""


def _read_header(fh: BinaryIO, segment: int) -> tuple[bytes, dict]:
    header = fh.readline(_MAX_HEADER + 1)
    if not header.endswith(b"\n") or len(header) > _MAX_HEADER:
        raise _invalid("the header line is missing or too long")
    try:
        fields = json.loads(header.decode("ascii"))
    except ValueError:          # a UnicodeDecodeError is a ValueError
        raise _invalid("the header is not JSON") from None
    if not isinstance(fields, dict) or set(fields) != {"chunk_bytes", "compression", "format", "salt", "segment"}:
        raise _invalid("the header is not a two-key archive header")
    if fields["format"] != ARCHIVE_FORMAT or fields["chunk_bytes"] != CHUNK_BYTES \
            or fields["compression"] not in COMPRESSIONS:
        raise _invalid("the header names another format, chunk size or compression")
    if fields["segment"] != segment or type(fields["segment"]) is not int:
        raise _invalid(f"the header is for segment {fields['segment']!r}, not {segment}")
    salt = fields["salt"]
    if not isinstance(salt, str) or len(salt) != 2 * _SALT or salt.strip("0123456789abcdef"):
        raise _invalid("the header salt is not 16 bytes of hex")
    if header != _header(segment, bytes.fromhex(salt), fields["compression"]):
        raise _invalid("the header is not in its canonical form")
    return header, fields


def _read_chunk(fh: BinaryIO, counter: int) -> bytes:
    """One chunk's length prefix and sealed bytes."""
    prefix = _read_exact(fh, _LENGTH)
    if len(prefix) != _LENGTH:
        raise _invalid("the last chunk is missing (the file was cut short)")
    size = int.from_bytes(prefix, "big")
    if not _TAG <= size <= CHUNK_BYTES + _TAG:
        raise _invalid(f"chunk {counter} has an impossible length ({size} bytes)")
    sealed = _read_exact(fh, size)
    if len(sealed) != size:
        raise _invalid("the last chunk is missing (the file was cut short)")
    return sealed


def _open_chunk(aead: AESGCM, counter: int, sealed: bytes, header: bytes) -> tuple[bytes, bool]:
    """A chunk's plaintext, and whether it is the last one: its nonce says so."""
    for last in (False, True):
        try:
            return aead.decrypt(_nonce(counter, last), sealed, header), last
        except InvalidTag:
            continue
    raise _invalid(f"chunk {counter} does not decrypt (wrong key, or a changed, moved or missing chunk)")


def _chunks(fh: BinaryIO, aead: AESGCM, header: bytes) -> Iterator[bytes]:
    """Each chunk's plaintext, checked: no chunk too large, a last chunk, and nothing after it."""
    counter, last = 0, False
    while not last:
        plain, last = _open_chunk(aead, counter, _read_chunk(fh, counter), header)
        if not last and len(plain) != CHUNK_BYTES:
            raise _invalid(f"chunk {counter} is not full and not the last one")
        yield plain
        counter += 1
    if fh.read(1):
        raise _invalid("there is data after the last chunk")


class _Lines:
    """Splits the plaintext into JSON lines, refusing more than ``limit`` bytes before the zero padding."""

    def __init__(self, limit: int):
        self.limit = limit
        self.taken = 0
        self.partial = bytearray()

    def feed(self, data: bytes) -> Iterator[Any]:
        self.taken += len(data)
        if self.taken > self.limit:
            raise _invalid("the archive holds more than its recorded length (refused before reading on)")
        self.partial += data
        while True:
            end = self.partial.find(b"\n")
            if end < 0:
                return
            line = bytes(self.partial[:end])
            del self.partial[:end + 1]
            try:
                yield json.loads(line.decode("ascii"))
            except ValueError:  # a UnicodeDecodeError is a ValueError
                raise _invalid("a line of the archive is not JSON") from None

    def finish(self) -> None:
        if self.partial:
            raise _invalid("the archive ends inside a line")


def _zeros(data: bytes) -> None:
    if data.strip(b"\0"):
        raise _invalid("there is data after the end of the archive body")


def _unpack(chunks: Iterator[bytes], compression: str, limit: int) -> Iterator[Any]:
    lines = _Lines(limit)
    if compression == "none":
        yield from _unpack_stored(chunks, lines)
    else:
        yield from _unpack_zlib(chunks, lines, limit)
    lines.finish()


def _unpack_stored(chunks: Iterator[bytes], lines: _Lines) -> Iterator[Any]:
    """An uncompressed body: whole lines as they arrive, then only zero padding."""
    tail = bytearray()
    for plain in chunks:
        tail += plain
        cut = tail.rfind(b"\n") + 1
        if cut:
            yield from lines.feed(bytes(tail[:cut]))
            del tail[:cut]
        if len(tail) > PAD_BYTES + CHUNK_BYTES:
            raise _invalid("a line of the archive is too long")
    _zeros(bytes(tail))


def _unpack_zlib(chunks: Iterator[bytes], lines: _Lines, limit: int) -> Iterator[Any]:
    """A zlib body, never inflated past ``limit``, then only zero padding."""
    unpacker = zlib.decompressobj()
    for plain in chunks:
        if unpacker.eof:
            _zeros(plain)
        else:
            yield from _inflate(unpacker, plain, lines, limit)
    if not unpacker.eof:
        raise _invalid("the compressed body ends early")


def _inflate(unpacker, data: bytes, lines: _Lines, limit: int) -> Iterator[Any]:
    """One chunk through the decompressor, at most one byte past the limit at a time."""
    while data and not unpacker.eof:
        try:
            out = unpacker.decompress(data, limit - lines.taken + 1)
        except zlib.error:
            raise _invalid("the compressed body is damaged") from None
        yield from lines.feed(out)
        data = unpacker.unconsumed_tail
    if unpacker.eof:
        _zeros(unpacker.unused_data)


def _file_size(path) -> int:
    fd = open_archive_file(path)
    try:
        return os.fstat(fd).st_size
    finally:
        os.close(fd)


def read_archive(path, data_key: bytes, segment: int, *, max_plain: int,
                 expect_bytes: int | None = None, expect_sha256: str | None = None) -> Iterator[Any]:
    """Each JSON line of the archive at ``path``, in order: the entries, then the head line. With ``expect_sha256``
    the whole file is hashed first. Raises ``ArchiveError``."""
    if expect_bytes is not None:
        total = _file_size(path)
        if total != expect_bytes:
            raise _invalid(f"{path} is {total} bytes, and the catalogue says {expect_bytes}")
    if expect_sha256 is not None and file_digest(path)[1] != expect_sha256:
        raise _invalid(f"{path} does not match the SHA-256 in the catalogue")
    fd = open_archive_file(path)
    with os.fdopen(fd, "rb") as fh:
        header, fields = _read_header(fh, segment)
        aead = _key(data_key, segment, bytes.fromhex(fields["salt"]))
        yield from _unpack(_chunks(fh, aead, header), fields["compression"], max_plain)

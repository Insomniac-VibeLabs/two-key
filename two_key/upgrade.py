# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""The key upgrade (0.9.0): a 0.8.0 deployment's Ed25519 keys become hybrid Ed25519 + ML-DSA-65 keys.

It runs once, by itself, at the first start of 0.9.0 (``two-key mcp-proxy``, and the commands that run Two-Key
on a ledger), or by hand with ``two-key keys upgrade``. Each key keeps its Ed25519 key and gains a new ML-DSA-65
key (``keys.add_ml_dsa``), so everything signed before the upgrade still checks against the old halves. There is
no way back: once the ledger records ``keys_upgraded``, a 0.8.0 key is refused.

The steps, under the ledger's lock. A stop before step 5 is taken up by the next start; a stop inside step 5,
after ``keys_upgraded`` is written and before the head that covers it, leaves a ledger that needs
``two-key recover`` first, as any interrupted write does (docs/UPGRADING.md):

1. Open the ledger with the key on disk; it must open and verify as it is. Under the lock, remove the temporary
   key files a stopped upgrade left (``.principal.pem.<pid>.<hex>.tmp``).
2. Replace the principal key file with the hybrid key, encrypted again with its passphrase if it was encrypted.
   The principal goes first: a ledger opened with a hybrid principal accepts the old witness key until step 5.
3. Replace ``witness.pem``, ``capability.pem`` and ``stamp.pem`` (each where it exists) and their public files,
   and ``principal.pub.pem`` beside the principal key.
4. Sign the constitution again with the hybrid key; the signed body, so its digest, is unchanged.
5. Record ``keys_upgraded`` (``Ledger.upgrade_keys``), signed by the old and new principal and witness keys,
   with the new capability and stamp key fingerprints; the head and the anchor are hybrid from then on.
6. Leave ``backup-due`` beside the ledger key. Every start says to back up until ``two-key backup-export``
   removes it: a backup from before the upgrade restores the old keys.

The automatic upgrade refuses (``keys_upgrade_needed``) where it cannot do all of it alone: when the witness
public key is also pinned outside the ledger (``witness_public_key``), which the operator has to replace by hand.
``two-key keys upgrade`` does it and says what to replace. Where ML-DSA-65 is missing, both refuse
(``ml_dsa_unavailable``); Two-Key never falls back to Ed25519 alone.

After the upgrade, a start never signs a constitution again by itself: a file signed by the 0.8.0 key is refused,
or an Ed25519 forger could pass one off. ``two-key keys upgrade --constitution FILE`` signs a file the operator
names again, as ``sign-constitution`` would.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from . import _platform
from .canonical import canonical_bytes
from .keys import (HYBRID_ALG, Passphrase, add_ml_dsa, classical_half, fingerprint, is_hybrid, key_fingerprint,
                   key_file_is_encrypted, load_private_key_file, load_public_key, passphrase_bytes, private_key_bytes,
                   public_raw, remember, require_ml_dsa, save_public_key, sign, verify)
from .ledger import Ledger, LedgerError

BACKUP_DUE = "backup-due"
PUBLIC_SUFFIX = ".pub.pem"
BACKUP_NOTE = ("two-key: back up now: the key upgrade changed every key file, and a backup made before it restores "
               "the old keys, which this ledger refuses (two-key backup-export; docs/UPGRADING.md)")


class UpgradeError(ValueError):
    """The key upgrade refused, or stopped. What it had written is safe: the next start goes on from there."""


@dataclass
class Upgrade:
    """What :func:`open_upgraded` found and did."""
    principal: Any                               # the hybrid principal key once upgraded
    ledger: Ledger
    upgraded: bool = False                       # this call recorded keys_upgraded
    replaced: list[str] = field(default_factory=list)
    entry: dict | None = None


def backup_due_path(ledger: Ledger) -> Path:
    """The marker the upgrade leaves until a backup is made, beside the ledger key (Two-Key's own folder)."""
    return ledger.ledger_key_path.parent / BACKUP_DUE


def backup_made(ledger_key_path: Path | str) -> None:
    """``two-key backup-export`` succeeded: the upgrade's backup reminder stops."""
    marker = Path(ledger_key_path).parent / BACKUP_DUE
    try:
        if marker.is_file() and not marker.is_symlink():
            marker.unlink()
    except OSError:
        pass


def _temp_name(path: Path) -> Path:
    return path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")


def _sweep_temps(paths) -> None:
    """Remove the temporary files a stopped upgrade left beside ``paths`` (run 12, B7b: half a private key, owner
    only, that nothing else would ever remove). Called under the ledger's lock, where no other upgrade writes."""
    for path in paths:
        leftover = re.compile(rf"\.{re.escape(path.name)}\.\d+\.[0-9a-f]{{8}}\.tmp")
        try:
            names = os.listdir(path.parent)
        except OSError:
            continue
        for name in names:
            stale = path.parent / name
            if leftover.fullmatch(name) and stale.is_file() and not stale.is_symlink():
                stale.unlink()


def _replace_key(path: Path, key, passphrase: bytes | None = None) -> None:
    """Write ``key`` over ``path`` as a new owner-only file renamed into place: a reader sees the old key or the
    new one, never half of either."""
    tmp = _temp_name(path)
    data = private_key_bytes(key, passphrase)
    try:
        fd = _platform.create_new(tmp)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        _platform.replace(tmp, path)
        _platform.fsync_dir(path.parent)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def _replace_public(path: Path, public) -> None:
    """Write ``public`` over ``path``, keeping the mode the operator gave the old file (run 12: 0600 became 0644)."""
    tmp = _temp_name(path)
    try:
        save_public_key(tmp, public)
        if path.exists():
            shutil.copymode(path, tmp)
        _platform.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def _upgrade_file(path: Path, replaced: list[str]):
    """The hybrid key in the unencrypted key file at ``path``, made and written there if it was Ed25519; None
    when there is no file."""
    if not path.exists():
        return None
    key = load_private_key_file(path)
    if not is_hybrid(key):
        key = add_ml_dsa(key)
        _replace_key(path, key)
        replaced.append(str(path))
    public = path.with_name(path.name.removesuffix(".pem") + PUBLIC_SUFFIX)
    if public.exists() and public_raw(load_public_key(public)) != public_raw(key.public_key()):
        _replace_public(public, key.public_key())
        replaced.append(str(public))
    return key


def _resign_constitution(path: Path | None, principal, replaced: list[str]) -> None:
    """Sign the constitution at ``path`` again with the hybrid principal when its signature is the 0.8.0 key's.
    A file signed by anything else is left for ``TwoKey.load`` to refuse, as before."""
    from .constitution import load_envelope, save_envelope
    if path is None or not Path(path).exists():
        return
    envelope = load_envelope(path)
    signed = envelope.get("signed") if isinstance(envelope, dict) else None
    if not isinstance(signed, dict):
        return
    message = canonical_bytes(signed)
    signature = envelope.get("signature") or ""
    if verify(principal.public_key(), message, signature):
        return
    if not verify(classical_half(principal.public_key()), message, signature):
        return
    save_envelope(path, {**envelope, "signature": sign(principal, message),
                         "fingerprint": fingerprint(principal.public_key())},
                  owner_only=not Path(path).stat().st_mode & 0o077)
    replaced.append(str(path))


def _fingerprint_of(key) -> str | None:
    return None if key is None else key_fingerprint(key.public_key())


def open_upgraded(principal_path: Path | str, passphrase: Passphrase, ledger_path: Path | str, *,
                  constitution: Path | str | None = None, witness_public_key: Path | str | None = None,
                  anchor_path: Path | str | None = None, automatic: bool = True, principal=None,
                  out: TextIO | None = None) -> Upgrade:
    """Load the principal key (or take ``principal``, already loaded from ``principal_path``) and open the
    ledger, doing the key upgrade first when the deployment needs it.

    ``automatic`` is the start of a proxy or a command: it refuses (``keys_upgrade_needed``) where the upgrade
    needs the operator. What it did, and the backup reminder, go to ``out`` (stderr by default).
    """
    out = out or sys.stderr
    principal_path = Path(principal_path)
    passphrase = remember(passphrase)
    if principal is None:
        principal = load_private_key_file(principal_path, passphrase)
    pin = load_public_key(witness_public_key) if witness_public_key else None
    ledger = Ledger(ledger_path, principal, witness_public_key=pin, anchor_path=anchor_path)
    result = Upgrade(principal, ledger)
    if is_hybrid(principal) and not ledger.upgrade_pending:
        _already_upgraded(result, None if automatic else constitution, out)
        return result
    require_ml_dsa()
    if automatic and pin is not None:
        raise UpgradeError("keys_upgrade_needed: 0.9.0 upgrades the keys to hybrid Ed25519 + ML-DSA-65, and the "
                           "witness public key is also pinned outside the ledger (witness_public_key), which has "
                           "to be replaced by hand; run two-key keys upgrade (docs/UPGRADING.md)")
    print(f"two-key: upgrading the keys to hybrid {HYBRID_ALG}, once; let it finish", file=out)
    _upgrade_locked(result, principal_path, passphrase, Path(constitution) if constitution else None)
    result.upgraded = True
    print(f"two-key: keys upgraded to hybrid {HYBRID_ALG} (keys_upgraded at seq {result.entry['seq']}): "
          f"principal {result.entry['principal_key_fingerprint']}, witness {result.entry['witness_key_fingerprint']}; "
          f"files replaced: {', '.join(result.replaced) or 'none'}", file=out)
    if pin is not None:
        print(f"two-key: replace the out-of-ledger witness pin {witness_public_key} with "
              f"{ledger.witness_path.with_suffix(PUBLIC_SUFFIX)}; until then the ledger refuses to open with it",
              file=out)
    _remind(ledger, out)
    return result


def _upgrade_locked(result: Upgrade, principal_path: Path, passphrase: Passphrase, constitution: Path | None) -> None:
    """``_upgrade`` under the ledger's lock, with the two stops an operator can act on named (live run 12)."""
    try:
        with result.ledger.exclusive():
            _upgrade(result, principal_path, passphrase, constitution)
    except PermissionError as e:
        raise UpgradeError(f"keys_upgrade_stopped: this account cannot write {e.filename}; the key upgrade "
                           "replaces the key files, so their folders must be writable by Two-Key's account. What "
                           "was written is safe: make them writable and start again (docs/UPGRADING.md)") from None
    except LedgerError:
        if not is_hybrid(result.principal) and _upgraded_elsewhere(principal_path, passphrase):
            raise UpgradeError("keys_upgraded_elsewhere: another process upgraded the keys while this one waited "
                               "for the ledger; start again, which opens the upgraded keys") from None
        raise


def _upgraded_elsewhere(principal_path: Path, passphrase: Passphrase) -> bool:
    """The principal key file on disk is hybrid now: a second first start lost the race (run 12, X3)."""
    try:
        return is_hybrid(load_private_key_file(principal_path, passphrase))
    except (OSError, ValueError):
        return False


def _already_upgraded(result: Upgrade, constitution: Path | str | None, out: TextIO) -> None:
    """Nothing to upgrade. ``two-key keys upgrade --constitution FILE`` (never a start) signs that file again."""
    if constitution:
        _resign_constitution(Path(constitution), result.principal, result.replaced)
    _remind(result.ledger, out)


def _upgrade(result: Upgrade, principal_path: Path, passphrase: Passphrase, constitution: Path | None) -> None:
    """Steps 2 to 6, under the ledger's lock."""
    ledger = result.ledger
    capability_path = ledger.capability_key_path()
    keys = [principal_path, ledger.witness_path, capability_path, capability_path.with_name("stamp.pem")]
    _sweep_temps(keys + [path.with_suffix(PUBLIC_SUFFIX) for path in keys])
    result.principal = _upgrade_principal(principal_path, result.principal, passphrase, result.replaced)
    _upgrade_file(ledger.witness_path, result.replaced)
    capability = _upgrade_file(capability_path, result.replaced)
    stamp = _upgrade_file(capability_path.with_name("stamp.pem"), result.replaced)
    _resign_constitution(constitution, result.principal, result.replaced)
    try:
        result.entry = ledger.upgrade_keys(None if ledger.upgrade_pending else result.principal,
                                           capability_key_fingerprint=_fingerprint_of(capability),
                                           stamp_key_fingerprint=_fingerprint_of(stamp))
    except LedgerError as e:
        raise UpgradeError(f"keys_upgrade_stopped: {e}") from None
    marker = backup_due_path(ledger)
    if not os.path.lexists(marker):
        os.close(_platform.create_new(marker))


def _upgrade_principal(path: Path, principal, passphrase: Passphrase, replaced: list[str]):
    """The hybrid principal, written over ``path`` (encrypted again under the same passphrase) when it was the
    0.8.0 key, and ``principal.pub.pem`` beside it."""
    if not is_hybrid(principal):
        secret = passphrase_bytes(passphrase, str(path)) if key_file_is_encrypted(path) else None
        principal = add_ml_dsa(principal)
        _replace_key(path, principal, secret)
        replaced.append(str(path))
    public = path.with_name("principal.pub.pem")
    if public.exists() and public_raw(load_public_key(public)) != public_raw(principal.public_key()):
        _replace_public(public, principal.public_key())
        replaced.append(str(public))
    return principal


def _remind(ledger: Ledger, out: TextIO) -> None:
    if os.path.lexists(backup_due_path(ledger)):
        print(BACKUP_NOTE, file=out)


__all__ = ["BACKUP_DUE", "Upgrade", "UpgradeError", "backup_due_path", "backup_made", "open_upgraded"]

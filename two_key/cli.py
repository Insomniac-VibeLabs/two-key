# Copyright 2026 Insomniac-VibeLabs
# Author: Stephan Busch
# SPDX-License-Identifier: Apache-2.0
"""Command line for Two-Key.

  two-key init-key DIR [--passphrase | --passphrase-file FILE]
  two-key sign-constitution --key KEY --prose FILE --rules FILE --out FILE [--envelope-format auto|v2|v3]
  two-key authorize --key KEY --ledger DIR --constitution FILE --judges FILE --tool NAME
                    [--facts FILE] [--agent-session-env NAME] [--ttl-seconds N] [--emit-token PATH]
                    [--witness-public-key PEM]
  two-key rotate-witness --key KEY --ledger DIR [--witness-public-key PEM] [--reason TEXT]
  two-key keys upgrade (--config FILE | --key KEY --ledger DIR [--constitution FILE]
                    [--witness-public-key PEM] [--head-anchor PATH])
  two-key recover --key KEY --ledger DIR [--witness-public-key PEM] [--head-anchor PATH]
  two-key backup-export --key KEY --ledger DIR --out DIR \
                    --principal-passphrase-env NAME --ledger-passphrase-env NAME \
                    --witness-passphrase-env NAME [--witness-public-key PEM] [--head-anchor PATH]
  two-key backup-verify --bundles DIR \
                    --principal-passphrase-env NAME --ledger-passphrase-env NAME \
                    --witness-passphrase-env NAME [--witness-public-key PEM]
  two-key backup-restore --key KEY --ledger DIR --bundles DIR \
                    --principal-passphrase-env NAME --ledger-passphrase-env NAME \
                    --witness-passphrase-env NAME [--witness-public-key PEM] [--head-anchor PATH] \
                    [--replace-ledger]
  two-key audit --key KEY --ledger DIR [--witness-public-key PEM] [--check-history CONSTITUTION]
  two-key ledger-view --key KEY --ledger DIR [--witness-public-key PEM] [--search TEXT]
                    [--search-names] [--where FIELD OP [VALUE]]... [--any] [--sort FIELD[:desc]]...
                    [--print | --fields]
  two-key constitution-editor [--prose FILE --rules FILE | --signed FILE [--public-key PEM]] [--key KEY]
                    [--dir DIR] [--check]
  two-key siem-export --key KEY --ledger DIR [--out FILE] [--schema native|ecs|ocsf]
                    [--format json|cef] [--from-seq N] [--to-seq N]
  two-key siem-verify --key KEY --ledger DIR --events FILE [--require-complete]
  two-key mcp-proxy --config FILE
  two-key config show|check --config FILE
  two-key config get --config FILE SETTING
  two-key config set --config FILE SETTING (VALUE | --value-file FILE | --prompt | --unset)
                    [--confirm-weaker] [--key KEY --rules FILE]
  two-key config undo --config FILE [--confirm-weaker] [--key KEY]
  two-key config key-passphrase --config FILE (--new-from FILE | --remove) [--confirm-weaker]
  two-key setup --dir DIR [--answers FILE [--confirm-weaker]] [--window]

Every command that takes --key also takes --key-passphrase-file FILE for an encrypted key; without it, it
asks on the terminal (docs/SETUP.md).
  two-key mcp-draft-specs (--out DIR | --constitution FILE) [--tool NAME]... [--env NAME[=VALUE]]... -- COMMAND...
  two-key demo [--siem FILE]

``authorize`` never prints the bearer token. It prints the decision with the token's
jti and digest (the ledger's ``capability_issued.token_hash``). ``--emit-token PATH``
writes the token itself to a new file with mode 0600. The agent session secret is
read from the environment variable named by ``--agent-session-env``; it is never
taken on argv, where other local users and shell history can see it.

``--witness-public-key PEM`` is the witness pin outside the ledger: a copy of the
witness public key kept where whoever writes the ledger directory cannot change it.
``rotate-witness`` changes the witness key as a ledgered ``witness_rotated`` entry;
update that copy afterwards. ``keys upgrade`` makes a 0.8.0 deployment's Ed25519 keys hybrid
Ed25519 + ML-DSA-65 and records ``keys_upgraded``; the first start of 0.9.0 does it by itself, except where
the witness key is also pinned outside the ledger (docs/UPGRADING.md). ``recover`` drops only an uncheckpointed tail
(a crash between append and checkpoint) and records it. It does not roll a
signed head backwards, and it does not run on open. ``audit`` verifies the
ledger and the decision digests and prints both witness pins as JSON. The
head anchor (``<ledger>.ledger-key/head.anchor``, or ``--head-anchor``) refuses
a rollback or a wipe of the ledger directory. Creating a ledger at a new path
warns on stderr. Opening a ledger made before 0.2.3 pins its witness key
(trust on first use), whichever command opens it.

``ledger-view`` opens the ledger the way ``audit`` does and shows its entries in a window (tkinter) to
search, filter, and sort for an audit; ``--print`` writes the matching entries to stdout as JSON Lines
instead, and ``--fields`` lists every field name a filter can use. It never appends to the ledger.

``siem-export`` verifies the ledger, decrypts it locally, and writes one event per
line for a SIEM: digests, sizes, and reason codes, never argument values, the proposal
text, the derived amount or counterparty, or a custom field value (the allowlist is
``two_key/siem.py``). ``siem-verify`` checks events against the ledger and reports
anything missing, repeated, or changed. A live copy, over syslog or an HTTPS webhook,
is the ``siem:`` block of ``proxy.yaml`` (or ``TwoKey(siem=...)``); see docs/SIEM.md.

``backup-export`` writes three passphrase-protected bundles (principal, ledger, and witness)
so that one file never holds every key a signed head needs. The passphrases come from
environment variables, never from argv. ``backup-verify`` decrypts them into a temporary
ledger and checks fingerprints. It does not touch the real ledger. ``backup-restore`` puts
the keys back. It writes the ledger files and ``head.anchor`` from the same bundle together,
or it leaves an existing different ledger in place unless ``--replace-ledger`` is set. It
never deletes the anchor.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from . import _platform
from .constitution import (ENVELOPE_FORMATS, domain_allow_notes, encrypted_pass_notes, load_serial,
                           load_unsigned_with_fields, save_envelope, sign_constitution)
from .fields import case_warnings, not_applicable_notes
from .keys import (check_new_passphrase, generate_private_key, load_private_key_file, load_public_key, passphrase_source,
                   prompt_passphrase, read_passphrase_file, save_private_key, save_public_key)
from .policy_vm import ConstitutionError
from .siem import FORMATS, SCHEMAS


def _init_key(args) -> int:
    key = generate_private_key()
    dest = Path(args.dir)
    try:
        passphrase = None
        if args.passphrase_file:
            passphrase = check_new_passphrase(read_passphrase_file(args.passphrase_file))
        elif args.passphrase:
            passphrase = prompt_passphrase(str(dest / "principal.pem"), new=True)
    except ValueError as e:
        print(f"two-key: init-key: refused: {e}", file=sys.stderr)
        return 1
    try:
        save_private_key(dest / "principal.pem", key, passphrase=passphrase)
    except FileExistsError:
        print(f"refusing to overwrite {dest / 'principal.pem'}", file=sys.stderr)
        return 1
    save_public_key(dest / "principal.pub.pem", key.public_key())
    print(f"wrote {dest / 'principal.pem'}")
    return 0


def _key_passphrase(args):
    """The passphrase for an encrypted ``--key``: ``--key-passphrase-file``, else a prompt on the terminal."""
    return passphrase_source(getattr(args, "key_passphrase_file", None))


def _principal_key(args):
    """The principal private key named by ``--key``. A refusal is one line, not a traceback."""
    try:
        return load_private_key_file(args.key, _key_passphrase(args))
    except ValueError as e:
        raise SystemExit(f"--key: {e}") from None


def _sign(args) -> int:
    key = _principal_key(args)
    if not args.force and Path(args.out).exists():
        # Signing is deliberate, and the file it writes is what every later check verifies against
        # (live run 8x, finding 3). Replacing one is deliberate too.
        print(f"two-key: sign-constitution: refused: {args.out} exists; move it aside, or pass --force to "
              "replace it", file=sys.stderr)
        return 1
    try:
        prose, rules, specs, fields = load_unsigned_with_fields(args.prose, args.rules)
        envelope = sign_constitution(prose, rules, key, specs, fields=fields, envelope_format=args.envelope_format,
                                     serial=load_serial(args.rules))
    except ConstitutionError as e:      # the principal's own file: say what is wrong, no traceback
        print(f"two-key: sign-constitution: refused: {e}", file=sys.stderr)
        return 1
    save_envelope(args.out, envelope)
    signed = envelope["signed"]
    registry = signed.get("fields") or {}
    for warn, line in not_applicable_notes(signed["hard_rules"], signed["tool_specs"], registry):
        print(f"two-key: {'WARNING' if warn else 'note'}: {line}", file=sys.stderr)
    for line in case_warnings(signed["hard_rules"], signed["tool_specs"], registry):
        print(f"two-key: WARNING: {line}", file=sys.stderr)
    for warn, line in domain_allow_notes(signed["tool_specs"]):
        print(f"two-key: {'WARNING' if warn else 'note'}: {line}", file=sys.stderr)
    for line in encrypted_pass_notes(signed["tool_specs"]):
        print(f"two-key: WARNING: {line}", file=sys.stderr)
    print(f"wrote {args.out}")
    return 0


def _demo_siem(path):
    """``demo --siem FILE``: the ``siem:`` block of a config file, so a collector can be tried end to end
    (examples/siem/elastic/). The demo's own ledger is temporary; the copy it sends is real."""
    if path is None:
        return None
    from .siem_sinks import siem_from_config
    from .strict import StrictParseError, load_file_strict
    try:
        data = load_file_strict(path)
    except (OSError, StrictParseError) as e:
        raise SystemExit(f"--siem: {path}: {e}") from None
    except ImportError:
        raise SystemExit(f'--siem: {path}: reading YAML needs PyYAML (pip install "two-key[yaml]")') from None
    if not isinstance(data, dict):
        raise SystemExit(f"--siem: {path}: expected a mapping with a siem: block")
    block = data["siem"] if "siem" in data else data
    return siem_from_config(block, Path(path).resolve().parent)


def _demo(args) -> int:
    import tempfile
    from .constitution import sign_constitution
    from .core import TwoKey
    from .ledger import Ledger
    from .quorum import QuorumPolicy
    from .testing import TEST_AGENT, FixedJudge

    siem = _demo_siem(getattr(args, "siem", None))

    key = generate_private_key()
    prose = "Never wire money. Never spend more than 200 dollars. Drafts are allowed."
    rules = [
        {"id": "tools", "allow_only_tools": ["search", "email_draft"]},
        {"id": "no-wires", "deny_if": {"tool": "wire_transfer"}},
        {"id": "cap", "deny_if": {"amount_usd_gt": 200}},
    ]
    specs = {
        "search": {"irreversible": False, "data_class_floor": "public"},
        "email_draft": {"irreversible": False, "data_class_floor": "public",
                        "counterparties": [{"json_path": "to", "allow": ["ada@example"]}]},
    }
    envelope = sign_constitution(prose, rules, key, specs)
    with tempfile.TemporaryDirectory() as tmp:
        # The ledger is a subdirectory so its key, witness, capability, and lock directories
        # (siblings of the ledger) are removed with the temporary directory too.
        ledger = Ledger(Path(tmp) / "ledger", key)
        judges = [FixedJudge("a", "yes", provider="local-a", maker="local", local_weights=True),
                  FixedJudge("b", "yes", provider="cloud-b", maker="other")]
        tk = TwoKey(ledger, key.public_key(), __import__("two_key.constitution", fromlist=["verify_signed"]).verify_signed(envelope, key.public_key()),
                    judges, private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT,
                    siem=siem)
        denied = tk.authorize({"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True},
                              {}, "please wire the funds")
        allowed = tk.authorize({"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                               {"to": "ada@example"}, "draft a note")
        gateway = tk.gateway(tools={"email_draft": lambda a: {"drafted": a.get("to")}})
        redeemed = gateway.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
        replay = gateway.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
        if siem is not None:
            # One token that does not verify, so the refused-token count has something to report.
            # It is not ledgered: the gateway counts it by class and the count goes to the SIEM.
            gateway.invoke("not.a.token", "email_draft", {"to": "ada@example"})
        tk.close()
    print(json.dumps({
        "wire_denied": denied.reason,
        "draft_allowed": allowed.allowed,
        "redeemed": None if redeemed is None else redeemed.reason,
        "replay": None if replay is None else replay.reason,
    }, indent=2))
    return 0 if denied.allowed is False and allowed.allowed and redeemed and redeemed.allowed and replay and not replay.allowed else 1



def _witness_pin(args):
    """The out-of-ledger witness pin named by --witness-public-key, or None. An empty value is refused, so an
    unset variable in a script does not turn the pin off."""
    if args.witness_public_key is None:
        return None
    if not args.witness_public_key.strip():
        raise SystemExit("--witness-public-key: empty path; give the file, or leave the option out")
    try:
        return load_public_key(args.witness_public_key)
    except (OSError, ValueError) as e:
        raise SystemExit(f"--witness-public-key: {args.witness_public_key}: {e}") from None


def _anchor_arg(args):
    """``--head-anchor``, or None for ``<ledger>.ledger-key/head.anchor``. An empty value is refused."""
    path = getattr(args, "head_anchor", None)
    if path is None:
        return None
    if not str(path).strip():
        raise SystemExit("--head-anchor: empty path; give the file, or leave the option out")
    return path


def _ledger_missing(folder) -> str | None:
    """Why there is no ledger file to open in ``folder``, or None when there is one. A file or folder this
    account may not read is said as that, not as a missing ledger (live run 10)."""
    missing = f"no ledger at {folder}"
    try:
        mode = (Path(folder) / "entries.jsonl").stat().st_mode
    except PermissionError:
        return f"cannot read the ledger at {folder}: permission denied"
    except OSError:
        return missing
    return None if stat.S_ISREG(mode) else missing


def _open_ledger(args, key):
    """Open an existing ledger for rotate-witness and audit; a refusal is printed, not raised. A path with no
    ledger is refused rather than created."""
    from .ledger import Ledger, LedgerError
    missing = _ledger_missing(args.ledger)
    if missing:
        print(json.dumps({"ok": False, "error": missing}, indent=2))
        return None
    try:
        return Ledger(args.ledger, key, witness_public_key=_witness_pin(args), anchor_path=_anchor_arg(args))
    except LedgerError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return None


def _tool_key_new(args) -> int:
    """``two-key tool-key new``: a tool's receipt key (#28), owner-only, and the fingerprint to sign into its spec."""
    from .toolcheck import new_tool_key
    try:
        fingerprint = new_tool_key(args.out)
    except FileExistsError:
        raise SystemExit(f"--out: {args.out} exists; a tool key is never replaced in place") from None
    print(json.dumps({"ok": True, "tool_private_key": str(args.out), "fingerprint": fingerprint,
                      "next": "sign it into the tool's spec as tool_check: {key: <fingerprint>} (two-key config set "
                              "tool_specs.<tool>.tool_check, or the constitution editor); keep the key file where "
                              "only the tool's account can read it"}, indent=2))
    return 0


def _tool_key_trust(args) -> int:
    """``two-key tool-key trust``: Two-Key's two public keys for a checking tool, each checked against the
    fingerprint the ledger pins, written to ``--out`` with the fingerprints to put in the tool's config."""
    from .capability import capability_key_fingerprint
    from .keys import load_public_key, save_public_key
    from .toolcheck import key_fingerprint, stamp_key_path
    ledger = _open_ledger(args, _principal_key(args))
    if ledger is None:
        return 1
    loaded = ledger.last_before(ledger.size(), "constitution_loaded")
    body = loaded.body if loaded is not None else {}
    if not body.get("stamp_key_fingerprint"):
        print(json.dumps({"ok": False, "error": "no tool in the running constitution has the tool check on, so "
                                                "this ledger pins no stamp key; sign tool_check into a tool's spec "
                                                "and start Two-Key once"}, indent=2))
        return 1
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, source, pinned, fp in (
            ("capability", ledger.capability_key_path().with_name("capability.pub.pem"),
             body.get("capability_key_fingerprint"), capability_key_fingerprint),
            ("stamp", stamp_key_path(ledger).with_name("stamp.pub.pem"), body["stamp_key_fingerprint"],
             key_fingerprint)):
        public = load_public_key(source)
        if fp(public) != pinned:
            print(json.dumps({"ok": False, "error": f"{source} is not the {name} key the ledger pins"}, indent=2))
            return 1
        target = out / f"two-key-{name}.pub.pem"
        save_public_key(target, public)
        written[f"{name}_public_key"] = str(target)
        written[f"{name}_key_fingerprint"] = pinned
    print(json.dumps({"ok": True, **written,
                      "next": "put these paths and fingerprints in the tool's check config (docs/TOOL_CHECK.md)"},
                     indent=2))
    return 0


def _tool_release(args) -> int:
    """``two-key tool release``: calls to a tool held after a bad receipt go ahead again; ledgered with why."""
    reason = (args.reason or "").strip()
    if not reason:
        raise SystemExit("--reason: say why the tool can be trusted again; it is recorded in the ledger")
    ledger = _open_ledger(args, _principal_key(args))
    if ledger is None:
        return 1
    if not ledger.tool_held(args.tool):
        print(json.dumps({"ok": False, "error": f"{args.tool} is not held", "held": ledger.held_tools()}, indent=2))
        return 1
    ledger.record("tool_released", {"tool": args.tool, "reason": reason[:200]})
    print(json.dumps({"ok": True, "released": args.tool, "held": ledger.held_tools()}, indent=2))
    return 0


def _rotate_witness(args) -> int:
    from .ledger import LedgerError
    key = _principal_key(args)
    ledger = _open_ledger(args, key)
    if ledger is None:
        return 1
    try:
        result = ledger.rotate_witness(reason=args.reason)
    except LedgerError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 1
    print(json.dumps({"ok": True, **result,
                      "next": "copy the new witness public key to where your --witness-public-key copy is "
                              "kept; the old copy no longer opens this ledger"
                              + ("" if result["witness_public_key_path"] else
                                 ". witness.pub.pem could not be written; the next open of the ledger writes it")},
                     indent=2))
    return 0


def _keys_upgrade(args) -> int:
    """``two-key keys upgrade``: the key upgrade by hand (``two_key/upgrade.py``), for a deployment the first start
    will not upgrade by itself (an out-of-ledger witness pin), or to do it before that start."""
    from .ledger import LedgerError
    from .upgrade import open_upgraded
    if args.config:
        from .mcp_proxy.config import ProxyConfigError, load_proxy_config
        try:
            config = load_proxy_config(args.config)
        except ProxyConfigError as e:
            print(json.dumps({"ok": False, "error": str(e)}, indent=2))
            return 1
        where = (config.principal_key, passphrase_source(config.principal_passphrase_file), config.ledger,
                 config.constitution, config.witness_public_key, config.head_anchor)
    elif args.key and args.ledger:
        where = (args.key, _key_passphrase(args), args.ledger, args.constitution, _pin_path(args), _anchor_arg(args))
    else:
        print(json.dumps({"ok": False, "error": "give --config FILE, or --key KEY and --ledger DIR"}, indent=2))
        return 1
    key_path, passphrase, ledger, constitution, pin, anchor = where
    try:
        opened = open_upgraded(key_path, passphrase, ledger, constitution=constitution, witness_public_key=pin,
                               anchor_path=anchor, automatic=False)
    except (LedgerError, ValueError, OSError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 1
    result = {"ok": True, "upgraded": opened.upgraded, "keys_upgraded": opened.entry, "replaced": opened.replaced}
    if not opened.upgraded:
        result["note"] = "the keys are already hybrid; " + _signed_again(opened.replaced)
    elif pin is not None:
        result["next"] = (f"replace the out-of-ledger witness pin {pin} with "
                          f"{opened.ledger.witness_path.with_suffix('.pub.pem')}, then back up (two-key backup-export)")
    else:
        result["next"] = "back up now (two-key backup-export): a backup from before the upgrade holds the old keys"
    print(json.dumps(result, indent=2))
    return 0


def _signed_again(replaced: list) -> str:
    return f"signed again with the hybrid key: {', '.join(replaced)}" if replaced else "nothing to do"


def _pin_path(args):
    """``--witness-public-key`` as a path, checked as ``_witness_pin`` checks it, or None."""
    return None if _witness_pin(args) is None else args.witness_public_key


def _audit(args) -> int:
    from .audit import check_decision_digests
    key = _principal_key(args)
    ledger = _open_ledger(args, key)
    if ledger is None:
        return 1
    witness = ledger.witness_report()       # opening verified the chain, the head, and both pins
    problems = check_decision_digests(ledger)
    report = {"ok": not problems, "size": ledger.size(), "witness": witness, "decision_digest_problems": problems}
    if args.check_history:
        from .audit import check_history_digests
        from .constitution import load_envelope, verify_signed
        history = check_history_digests(ledger, verify_signed(load_envelope(args.check_history), key.public_key()))
        report["history_digest_problems"] = history
        # A decision under another constitution is listed as not checked; it does not fail the audit.
        report["ok"] = report["ok"] and all(": not checked:" in line for line in history)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


def _reopen_ledger(args, key):
    """The window's Reload: the ledger opened and checked again as ``_open_ledger`` does, or ``ViewError`` with
    the reason, so the window can show it. An unreadable file is a reason too, not a traceback."""
    from .ledger import Ledger, LedgerError
    from .ledger_view import ViewError
    missing = _ledger_missing(args.ledger)
    if missing:
        raise ViewError(missing)
    try:
        pin = None if args.witness_public_key is None else load_public_key(args.witness_public_key)
        return Ledger(args.ledger, key, witness_public_key=pin, anchor_path=_anchor_arg(args))
    except (LedgerError, OSError, ValueError) as e:
        raise ViewError(str(e)) from None


def _ledger_view(args) -> int:
    from .ledger_view import ViewError, field_names, integrity, print_rows, query_from_args, rows_from_entries, select
    try:
        query = query_from_args(args)
    except ViewError as e:
        raise SystemExit(f"ledger-view: {e}") from None
    if args.max_rows < 1:
        raise SystemExit("ledger-view: --max-rows must be at least 1")
    key = _principal_key(args)
    ledger = _open_ledger(args, key)        # opening verified the chain, the head, and both witness pins
    if ledger is None:
        return 1
    rows = rows_from_entries(e.to_json() for e in ledger.entries)
    if args.fields:
        print("\n".join(field_names(rows)))
        return 0
    if args.print:
        try:
            print_rows(select(rows, query), sys.stdout)
        except ViewError as e:
            raise SystemExit(f"ledger-view: {e}") from None
        return 0
    try:
        from .ledger_gui import show
    except ImportError:
        print("two-key ledger-view: the window needs tkinter, which this Python does not have (on Debian and "
              "Ubuntu: apt install python3-tk); use --print to list the entries instead", file=sys.stderr)
        return 1

    def reload():
        again = _reopen_ledger(args, key)
        return rows_from_entries(e.to_json() for e in again.entries), integrity(again)
    return show(rows, title=str(args.ledger), report=integrity(ledger), reload=reload, query=query,
                max_rows=args.max_rows)


def _editor_draft(args):
    """The draft ``constitution-editor`` starts from, its window title, and a line on where it came from."""
    from .constitution_editor import new_draft, open_signed, open_sources
    if bool(args.prose) != bool(args.rules):
        raise SystemExit("constitution-editor: give --prose and --rules together")
    if args.signed and args.prose:
        raise SystemExit("constitution-editor: give --prose and --rules, or --signed, not both")
    try:
        if args.signed:
            public = load_public_key(args.public_key) if args.public_key else None
            draft, said = open_signed(args.signed, public)
            return draft, args.signed, f"Opened {args.signed}: {said}."
        if args.prose:
            return open_sources(args.prose, args.rules), args.rules, f"Opened {args.prose} and {args.rules}."
    except (OSError, ValueError) as e:       # EditorError is a ValueError
        raise SystemExit(f"constitution-editor: {e}") from None
    return new_draft(), "new constitution", ""


def _editor_check(draft) -> int:
    from .constitution_editor import check
    report = check(draft)
    for level, line in report.notes:
        print(f"{level}: {line}")
    if not report.ok:
        print(f"does not sign: {report.error}")
        return 1
    serial = "no serial" if draft.serial is None else f"serial {draft.serial}"
    print(f"signs as {report.envelope_format}, {serial}, digest {report.digest}")
    return 0


def _constitution_editor(args) -> int:
    draft, title, opened = _editor_draft(args)
    if args.check:
        return _editor_check(draft)
    try:
        from .constitution_gui import show
    except ImportError:
        print("two-key constitution-editor: the window needs tkinter, which this Python does not have (on Debian and "
              "Ubuntu: apt install python3-tk); use --check, or two-key sign-constitution", file=sys.stderr)
        return 1
    source = args.signed or args.rules
    folder = args.dir or str(Path(source).resolve().parent if source else Path.cwd())
    return show(draft, title=title, key_path=args.key or "", folder=folder, opened=opened)


def _siem_export(args) -> int:
    from .siem import SiemConfigError
    from .siem_export import ExportError, write
    key = _principal_key(args)
    ledger = _open_ledger(args, key)        # opening verified the chain, the head, and both witness pins
    if ledger is None:
        return 1
    try:
        result = write(ledger, args.out if args.out != "-" else None, schema=args.schema, fmt=args.format,
                       from_seq=args.from_seq, to_seq=args.to_seq)
    except (ExportError, SiemConfigError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, **result}, indent=2), file=sys.stderr if args.out == "-" else sys.stdout)
    return 0


def _siem_verify(args) -> int:
    from .siem_export import ExportError, verify
    key = _principal_key(args)
    ledger = _open_ledger(args, key)
    if ledger is None:
        return 1
    try:
        result = verify(ledger, args.events, require_complete=args.require_complete)
    except ExportError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def _write_token(path: Path, token: str) -> None:
    """Write the bearer token to a new file, mode 0600 from creation. Never overwrite."""
    fd = _platform.create_new(path)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
        fh.write(token + "\n")


def _open_upgraded(args, key):
    """The principal key and the ledger, the key upgrade done first when the deployment needs it
    (``two_key/upgrade.py``), or None after printing why not."""
    from .ledger import LedgerError
    from .upgrade import open_upgraded
    pin = _pin_path(args)
    try:
        opened = open_upgraded(args.key, _key_passphrase(args), args.ledger,
                               constitution=getattr(args, "constitution", None), witness_public_key=pin,
                               anchor_path=_anchor_arg(args), principal=key)
    except (LedgerError, ValueError, OSError) as e:
        print(f"ledger refused: {e}", file=sys.stderr)
        return None
    return opened.principal, opened.ledger


def _open_two_key(args):
    """``authorize``'s TwoKey, or None after printing why it would not start (a refusal, not a traceback)."""
    from .constitution import ConstitutionSignatureError, load_envelope
    from .core import TwoKey, TwoKeyConfigError
    from .identity import load_monitored_agent_file
    from .judges.config import load_config_file
    key = _principal_key(args)
    judges, policy = load_config_file(Path(args.judges))
    # The monitored agent is declared by the operator in the judges file, never by the agent.
    agent = load_monitored_agent_file(Path(args.judges))
    opened = _open_upgraded(args, key)
    if opened is None:
        return None
    key, ledger = opened
    try:
        return TwoKey.load(ledger, key.public_key(), load_envelope(args.constitution), judges,
                           private_key=key, quorum=policy, monitored_agent=agent,
                           ttl_seconds=args.ttl_seconds)
    except (TwoKeyConfigError, ConstitutionError, ConstitutionSignatureError) as e:
        print(f"two-key: refused to start: {e}", file=sys.stderr)
        return None


def _authorize(args) -> int:
    if args.agent_session is not None:
        print("--agent-session took the secret on the command line and is no longer accepted; "
              "put it in an environment variable and pass --agent-session-env NAME", file=sys.stderr)
        return 1
    agent_session = None
    if args.agent_session_env:
        agent_session = os.environ.get(args.agent_session_env)
        if not agent_session:
            print(f"environment variable {args.agent_session_env} is not set", file=sys.stderr)
            return 1
    # Parsed first, strictly: a repeated key in --args is refused before anything is loaded.
    from .strict import StrictParseError, loads_json
    try:
        arguments = loads_json(args.args)
    except StrictParseError as e:
        raise SystemExit(f"--args: {e}") from None
    if not isinstance(arguments, dict):
        raise SystemExit("args must be a JSON object")
    facts = None
    if args.facts is not None:
        # Caller-supplied facts: the operator's values for source: caller fields, never the agent's.
        try:
            facts = loads_json(Path(args.facts).read_text(encoding="utf-8"))
        except (OSError, StrictParseError) as e:
            raise SystemExit(f"--facts: {e}") from None
        if not isinstance(facts, dict):
            raise SystemExit("--facts must hold a JSON object")
    token_path = Path(args.emit_token) if args.emit_token else None
    if token_path is not None and (token_path.exists() or token_path.is_symlink()):
        print(f"refusing to overwrite {token_path}", file=sys.stderr)
        return 1
    tk = _open_two_key(args)
    if tk is None:
        return 1
    action = {"tool": args.tool}
    # Omitted claims are not lies: derive fills amount and counterparty from the
    # bytes, irreversible from the spec, and a missing data_class from normalize_action (#53).
    if args.amount_usd is not None:
        action["amount_usd"] = args.amount_usd
    if args.data_class is not None:
        action["data_class"] = args.data_class
    if args.irreversible is not None:
        action["irreversible"] = args.irreversible
    if args.counterparty:
        action["counterparty"] = args.counterparty
    extra = {} if facts is None else {"facts": facts}
    decision = tk.authorize(action, arguments, args.proposal, agent_session=agent_session, origin="cli", **extra)
    record = decision.to_record()
    if decision.allowed and token_path is not None:
        try:
            _write_token(token_path, decision.token)
        except OSError as e:
            print(f"could not write {token_path}: {e.strerror}", file=sys.stderr)
            print(json.dumps(record, indent=2))
            return 1
        record["token_file"] = str(token_path)
    print(json.dumps(record, indent=2))
    return 0 if decision.allowed else 2


def _mcp_proxy(args) -> int:
    from .mcp_proxy.config import ProxyConfigError, load_proxy_config
    try:
        config = load_proxy_config(args.config)
    except ProxyConfigError as e:
        print(f"two-key: mcp-proxy refused to start: {e}", file=sys.stderr)
        return 1
    try:
        from .mcp_proxy import sdk
    except ImportError as e:
        print(f"two-key: {e}", file=sys.stderr)
        return 1
    return sdk.run(config)


def _config_show(args) -> int:
    from .config_cmd import run_show
    return run_show(args)


def _config_check(args) -> int:
    from .config_cmd import run_check
    return run_check(args)


def _config_get(args) -> int:
    from .config_set import run_get
    return run_get(args)


def _config_set(args) -> int:
    from .config_set import run_set
    return run_set(args)


def _config_undo(args) -> int:
    from .config_set import run_undo
    return run_undo(args)


def _config_key_passphrase(args) -> int:
    from .config_set import run_key_passphrase
    return run_key_passphrase(args)


def _setup(args) -> int:
    if getattr(args, "window", False):
        return _setup_window(args)
    from .setup_cmd import run
    return run(args)


def _setup_window(args) -> int:
    from .setup_cmd import SetupError
    try:
        from .setup_gui import load_for_window, show
    except ImportError:
        print("two-key setup: the window needs tkinter, which this Python does not have (on Debian and Ubuntu: apt "
              "install python3-tk); answer on the terminal, or give --answers FILE", file=sys.stderr)
        return 1
    try:
        answers = load_for_window(args.answers)
    except SetupError as e:
        print(f"two-key setup: refused: {e}", file=sys.stderr)
        return 1
    return show(answers, folder=args.dir)


def _draft_env(items: list[str] | None) -> dict[str, str]:
    """``--env NAME`` passes the variable from this environment; ``--env NAME=VALUE`` passes a literal."""
    from .mcp_proxy.config import ENV_NAME
    out: dict[str, str] = {}
    for item in items or []:
        name, sep, value = item.partition("=")
        if not ENV_NAME.fullmatch(name):
            raise SystemExit(f"--env {name[:80]!r}: expected NAME or NAME=VALUE")
        if not sep:
            value = os.environ.get(name, "")
            if not value:
                raise SystemExit(f"--env {name}: the environment variable is unset or empty")
        out[name] = value
    return out


def _write_new(path: Path, text: str) -> None:
    with os.fdopen(_platform.create_new(path, owner_only=False), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _draft_command(args) -> list[str]:
    """The upstream server's command (after ``--``), and exactly one of ``--out`` or ``--constitution``."""
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise SystemExit("give the upstream server's command after --, for example: -- npx -y @example/server@1.2.3")
    if (args.out is None) == (args.constitution is None):
        raise SystemExit("give --out DIR (draft specs) or --constitution FILE (the digest of its signed tools)")
    return command


def _draft_signed_check(tools, path: str, signed_check) -> int:
    """``--constitution``: the digest of the signed tools, those the server does not list, and undescribed inputs."""
    from .constitution import load_envelope
    digest, missing, undescribed = signed_check(tools, load_envelope(path))
    for line in undescribed:
        print(f"two-key: WARNING: mcp-draft-specs: {line}", file=sys.stderr)
    print(json.dumps({"schema_digest": digest, "signed_tools_not_listed": list(missing),
                      "undescribed_inputs": undescribed}, indent=2))
    return 0 if not missing else 2


def _draft_write(draft, out: Path, files: dict[str, str]) -> int:
    """``--out``: write the draft files (never over an existing file or link) and report them."""
    out.mkdir(parents=True, exist_ok=True)
    taken = [name for name in files if (out / name).exists() or (out / name).is_symlink()]
    if taken:
        print(f"refusing to overwrite {[str(out / n) for n in taken]}", file=sys.stderr)
        return 1
    for name, text in files.items():
        _write_new(out / name, text)
    for tool, lines in draft.warnings.items():
        for line in lines:
            print(f"two-key: WARNING: mcp-draft-specs: {tool}.{line}", file=sys.stderr)
    print(json.dumps({"schema_digest": draft.digest, "tools": [t.tool_id for t in draft.tools],
                      "fact_candidates": draft.fact_candidates, "warnings": draft.warnings,
                      "not_drafted": draft.skipped, "wrote": [str(out / n) for n in files]}, indent=2))
    return 0


def _mcp_draft_specs(args) -> int:
    from .mcp_proxy.config import ProxyConfigError
    command = _draft_command(args)
    env = _draft_env(args.env)
    try:
        from .mcp_proxy import sdk
        from .mcp_proxy.draft import draft_specs, render_proxy_tools, render_rules, signed_check
    except ImportError as e:
        print(f"two-key: {e}", file=sys.stderr)
        return 1
    try:
        tools = sdk.draft_tools(command, env)
    except ProxyConfigError as e:
        print(f"two-key: mcp-draft-specs: {e}", file=sys.stderr)
        return 1
    if args.constitution is not None:
        return _draft_signed_check(tools, args.constitution, signed_check)
    try:
        draft = draft_specs(tools, args.tool)
    except ValueError as e:
        print(f"two-key: mcp-draft-specs: {e}", file=sys.stderr)
        return 1
    files = {"rules.draft.yaml": render_rules(draft, command),
             "proxy-tools.draft.yaml": render_proxy_tools(draft),
             "schemas.json": json.dumps(draft.views, indent=2, sort_keys=True, ensure_ascii=True) + "\n"}
    return _draft_write(draft, Path(args.out), files)


def _recover(args) -> int:
    from .ledger import Ledger, LedgerError
    key = _principal_key(args)
    try:
        result = Ledger.recover_tail(args.ledger, key, witness_public_key=_witness_pin(args),
                                     anchor_path=_anchor_arg(args))
    except LedgerError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 1
    print(json.dumps({"ok": True, **result}, indent=2))
    return 0


def _passphrase_env(args) -> dict:
    """The three backup passphrases, from the environment. They are never taken on argv."""
    names = {
        "principal": args.principal_passphrase_env,
        "ledger": args.ledger_passphrase_env,
        "witness": args.witness_passphrase_env,
    }
    out = {}
    for role, name in names.items():
        if name is None or not str(name).strip():
            raise SystemExit(f"--{role}-passphrase-env is required")
        value = os.environ.get(name)
        if value is None or value == "":
            raise SystemExit(f"environment variable {name} is unset or empty")
        out[role] = value
    return out


def _backup_export(args) -> int:
    from .backup import BackupError, export_backup
    try:
        result = export_backup(args.ledger, args.key, args.out, _passphrase_env(args),
                               witness_public_key=_witness_pin(args), anchor_path=_anchor_arg(args),
                               key_passphrase=_key_passphrase(args))
    except BackupError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def _backup_verify(args) -> int:
    from .backup import BackupError, verify_backup
    try:
        result = verify_backup(args.bundles, _passphrase_env(args), witness_public_key=_witness_pin(args),
                               key_passphrase=_key_passphrase(args))
    except BackupError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def _backup_restore(args) -> int:
    from .backup import BackupError, restore_backup
    try:
        result = restore_backup(args.ledger, args.key, args.bundles, _passphrase_env(args),
                                witness_public_key=_witness_pin(args), anchor_path=_anchor_arg(args),
                                replace_ledger=args.replace_ledger, key_passphrase=_key_passphrase(args))
    except BackupError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


_CONSTITUTION_FLAG = "--constitution"
_PROXY_CONFIG_HELP = "the proxy config file (YAML or JSON)"
_KEY_HELP = "the principal private key (principal.pem from init-key, mode 0600); not principal.pub.pem"
_KEY_UNLOCK_HELP = ("for an encrypted --key: a file only you can read holding its passphrase; without it, "
                        "the passphrase is asked for on the terminal")
_PASSPHRASE_HELP = "name of the environment variable holding this bundle's passphrase; not the passphrase"


_WITNESS_HELP = ("the witness public key (PEM), kept where whoever writes the ledger directory cannot change it; "
                 "a head signed by any other witness key is refused")
_ANCHOR_HELP = ("monotonic head anchor outside the ledger directory (default <ledger>.ledger-key/head.anchor); "
                "a signed head older than it, or a wiped ledger directory, is refused")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="two-key")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def _add_key(parser, help=_KEY_HELP):
        parser.add_argument("--key", required=True, help=help)
        parser.add_argument("--key-passphrase-file", default=None, metavar="FILE", help=_KEY_UNLOCK_HELP)
    init = sub.add_parser("init-key")
    init.add_argument("dir")
    protect = init.add_mutually_exclusive_group()
    protect.add_argument("--passphrase", action="store_true",
                         help="encrypt principal.pem with a passphrase typed twice on the terminal")
    protect.add_argument("--passphrase-file", default=None, metavar="FILE",
                         help="encrypt principal.pem with the passphrase in this file (only you can read it)")
    init.set_defaults(func=_init_key)
    sign = sub.add_parser("sign-constitution")
    _add_key(sign)
    sign.add_argument("--prose", required=True)
    sign.add_argument("--rules", required=True)
    sign.add_argument("--envelope-format", choices=ENVELOPE_FORMATS, default="auto",
                      help="auto (default): v1 unless the rules declare custom fields, then v2, or v3 when "
                           "they use a 0.5.0 feature (a source: caller field, case: exact, a not_applicable mark, "
                           "an @domain allow entry); v2 forces v2 (refused with any of those); v3 forces v3. "
                           "Installs older than custom fields refuse v2; installs before 0.5.0 refuse v3")
    sign.add_argument("--out", required=True)
    sign.add_argument("--force", action="store_true",
                      help="replace an existing --out file; without it, signing refuses rather than write "
                           "over a signed constitution")
    sign.set_defaults(func=_sign)
    auth = sub.add_parser("authorize", help="run Path A and Path B; do not execute the tool")
    _add_key(auth)
    auth.add_argument("--ledger", required=True)
    auth.add_argument(_CONSTITUTION_FLAG, required=True)
    auth.add_argument("--judges", required=True)
    auth.add_argument("--tool", required=True)
    auth.add_argument("--args", default="{}")
    auth.add_argument("--facts", default=None, metavar="FILE",
                      help="a JSON object of caller-supplied facts (source: caller fields) for this call")
    auth.add_argument("--proposal", required=True)
    auth.add_argument("--amount-usd", type=float, default=None,
                      help="claim this USD amount; omit it and the amount is read from the argument bytes")
    auth.add_argument("--data-class", default=None,
                      help="claim this data class (or financial+medical); omit it and a missing class is "
                           "classified, then the tool floor")
    auth.add_argument("--irreversible", action=argparse.BooleanOptionalAction, default=None,
                      help="claim irreversible, or --no-irreversible for reversible; omit it and the tool spec decides")
    auth.add_argument("--counterparty", default=None,
                      help="claim this counterparty; omit it and the party is read from the argument bytes")
    auth.add_argument("--agent-session-env", default=None, metavar="NAME",
                      help="name of the environment variable holding the agent session secret")
    auth.add_argument("--agent-session", default=None, help=argparse.SUPPRESS)
    auth.add_argument("--ttl-seconds", type=int, default=120,
                      help="token lifetime in seconds, 1 to 300; the gateway refuses longer tokens (default 120)")
    auth.add_argument("--emit-token", default=None, metavar="PATH",
                      help="write the token to a new 0600 file; it is never printed")
    auth.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    auth.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    auth.set_defaults(func=_authorize)
    rotate = sub.add_parser("rotate-witness", help="replace the ledger's witness key with a new one, ledgered")
    _add_key(rotate)
    rotate.add_argument("--ledger", required=True)
    rotate.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    rotate.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    rotate.add_argument("--reason", default="", help="recorded in the witness_rotated entry (at most 200 characters)")
    rotate.set_defaults(func=_rotate_witness)
    keys = sub.add_parser("keys", help="the key upgrade to hybrid Ed25519 + ML-DSA-65 (docs/UPGRADING.md)")
    keys_sub = keys.add_subparsers(dest="keys_cmd", required=True)
    upgrader = keys_sub.add_parser("upgrade", help="make a 0.8.0 deployment's keys hybrid and record keys_upgraded")
    upgrader.add_argument("--config", default=None, metavar="FILE", help=_PROXY_CONFIG_HELP)
    upgrader.add_argument("--key", default=None, help=_KEY_HELP)
    upgrader.add_argument("--key-passphrase-file", default=None, metavar="FILE", help=_KEY_UNLOCK_HELP)
    upgrader.add_argument("--ledger", default=None)
    upgrader.add_argument(_CONSTITUTION_FLAG, default=None, metavar="FILE",
                          help="the signed constitution, signed again with the hybrid key")
    upgrader.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    upgrader.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    upgrader.set_defaults(func=_keys_upgrade)
    audit = sub.add_parser("audit", help="verify the ledger and print its witness pins and digest checks")
    _add_key(audit)
    audit.add_argument("--ledger", required=True)
    audit.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    audit.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    audit.add_argument("--check-history", default=None, metavar="CONSTITUTION",
                       help="also rebuild every judge history summary from the ledger and check its history_digest; "
                            "CONSTITUTION is the signed constitution the decisions ran under")
    audit.set_defaults(func=_audit)
    viewer = sub.add_parser("ledger-view", help="search, filter, and sort the ledger's entries in a window "
                                                "(or print them); read-only")
    _add_key(viewer)
    viewer.add_argument("--ledger", required=True)
    viewer.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    viewer.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    viewer.add_argument("--search", default="", metavar="TEXT", help="keep entries with TEXT in any field's value")
    viewer.add_argument("--search-names", action="store_true",
                        help="--search also matches field names, such as tools.pay_bill.irreversible")
    viewer.add_argument("--where", action="append", nargs="+", default=None, metavar="FIELD OP [VALUE]",
                        help="keep entries where FIELD passes the test (repeatable); OP is contains, not-contains, "
                             "equals, not-equals, starts-with, ends-with, regex, gt, ge, lt, le, empty, or not-empty; "
                             "FIELD * means any field")
    viewer.add_argument("--any", action="store_true", help="keep entries that pass any --where (default: all)")
    viewer.add_argument("--sort", action="append", default=None, metavar="FIELD[:desc]",
                        help="sort by FIELD (repeatable; the first decides first); default seq")
    shown = viewer.add_mutually_exclusive_group()
    shown.add_argument("--print", action="store_true",
                       help="write the matching entries to stdout as JSON Lines instead of opening a window")
    shown.add_argument("--fields", action="store_true", help="list every field name a filter or sort can use")
    viewer.add_argument("--max-rows", type=int, default=10000, metavar="N",
                        help="list at most N matching entries in the window (default 10000); the count shows all")
    viewer.set_defaults(func=_ledger_view)
    editor = sub.add_parser("constitution-editor", help="write, check, try, and sign a constitution (prose, rules, "
                                                       "tool specs, fields, serial) in a window")
    editor.add_argument("--prose", default=None, metavar="FILE", help="start from this prose (with --rules)")
    editor.add_argument("--rules", default=None, metavar="FILE", help="start from this rules file (with --prose)")
    editor.add_argument("--signed", default=None, metavar="FILE",
                        help="start from a signed constitution, as its next version (the serial goes up by one)")
    editor.add_argument("--public-key", default=None, metavar="PEM",
                        help="check --signed against this public key before opening it")
    editor.add_argument("--key", default=None, help="fill in the principal key to sign with (asked for in the window "
                                                    "otherwise)")
    editor.add_argument("--dir", default=None, metavar="DIR", help="the folder to write into (default: the folder of "
                                                                    "--rules or --signed, else this one)")
    editor.add_argument("--check", action="store_true",
                        help="print whether the files sign, with every warning, instead of opening a window")
    editor.set_defaults(func=_constitution_editor)
    recover = sub.add_parser("recover", help="drop an uncheckpointed tail and record it; does not run on open")
    _add_key(recover)
    recover.add_argument("--ledger", required=True)
    recover.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    recover.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    recover.set_defaults(func=_recover)
    def _add_passphrases(parser):
        parser.add_argument("--principal-passphrase-env", required=True, metavar="NAME", help=_PASSPHRASE_HELP)
        parser.add_argument("--ledger-passphrase-env", required=True, metavar="NAME", help=_PASSPHRASE_HELP)
        parser.add_argument("--witness-passphrase-env", required=True, metavar="NAME", help=_PASSPHRASE_HELP)
    export = sub.add_parser("backup-export", help="write three passphrase-protected key bundles")
    _add_key(export)
    export.add_argument("--ledger", required=True)
    export.add_argument("--out", required=True, help="directory for the three new bundle files")
    export.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    export.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    _add_passphrases(export)
    export.set_defaults(func=_backup_export)
    verify = sub.add_parser("backup-verify", help="decrypt the bundles into a temporary ledger and check fingerprints")
    verify.add_argument("--bundles", required=True)
    verify.add_argument("--key-passphrase-file", default=None, metavar="FILE", help=_KEY_UNLOCK_HELP)
    verify.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    _add_passphrases(verify)
    verify.set_defaults(func=_backup_verify)
    restore = sub.add_parser("backup-restore",
                             help="restore keys; ledger files and head.anchor are written together")
    _add_key(restore, help="where to put principal.pem")
    restore.add_argument("--ledger", required=True)
    restore.add_argument("--bundles", required=True)
    restore.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    restore.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    restore.add_argument("--replace-ledger", action="store_true",
                         help="write the backup's ledger and head.anchor over a different ledger on disk; "
                              "does not delete the anchor")
    _add_passphrases(restore)
    restore.set_defaults(func=_backup_restore)
    exporter = sub.add_parser("siem-export", help="verify and decrypt the ledger locally and write its "
                                                  "events for a SIEM, without argument values")
    _add_key(exporter)
    exporter.add_argument("--ledger", required=True)
    exporter.add_argument("--out", default="-", metavar="FILE",
                          help="write to this new file (never an existing one); - writes to stdout (default)")
    exporter.add_argument("--schema", choices=SCHEMAS, default="native",
                          help="native (default): Two-Key's own field names; ecs: Elastic Common Schema; "
                               "ocsf: OCSF 1.1")
    exporter.add_argument("--format", choices=FORMATS, default="json",
                          help="json (default) or cef; cef maps the native schema only")
    exporter.add_argument("--from-seq", type=int, default=0, metavar="N",
                          help="start at this entry (default 0)")
    exporter.add_argument("--to-seq", type=int, default=None, metavar="N",
                          help="stop at this entry (default: the head)")
    exporter.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    exporter.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    exporter.set_defaults(func=_siem_export)
    siem_verify = sub.add_parser("siem-verify", help="check exported events (or events pulled back out of a "
                                                     "SIEM) against the ledger")
    _add_key(siem_verify)
    siem_verify.add_argument("--ledger", required=True)
    siem_verify.add_argument("--events", required=True, metavar="FILE",
                             help="the native JSON Lines events to check")
    siem_verify.add_argument("--require-complete", action="store_true",
                             help="also require every entry from 0 to the current head")
    siem_verify.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    siem_verify.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    siem_verify.set_defaults(func=_siem_verify)
    tool_key = sub.add_parser("tool-key", help="keys for the tool check (docs/TOOL_CHECK.md)")
    tool_key_sub = tool_key.add_subparsers(dest="tool_key_cmd", required=True)
    maker = tool_key_sub.add_parser("new", help="make a tool's receipt key and print its fingerprint")
    maker.add_argument("--out", required=True, metavar="FILE", help="the new private key file (never replaced)")
    maker.set_defaults(func=_tool_key_new)
    truster = tool_key_sub.add_parser("trust", help="write Two-Key's two public keys for a checking tool, each "
                                                    "checked against the ledger's pin")
    _add_key(truster)
    truster.add_argument("--ledger", required=True)
    truster.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    truster.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    truster.add_argument("--out", required=True, metavar="DIR", help="the folder to write the two public keys to")
    truster.set_defaults(func=_tool_key_trust)
    tool = sub.add_parser("tool", help="a checked tool held after a bad receipt")
    tool_sub = tool.add_subparsers(dest="tool_cmd", required=True)
    releaser = tool_sub.add_parser("release", help="let calls to a held tool go ahead again, ledgered with why")
    _add_key(releaser)
    releaser.add_argument("tool", help="the tool's signed id")
    releaser.add_argument("--ledger", required=True)
    releaser.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    releaser.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    releaser.add_argument("--reason", required=True, help="why the tool can be trusted again (at most 200 characters)")
    releaser.set_defaults(func=_tool_release)
    proxy = sub.add_parser("mcp-proxy", help="serve an upstream MCP server's signed tools over stdio, through "
                                             "both keys (needs the mcp extra)")
    proxy.add_argument("--config", required=True, help=_PROXY_CONFIG_HELP)
    proxy.set_defaults(func=_mcp_proxy)
    cfg = sub.add_parser("config", help="show, check, or change a proxy config's settings")
    cfg_sub = cfg.add_subparsers(dest="config_cmd", required=True)
    for name, text in (("show", "print the effective settings as JSON, defaults filled in, no secret values"),
                       ("check", "load every file the config names and report what would stop or warn at start; "
                                 "writes nothing, opens no ledger")):
        part = cfg_sub.add_parser(name, help=text)
        part.add_argument("--config", required=True, help=_PROXY_CONFIG_HELP)
        part.set_defaults(func=_config_show if name == "show" else _config_check)
    getter = cfg_sub.add_parser("get", help="print one setting: its value, file, tier, and default")
    getter.add_argument("--config", required=True, help=_PROXY_CONFIG_HELP)
    getter.add_argument("setting", help="the setting's name, as docs/SETTINGS.md lists it (siem.sinks[0].port)")
    getter.set_defaults(func=_config_get)
    setter = cfg_sub.add_parser("set", help="change one setting: checked, recorded in the ledger, undoable; "
                                            "takes effect at the next start")
    setter.add_argument("--config", required=True, help=_PROXY_CONFIG_HELP)
    setter.add_argument("setting", help="the setting's name, as docs/SETTINGS.md lists it (siem.sinks[0].port)")
    setter.add_argument("value", nargs="?", default=None,
                        help="the new value: JSON (true, 120, [\"a\"], {\"env\": \"NAME\"}) or plain text; never a "
                             "secret")
    setter.add_argument("--value-file", default=None, metavar="FILE",
                        help="read the value, as text, from this owner-only file (for a value that can be a secret)")
    setter.add_argument("--prompt", action="store_true", help="read the value, as text, from a hidden prompt")
    setter.add_argument("--unset", action="store_true", help="remove the setting, so its default applies")
    setter.add_argument("--confirm-weaker", action="store_true",
                        help="go ahead with a change that weakens what Two-Key enforces, after a typed yes")
    setter.add_argument("--key", default=None, metavar="FILE",
                        help="the principal private key, for a signed setting (hard_rules, tool_specs, fields)")
    setter.add_argument("--rules", default=None, metavar="FILE",
                        help="the rules file the constitution was signed from, for a signed setting")
    setter.add_argument("--key-passphrase-file", default=None, metavar="FILE", help=_KEY_UNLOCK_HELP)
    setter.set_defaults(func=_config_set)
    undoer = cfg_sub.add_parser("undo", help="put back the files the last config set (or undo) replaced")
    undoer.add_argument("--config", required=True, help=_PROXY_CONFIG_HELP)
    undoer.add_argument("--confirm-weaker", action="store_true",
                        help="go ahead when putting the files back weakens what Two-Key enforces")
    undoer.add_argument("--key", default=None, metavar="FILE",
                        help="the principal private key, when the change being undone signed a constitution")
    undoer.add_argument("--key-passphrase-file", default=None, metavar="FILE", help=_KEY_UNLOCK_HELP)
    undoer.set_defaults(func=_config_undo)
    phraser = cfg_sub.add_parser("key-passphrase",
                                 help="encrypt the principal key with a passphrase from a file, change it, or remove "
                                      "it; sets keys.passphrase_file to match, recorded in the ledger")
    phraser.add_argument("--config", required=True, help=_PROXY_CONFIG_HELP)
    which = phraser.add_mutually_exclusive_group(required=True)
    which.add_argument("--new-from", default=None, metavar="FILE",
                       help="absolute path of a file only this account can read, holding the new passphrase "
                            "(at least 12 bytes); keys.passphrase_file is set to it")
    which.add_argument("--remove", action="store_true",
                       help="store the key unencrypted again (weaker: needs --confirm-weaker)")
    phraser.add_argument("--confirm-weaker", action="store_true",
                         help="go ahead with --remove, after a typed yes")
    phraser.add_argument("--key-passphrase-file", default=None, metavar="FILE",
                         help="the file holding the CURRENT passphrase, when it is not keys.passphrase_file")
    phraser.set_defaults(func=_config_key_passphrase)
    setup = sub.add_parser("setup", help="write a new deployment's keys, rules, judges and proxy config, sign, "
                                         "and check them")
    setup.add_argument("--dir", required=True, help="a new folder for the files (never an existing one)")
    setup.add_argument("--answers", default=None, metavar="FILE",
                       help="read the answers from this YAML or JSON file instead of asking (docs/SETUP.md)")
    setup.add_argument("--confirm-weaker", action="store_true",
                       help="go ahead with --answers quorum numbers below the profile's own, after a typed yes")
    setup.add_argument("--window", action="store_true",
                       help="answer in a window instead of on the terminal (tkinter); with --answers, start from "
                            "that file")
    setup.set_defaults(func=_setup)
    drafter = sub.add_parser("mcp-draft-specs", help="draft tool_specs and the schema digest from an upstream MCP "
                                                     "server, for the principal to review and sign (needs the mcp extra)")
    drafter.add_argument("--out", default=None, metavar="DIR",
                         help="write rules.draft.yaml, proxy-tools.draft.yaml, and schemas.json here (never overwritten)")
    drafter.add_argument(_CONSTITUTION_FLAG, default=None, metavar="FILE",
                         help="instead, print the schema_digest of this signed constitution's tools")
    drafter.add_argument("--tool", action="append", default=None, metavar="NAME",
                         help="draft only this upstream tool (repeatable); default: all")
    drafter.add_argument("--env", action="append", default=None, metavar="NAME[=VALUE]",
                         help="pass this variable to the server (repeatable); NAME reads it from this environment")
    drafter.add_argument("command", nargs=argparse.REMAINDER, help="-- then the server's program and arguments")
    drafter.set_defaults(func=_mcp_draft_specs)
    demo = sub.add_parser("demo")
    demo.add_argument("--siem", default=None, metavar="FILE",
                      help="send the demo's ledger entries to the sinks in this file's siem: block")
    demo.set_defaults(func=_demo)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

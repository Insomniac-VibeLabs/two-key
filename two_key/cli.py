"""Command line for the concept build.

  two-key init-key DIR
  two-key sign-constitution --key KEY --prose FILE --rules FILE --out FILE [--envelope-format auto|v2]
  two-key authorize --key KEY --ledger DIR --constitution FILE --judges FILE --tool NAME
                    [--agent-session-env NAME] [--ttl-seconds N] [--emit-token PATH]
                    [--witness-public-key PEM]
  two-key rotate-witness --key KEY --ledger DIR [--witness-public-key PEM] [--reason TEXT]
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
  two-key audit --key KEY --ledger DIR [--witness-public-key PEM]
  two-key demo

``authorize`` never prints the bearer token. It prints the decision with the token's
jti and digest (the ledger's ``capability_issued.token_hash``). ``--emit-token PATH``
writes the token itself to a new file with mode 0600. The agent session secret is
read from the environment variable named by ``--agent-session-env``; it is never
taken on argv, where other local users and shell history can see it.

``--witness-public-key PEM`` is the witness pin outside the ledger: a copy of the
witness public key kept where whoever writes the ledger directory cannot change it.
``rotate-witness`` changes the witness key as a ledgered ``witness_rotated`` entry;
update that copy afterwards. ``recover`` drops only an uncheckpointed tail
(a crash between append and checkpoint) and records it. It does not roll a
signed head backwards, and it does not run on open. ``audit`` verifies the
ledger and the decision digests and prints both witness pins as JSON. The
head anchor (``<ledger>.ledger-key/head.anchor``, or ``--head-anchor``) refuses
a rollback or a wipe of the ledger directory. Creating a ledger at a new path
warns on stderr. Opening a ledger made before 0.2.3 pins its witness key
(trust on first use), whichever command opens it.

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
import sys
from pathlib import Path

from .constitution import ENVELOPE_FORMATS, load_unsigned_with_fields, save_envelope, sign_constitution
from .keys import generate_private_key, load_private_key_file, load_public_key, save_private_key, save_public_key


def _init_key(args) -> int:
    key = generate_private_key()
    dest = Path(args.dir)
    try:
        save_private_key(dest / "principal.pem", key)
    except FileExistsError:
        print(f"refusing to overwrite {dest / 'principal.pem'}", file=sys.stderr)
        return 1
    save_public_key(dest / "principal.pub.pem", key.public_key())
    print(f"wrote {dest / 'principal.pem'}")
    return 0


def _sign(args) -> int:
    key = load_private_key_file(args.key)
    prose, rules, specs, fields = load_unsigned_with_fields(args.prose, args.rules)
    save_envelope(args.out, sign_constitution(prose, rules, key, specs, fields=fields,
                                              envelope_format=args.envelope_format))
    print(f"wrote {args.out}")
    return 0


def _demo(_args) -> int:
    import tempfile
    from .constitution import sign_constitution
    from .core import TwoKey
    from .ledger import Ledger
    from .quorum import QuorumPolicy
    from .testing import TEST_AGENT, FixedJudge

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
                    judges, private_key=key, quorum=QuorumPolicy(required_yes=2), allow_test_doubles=True, monitored_agent=TEST_AGENT)
        denied = tk.authorize({"tool": "wire_transfer", "amount_usd": 10, "data_class": "public", "irreversible": True},
                              {}, "please wire the funds")
        allowed = tk.authorize({"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
                               {"to": "ada@example"}, "draft a note")
        gateway = tk.gateway(tools={"email_draft": lambda a: {"drafted": a.get("to")}})
        redeemed = gateway.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
        replay = gateway.invoke(allowed.token, "email_draft", {"to": "ada@example"}) if allowed.token else None
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


def _open_ledger(args, key):
    """Open an existing ledger for rotate-witness and audit; a refusal is printed, not raised. A path with no
    ledger is refused rather than created."""
    from .ledger import Ledger, LedgerError
    if not (Path(args.ledger) / "entries.jsonl").is_file():
        print(json.dumps({"ok": False, "error": f"no ledger at {args.ledger}"}, indent=2))
        return None
    try:
        return Ledger(args.ledger, key, witness_public_key=_witness_pin(args), anchor_path=_anchor_arg(args))
    except LedgerError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return None


def _rotate_witness(args) -> int:
    from .ledger import LedgerError
    key = load_private_key_file(args.key)
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


def _audit(args) -> int:
    from .audit import check_decision_digests
    key = load_private_key_file(args.key)
    ledger = _open_ledger(args, key)
    if ledger is None:
        return 1
    witness = ledger.witness_report()       # opening verified the chain, the head, and both pins
    problems = check_decision_digests(ledger)
    print(json.dumps({"ok": not problems, "size": ledger.size(), "witness": witness,
                      "decision_digest_problems": problems}, indent=2))
    return 0 if not problems else 1


def _write_token(path: Path, token: str) -> None:
    """Write the bearer token to a new file, mode 0600 from creation. Never overwrite."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(token + "\n")


def _authorize(args) -> int:
    from .constitution import load_envelope
    from .core import TwoKey
    from .identity import load_monitored_agent_file
    from .judges.config import load_config_file
    from .ledger import Ledger, LedgerError
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
    token_path = Path(args.emit_token) if args.emit_token else None
    if token_path is not None and (token_path.exists() or token_path.is_symlink()):
        print(f"refusing to overwrite {token_path}", file=sys.stderr)
        return 1
    key = load_private_key_file(args.key)
    judges, policy = load_config_file(Path(args.judges))
    # The monitored agent is declared by the operator in the judges file, never by the agent.
    agent = load_monitored_agent_file(Path(args.judges))
    try:
        ledger = Ledger(args.ledger, key, witness_public_key=_witness_pin(args), anchor_path=_anchor_arg(args))
    except LedgerError as e:
        print(f"ledger refused: {e}", file=sys.stderr)
        return 1
    tk = TwoKey.load(ledger, key.public_key(), load_envelope(args.constitution), judges,
                     private_key=key, quorum=policy, monitored_agent=agent,
                     ttl_seconds=args.ttl_seconds)
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
    decision = tk.authorize(action, arguments, args.proposal, agent_session=agent_session, origin="cli")
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


def _recover(args) -> int:
    from .ledger import Ledger, LedgerError
    key = load_private_key_file(args.key)
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
                               witness_public_key=_witness_pin(args), anchor_path=_anchor_arg(args))
    except BackupError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def _backup_verify(args) -> int:
    from .backup import BackupError, verify_backup
    try:
        result = verify_backup(args.bundles, _passphrase_env(args), witness_public_key=_witness_pin(args))
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
                                replace_ledger=args.replace_ledger)
    except BackupError as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


_PASSPHRASE_HELP = "name of the environment variable holding this bundle's passphrase; not the passphrase"


_WITNESS_HELP = ("the witness public key (PEM), kept where whoever writes the ledger directory cannot change it; "
                 "a head signed by any other witness key is refused")
_ANCHOR_HELP = ("monotonic head anchor outside the ledger directory (default <ledger>.ledger-key/head.anchor); "
                "a signed head older than it, or a wiped ledger directory, is refused")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="two-key")
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init-key")
    init.add_argument("dir")
    init.set_defaults(func=_init_key)
    sign = sub.add_parser("sign-constitution")
    sign.add_argument("--key", required=True)
    sign.add_argument("--prose", required=True)
    sign.add_argument("--rules", required=True)
    sign.add_argument("--envelope-format", choices=ENVELOPE_FORMATS, default="auto",
                      help="auto (default): v1 unless the rules declare custom fields, then v2; "
                           "v2: always v2. Installs older than custom fields refuse v2")
    sign.add_argument("--out", required=True)
    sign.set_defaults(func=_sign)
    auth = sub.add_parser("authorize", help="run Path A and Path B; do not execute the tool")
    auth.add_argument("--key", required=True)
    auth.add_argument("--ledger", required=True)
    auth.add_argument("--constitution", required=True)
    auth.add_argument("--judges", required=True)
    auth.add_argument("--tool", required=True)
    auth.add_argument("--args", default="{}")
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
    rotate.add_argument("--key", required=True)
    rotate.add_argument("--ledger", required=True)
    rotate.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    rotate.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    rotate.add_argument("--reason", default="", help="recorded in the witness_rotated entry (at most 200 characters)")
    rotate.set_defaults(func=_rotate_witness)
    audit = sub.add_parser("audit", help="verify the ledger and print its witness pins and digest checks")
    audit.add_argument("--key", required=True)
    audit.add_argument("--ledger", required=True)
    audit.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    audit.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    audit.set_defaults(func=_audit)
    recover = sub.add_parser("recover", help="drop an uncheckpointed tail and record it; does not run on open")
    recover.add_argument("--key", required=True)
    recover.add_argument("--ledger", required=True)
    recover.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    recover.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    recover.set_defaults(func=_recover)
    def _add_passphrases(parser):
        parser.add_argument("--principal-passphrase-env", required=True, metavar="NAME", help=_PASSPHRASE_HELP)
        parser.add_argument("--ledger-passphrase-env", required=True, metavar="NAME", help=_PASSPHRASE_HELP)
        parser.add_argument("--witness-passphrase-env", required=True, metavar="NAME", help=_PASSPHRASE_HELP)
    export = sub.add_parser("backup-export", help="write three passphrase-protected key bundles")
    export.add_argument("--key", required=True)
    export.add_argument("--ledger", required=True)
    export.add_argument("--out", required=True, help="directory for the three new bundle files")
    export.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    export.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    _add_passphrases(export)
    export.set_defaults(func=_backup_export)
    verify = sub.add_parser("backup-verify", help="decrypt the bundles into a temporary ledger and check fingerprints")
    verify.add_argument("--bundles", required=True)
    verify.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    _add_passphrases(verify)
    verify.set_defaults(func=_backup_verify)
    restore = sub.add_parser("backup-restore",
                             help="restore keys; ledger files and head.anchor are written together")
    restore.add_argument("--key", required=True, help="where to put principal.pem")
    restore.add_argument("--ledger", required=True)
    restore.add_argument("--bundles", required=True)
    restore.add_argument("--witness-public-key", default=None, metavar="PEM", help=_WITNESS_HELP)
    restore.add_argument("--head-anchor", default=None, metavar="PATH", help=_ANCHOR_HELP)
    restore.add_argument("--replace-ledger", action="store_true",
                         help="write the backup's ledger and head.anchor over a different ledger on disk; "
                              "does not delete the anchor")
    _add_passphrases(restore)
    restore.set_defaults(func=_backup_restore)
    demo = sub.add_parser("demo")
    demo.set_defaults(func=_demo)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""Command-line interface: ``python -m compact_kernel <command>``.

Commands:
  keygen               generate the principal's Ed25519 key pair
  sign-constitution    bundle a plain-English constitution plus a hard-rules file and sign them
  verify-constitution  verify a signed constitution against the principal's public key
  verify-ledger        verify a ledger's hash chain, signed head and Merkle root
  check-judges         validate a judges.yaml (no network calls)
  demo                 run the offline demo
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import keys
from .constitution import ConstitutionSignatureError, load_envelope, save_envelope, sign_files, verify_signed
from .policy_vm import ConstitutionError, compile_constitution


def _passphrase(args, confirm: bool = False) -> bytes | None:
    if getattr(args, "passphrase_env", None):
        v = os.environ.get(args.passphrase_env)
        if v is None:
            sys.exit(f"environment variable {args.passphrase_env} is not set")
        return v.encode()
    if getattr(args, "no_passphrase", False):
        return None
    p = getpass.getpass("Key passphrase (empty for none): ")
    if confirm and p and getpass.getpass("Repeat passphrase: ") != p:
        sys.exit("passphrases do not match")
    return p.encode() or None


def cmd_keygen(args) -> int:
    out = Path(args.out)
    priv, pub = out / "principal.pem", out / "principal.pub.pem"
    if priv.exists():
        sys.exit(f"refusing to overwrite {priv}")
    k = keys.generate_private_key()
    keys.save_private_key(priv, k, _passphrase(args, confirm=True))
    keys.save_public_key(pub, k)
    print(f"private key: {priv} (mode 0600, keep it secret, never commit)")
    print(f"public key : {pub}")
    print(f"fingerprint: {keys.fingerprint(k)}")
    return 0


def cmd_sign(args) -> int:
    k = keys.load_private_key(Path(args.key), _passphrase(args))
    try:
        env = sign_files(Path(args.text), Path(args.rules), args.principal, k)
    except ConstitutionError as e:
        sys.exit(f"constitution rejected: {e}")
    save_envelope(Path(args.out), env)
    print(f"signed constitution written to {args.out} (signer {keys.fingerprint(k)})")
    return 0


def cmd_verify(args) -> int:
    try:
        c = verify_signed(load_envelope(Path(args.signed)), keys.load_public_key(Path(args.pub)))
        bc = compile_constitution(c.hard_rules)
    except (ConstitutionSignatureError, ConstitutionError, ValueError) as e:
        print(f"REJECTED: {e}")
        return 1
    print(f"OK: principal={c.principal} created_at={c.created_at} rules={len(c.hard_rules)} "
          f"bytecode={len(bc)} digest={c.digest[:16]}… signer={c.signer_fingerprint}")
    return 0


def cmd_verify_ledger(args) -> int:
    from .ledger import LedgerError, PersonalLedger
    try:
        rep = PersonalLedger(Path(args.ledger)).verify(keys.load_public_key(Path(args.pub)))
    except LedgerError as e:
        print(f"REJECTED: {e}")
        return 1
    print(f"{'OK' if rep.ok else 'REJECTED'}: {rep.reason} (entries={rep.size})")
    return 0 if rep.ok else 1


def cmd_check_judges(args) -> int:
    from .judges.config import JudgeConfigError, load_config_file
    try:
        judges, pol = load_config_file(Path(args.config))
    except (JudgeConfigError, ValueError, KeyError) as e:
        print(f"INVALID: {e}")
        return 1
    for j in judges:
        print(f"  {j.judge_id:<16} {type(j).__name__:<22} provider={j.provider} model={j.model} "
              f"endpoint={j.base_url} auth={j.credential!r}")
    print(f"OK: {len(judges)} judges; required_yes={pol.required_yes} "
          f"min_responding={pol.effective_min_responding} min_distinct_providers={pol.min_distinct_providers}")
    return 0


def cmd_demo(args) -> int:
    from .demo import main as demo_main
    demo_main()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="compact_kernel", description="Compact Kernel prototype CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    def pw(sp):
        sp.add_argument("--passphrase-env", help="read the key passphrase from this environment variable")
        sp.add_argument("--no-passphrase", action="store_true", help="unencrypted key (testing only)")

    s = sub.add_parser("keygen", help="generate principal Ed25519 key pair"); s.add_argument("--out", required=True); pw(s)
    s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("sign-constitution", help="sign constitution text + hard rules")
    s.add_argument("--text", required=True, help=".txt/.md plain-English constitution")
    s.add_argument("--rules", required=True, help=".json/.yaml hard rules for Path A")
    s.add_argument("--principal", required=True, help="principal identifier, e.g. did:ck:alice")
    s.add_argument("--key", required=True, help="principal private key (PEM)")
    s.add_argument("--out", required=True); pw(s); s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("verify-constitution", help="verify a signed constitution")
    s.add_argument("--signed", required=True); s.add_argument("--pub", required=True); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("verify-ledger", help="verify a ledger against the principal's public key")
    s.add_argument("--ledger", required=True); s.add_argument("--pub", required=True)
    s.set_defaults(fn=cmd_verify_ledger)
    s = sub.add_parser("check-judges", help="validate judges.yaml without calling any API")
    s.add_argument("--config", required=True); s.set_defaults(fn=cmd_check_judges)
    s = sub.add_parser("demo", help="run the offline demo"); s.set_defaults(fn=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

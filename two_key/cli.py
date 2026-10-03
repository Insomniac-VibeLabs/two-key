"""Command-line interface: ``two-key <command>`` (or ``python -m two_key <command>``).

Global options (before the command): --fips (refuse non-approved algorithms),
--pq-backend auto|pyca|liboqs|none.

Commands:
  keygen               generate the principal's key pair (--suite, default ed25519;
                       --seed-phrase also shows a 24-word backup once, personal mode only)
  recover-key          rebuild the key file from the 24-word seed phrase
  verify-seed-phrase   check the seed phrase (checksum, and against a public key) without writing anything
  sign-constitution    bundle a plain-English constitution plus a hard-rules file and sign them
  verify-constitution  verify a signed constitution against the principal's public key
  verify-ledger        verify a ledger's hash chain, signed head and Merkle root
  check-judges         validate a judges.yaml (no network calls)
  selftest             run the crypto known-answer self-test and show the provider
  deployment-mode      show the deployment mode (personal or enterprise) and where it is set
  demo                 run the offline demo
  e2e-demo             exercise every capability end to end, offline (exit 0 = every check passed)
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from . import keys
from .constitution import (ConstitutionSignatureError, load_envelope, save_envelope, sign_files, sign_source_file,
                           verify_signed)
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


def _seed_policy(args):
    """Seed phrases: personal mode only, never in fips_mode (seedphrase.check_allowed)."""
    from .crypto import default_provider
    from .deployment import DeploymentConfigError, resolve
    from .seedphrase import SeedPhrasePolicyError, check_allowed
    try:
        dep = resolve(getattr(args, "deployment_mode", None), config_path=getattr(args, "deployment_config", None))
        check_allowed(default_provider(), dep)
    except (SeedPhrasePolicyError, DeploymentConfigError) as e:
        sys.exit(f"REFUSED: {e}")
    return dep


def _seed_passphrase(args, confirm: bool = False) -> str:
    """The optional BIP-39 passphrase (not the key-file passphrase). Empty means none."""
    if getattr(args, "seed_passphrase_env", None):
        v = os.environ.get(args.seed_passphrase_env)
        if v is None:
            sys.exit(f"environment variable {args.seed_passphrase_env} is not set")
        return v
    if getattr(args, "seed_passphrase_prompt", False):
        p = getpass.getpass("Seed passphrase (empty for none): ")
        if confirm and p and getpass.getpass("Repeat seed passphrase: ") != p:
            sys.exit("seed passphrases do not match")
        return p
    return ""


def _read_words() -> str:
    """The 24 words from the terminal (not echoed) or from stdin. Never logged or echoed."""
    if sys.stdin.isatty():
        return getpass.getpass("Seed phrase (24 words, not echoed): ")
    return sys.stdin.readline()


def _save_key(out: Path, suite: str, k, args) -> tuple[Path, Path]:
    legacy = suite == "ed25519"
    priv = out / ("principal.pem" if legacy else "principal.keys.json")
    pub = out / ("principal.pub.pem" if legacy else "principal.pub.json")
    if priv.exists():
        sys.exit(f"refusing to overwrite {priv}")
    if legacy:
        keys.save_private_key(priv, k, _passphrase(args, confirm=True))
        keys.save_public_key(pub, k)
    else:
        keys.save_keyset(priv, k, _passphrase(args, confirm=True))
        keys.save_public_keyset(pub, k.public())
    return priv, pub


def cmd_keygen(args) -> int:
    from .crypto import PQUnavailableError
    out = Path(args.out)
    legacy = args.suite == "ed25519"
    priv = out / ("principal.pem" if legacy else "principal.keys.json")
    pub = out / ("principal.pub.pem" if legacy else "principal.pub.json")
    if priv.exists():
        sys.exit(f"refusing to overwrite {priv}")
    if args.seed_phrase:
        from .seedphrase import SeedPhraseError, generate
        dep = _seed_policy(args)
        try:
            phrase, k = generate(args.suite, _seed_passphrase(args, confirm=True), deployment=dep)
        except (PQUnavailableError, SeedPhraseError) as e:
            sys.exit(f"cannot generate {args.suite}: {e}")
        priv, pub = _save_key(out, args.suite, k, args)
        words = phrase.reveal().split()
        print("SEED PHRASE BACKUP: shown once, not stored. Write it down and keep it offline.")
        print("Anyone with these words (and the seed passphrase, if you set one) can rebuild this key.")
        for i in range(0, 24, 6):
            print("  " + "  ".join(f"{n + 1:>2}. {w:<9}" for n, w in enumerate(words[i:i + 6], start=i)).rstrip())
        del words, phrase
        print(f"private key: {priv} (mode 0600, keep it secret, never commit)")
        print(f"public key : {pub}")
        print(f"fingerprint: {keys.fingerprint(k)}")
        return 0
    try:
        k = keys.generate_keyset(args.suite)
    except PQUnavailableError as e:
        sys.exit(f"cannot generate {args.suite}: {e}")
    if legacy:
        keys.save_private_key(priv, k, _passphrase(args, confirm=True))
        keys.save_public_key(pub, k)
    else:
        keys.save_keyset(priv, k, _passphrase(args, confirm=True))
        keys.save_public_keyset(pub, k.public())
    print(f"private key: {priv} (mode 0600, keep it secret, never commit)")
    print(f"public key : {pub}")
    print(f"fingerprint: {keys.fingerprint(k)}")
    return 0


def cmd_recover_key(args) -> int:
    """Rebuild the key file from the seed phrase (stdin or a hidden prompt)."""
    from .crypto import PQUnavailableError
    from .crypto.signatures import as_public_keyset
    from .seedphrase import SeedPhraseError, derive_key
    dep = _seed_policy(args)
    try:
        k = derive_key(_read_words(), args.suite, _seed_passphrase(args), deployment=dep)
    except (PQUnavailableError, SeedPhraseError) as e:
        sys.exit(f"REJECTED: {e}")
    if args.expect_pub and as_public_keyset(keys.load_public_any(Path(args.expect_pub))).encoded != \
            as_public_keyset(k).encoded:
        sys.exit("REJECTED: the phrase (and seed passphrase) do not give the expected public key; nothing was written")
    priv, pub = _save_key(Path(args.out), args.suite, k, args)
    print(f"recovered private key: {priv} (mode 0600)")
    print(f"public key : {pub}")
    print(f"fingerprint: {keys.fingerprint(k)}")
    return 0


def cmd_verify_seed_phrase(args) -> int:
    """Check the words (and, with --pub, that they re-derive that key). Writes nothing."""
    from .crypto import PQUnavailableError
    from .seedphrase import SeedPhraseError, matches, validate
    dep = _seed_policy(args)
    try:
        words = _read_words()
        validate(words)
        if not args.pub:
            print("OK: 24 words, BIP-39 checksum valid (no --pub given, so the key itself was not checked)")
            return 0
        pub = keys.load_public_any(Path(args.pub))
        ok = matches(words, pub, _seed_passphrase(args), deployment=dep)
    except (PQUnavailableError, SeedPhraseError) as e:
        print(f"REJECTED: {e}")
        return 1
    if not ok:
        print("MISMATCH: checksum valid, but the phrase (and seed passphrase) give a different key")
        return 1
    print(f"OK: the phrase re-derives {keys.fingerprint(pub)}; nothing was written")
    return 0


def cmd_sign(args) -> int:
    k = keys.load_private_any(Path(args.key), _passphrase(args))
    try:
        if args.document:
            if args.text or args.rules:
                sys.exit("use either --document or --text/--rules, not both")
            env = sign_source_file(Path(args.document), args.principal, k)
        else:
            if not (args.text and args.rules):
                sys.exit("--text and --rules are required (or use --document)")
            env = sign_files(Path(args.text), Path(args.rules), args.principal, k)
    except ConstitutionError as e:
        sys.exit(f"constitution rejected: {e}")
    save_envelope(Path(args.out), env)
    print(f"signed constitution written to {args.out} (signer {keys.fingerprint(k)})")
    return 0


def cmd_verify(args) -> int:
    try:
        c = verify_signed(load_envelope(Path(args.signed)), keys.load_public_any(Path(args.pub)))
        bc = compile_constitution(c.hard_rules)
    except (ConstitutionSignatureError, ConstitutionError, ValueError, RuntimeError) as e:
        print(f"REJECTED: {e}")
        return 1
    print(f"OK: principal={c.principal} created_at={c.created_at} rules={len(c.hard_rules)} "
          f"bytecode={len(bc)} digest={c.digest_alg}:{c.digest[:16]}… signer={c.signer_fingerprint}")
    return 0


def cmd_verify_ledger(args) -> int:
    from .ledger import LedgerError, PersonalLedger
    try:
        signing = None
        if getattr(args, "key", None):
            signing = keys.load_private_any(Path(args.key), _passphrase(args))
        rep = PersonalLedger(Path(args.ledger), signing_key=signing).verify(keys.load_public_any(Path(args.pub)))
    except (LedgerError, ValueError, RuntimeError) as e:
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


def cmd_selftest(args) -> int:
    from .crypto import SelfTestError, default_provider
    p = default_provider()
    try:
        rep = p.ensure_selftest()
    except SelfTestError as e:
        print(f"SELF-TEST FAILED: {e}")
        return 1
    if args.require_pq and p.pq_backend() is None:
        print("SELF-TEST FAILED: --require-pq given but no ML-DSA backend is available")
        return 1
    print(json.dumps({"selftest": rep, "provider": p.describe()}, indent=2, default=str))
    return 0


def cmd_deployment_mode(args) -> int:
    from .deployment import DeploymentConfigError, resolve
    try:
        c = resolve(args.mode, config_path=args.config)
    except (DeploymentConfigError, OSError, ValueError) as e:
        print(f"INVALID: {e}")
        return 1
    print(f"OK: deployment_mode={c.mode} source={c.source}")
    return 0


def cmd_demo(args) -> int:
    from .demo import main as demo_main
    demo_main()
    return 0


def cmd_e2e_demo(args) -> int:
    from .e2e_demo import main as e2e_main
    return e2e_main()


def build_parser() -> argparse.ArgumentParser:
    from .crypto.signatures import SUITES
    p = argparse.ArgumentParser(prog="two-key", description="Two-Key prototype CLI")
    p.add_argument("--fips", action="store_true", help="fips_mode: refuse non-approved algorithms and liboqs")
    p.add_argument("--pq-backend", default="auto", choices=["auto", "pyca", "liboqs", "none"])
    sub = p.add_subparsers(dest="cmd", required=True)

    def pw(sp):
        sp.add_argument("--passphrase-env", help="read the key passphrase from this environment variable")
        sp.add_argument("--no-passphrase", action="store_true", help="unencrypted key (testing only)")

    s = sub.add_parser("keygen", help="generate the principal key pair"); s.add_argument("--out", required=True); pw(s)
    s.add_argument("--suite", default="ed25519", choices=sorted(SUITES),
                   help="ed25519 (legacy PEM), ecdsa-p384, or a hybrid ML-DSA-65 suite")

    def seed(sp):
        sp.add_argument("--seed-passphrase-env", help="optional BIP-39 passphrase from this environment variable")
        sp.add_argument("--seed-passphrase-prompt", action="store_true", help="prompt for an optional BIP-39 passphrase")
        sp.add_argument("--deployment-mode", help="personal or enterprise (seed phrases: personal only)")
        sp.add_argument("--deployment-config", help="config file with deployment_mode:")
    s.add_argument("--seed-phrase", action="store_true",
                   help="derive the key from a new 24-word BIP-39 phrase, shown once (personal mode; not with --fips)")
    seed(s)
    s.set_defaults(fn=cmd_keygen)
    s = sub.add_parser("recover-key", help="rebuild the key file from the 24-word seed phrase (read from stdin)")
    s.add_argument("--out", required=True); pw(s); seed(s)
    s.add_argument("--suite", default="ed25519", choices=sorted(SUITES))
    s.add_argument("--expect-pub", help="refuse to write unless the result matches this public key file")
    s.set_defaults(fn=cmd_recover_key)
    s = sub.add_parser("verify-seed-phrase", help="check the seed phrase without writing anything")
    s.add_argument("--pub", help="public key file the phrase should re-derive (suite taken from it)"); seed(s)
    s.set_defaults(fn=cmd_verify_seed_phrase)
    s = sub.add_parser("sign-constitution", help="sign constitution text + hard rules, or one single-source document")
    s.add_argument("--text", help=".txt/.md plain-English constitution")
    s.add_argument("--rules", help=".json/.yaml hard rules for Path A")
    s.add_argument("--document", help="single .md source with one ```twokey-rules JSON block (format /2)")
    s.add_argument("--principal", required=True, help="principal identifier, e.g. did:twokey:alice")
    s.add_argument("--key", required=True, help="principal private key (PEM or .keys.json bundle)")
    s.add_argument("--out", required=True); pw(s); s.set_defaults(fn=cmd_sign)
    s = sub.add_parser("verify-constitution", help="verify a signed constitution")
    s.add_argument("--signed", required=True); s.add_argument("--pub", required=True); s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("verify-ledger", help="verify a ledger against the principal's public key")
    s.add_argument("--ledger", required=True); s.add_argument("--pub", required=True)
    s.add_argument("--key", help="principal private key; required to decrypt the ledger")
    pw(s)
    s.set_defaults(fn=cmd_verify_ledger)
    s = sub.add_parser("check-judges", help="validate judges.yaml without calling any API")
    s.add_argument("--config", required=True); s.set_defaults(fn=cmd_check_judges)
    s = sub.add_parser("selftest", help="run the crypto self-test")
    s.add_argument("--require-pq", action="store_true", help="fail if no ML-DSA backend is available")
    s.set_defaults(fn=cmd_selftest)
    s = sub.add_parser("deployment-mode", help="show the deployment mode and where it is set")
    s.add_argument("--mode", help="personal or enterprise (as passed to TwoKey(deployment_mode=))")
    s.add_argument("--config", help="config file with deployment_mode: (JSON or YAML)")
    s.set_defaults(fn=cmd_deployment_mode)
    s = sub.add_parser("demo", help="run the offline demo"); s.set_defaults(fn=cmd_demo)
    s = sub.add_parser("e2e-demo", help="exercise every capability end to end, offline")
    s.set_defaults(fn=cmd_e2e_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    from .crypto import CryptoPolicyError, CryptoProvider, set_default_provider
    args = build_parser().parse_args(argv)
    if args.fips or args.pq_backend != "auto":
        try:
            set_default_provider(CryptoProvider(fips_mode=args.fips, pq_backend=args.pq_backend))
        except CryptoPolicyError as e:
            print(f"REFUSED: {e}")
            return 2
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())

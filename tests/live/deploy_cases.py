"""Run 9: the set-up and change commands (`two-key setup`, `config set`, `undo`, `key-passphrase`) and their ledger
entry (`config_changed`), driven the way an operator would, with no bot.

The harness is Two-Key's own account here, which is exactly who these commands are for (docs/SETUP.md). Three things
follow, and the pass says so rather than guessing:

- They refuse to run as root (`config_as_root`), so a pass run as root marks every step `not applicable`.
- A weaker or signed change needs a typed `yes` on a terminal. Steps that must be refused for want of one run with no
  terminal; steps that must succeed once a human types `yes` run on a pseudo-terminal that types it. That needs the
  `pty` module, so Windows marks those steps `not applicable`.
- Every step runs the package under test (`PKG`), so `--sabotage` weakens these commands too.

`run(ctx)` runs the whole story once and returns `{step: {"rc", "stdout", "stderr", "facts"}}`; `make_cases.py` has one
case per step, with what it expects of the result. The facts are read from the files and the ledger after the step,
by the harness, never from what the command printed about itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess  # nosec B404 - runs this repository's own CLI
import sys
from pathlib import Path

PASSPHRASE = "correct horse battery staple"          # 12+ bytes; made up for the pass, protects a throwaway key
CANARY = "canary-not-a-secret-7731"                   # a value that must never be written anywhere by a refusal


def not_applicable() -> str | None:
    if os.name == "nt":
        return "needs a POSIX terminal (pty) and a non-root account; these commands are run by hand on Windows"
    if os.geteuid() == 0:
        return "the commands refuse to run as root (config_as_root); run the pass as Two-Key's own account"
    return None


def sha_file(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def run_cli(ctx, args, *, answer: str | None = None):
    """One CLI call. `answer` types that line on a pseudo-terminal; without it there is no terminal at all."""
    cmd = [sys.executable, "-m", "two_key", *map(str, args)]
    kw = dict(cwd=ctx["pkg"], capture_output=True, text=True, env=ctx["env"], timeout=300)
    if answer is None:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, **kw)  # nosec B603
    else:
        import pty
        master, slave = pty.openpty()
        try:
            os.write(master, (answer + "\n").encode())       # typed ahead: the line waits in the terminal's queue
            r = subprocess.run(cmd, stdin=slave, **kw)  # nosec B603
        finally:
            os.close(master)
            os.close(slave)
    ctx["log"]("cli", args=[str(a)[:120] for a in args], rc=r.returncode, stdout=r.stdout[-3000:],
               stderr=r.stderr[-3000:], tty=answer is not None)
    return {"rc": r.returncode, "stdout": r.stdout[-6000:], "stderr": r.stderr[-6000:]}


def ledger_bodies(ctx, dep: Path, kind="config_changed", *, passphrase_file: Path | None = None):
    """The bodies of one kind in a deployment's ledger, read with the real package and the deployment's own key."""
    from two_key.keys import load_private_key_file, passphrase_source
    from two_key.ledger import Ledger
    key = load_private_key_file(dep / "principal.pem", passphrase_source(passphrase_file, prompt=False)
                                if passphrase_file else None)
    return [e.body for e in Ledger(str(dep / "ledger"), key).entries if e.kind == kind]


def tree_text(dep: Path) -> bytes:
    """Every byte under a deployment folder, for 'this value appears nowhere'."""
    return b"".join(p.read_bytes() for p in sorted(dep.rglob("*")) if p.is_file() and not p.is_symlink())


def answers(ctx, **over) -> dict:
    ports = ctx["ports"]
    base = {
        "route": "proxy", "profile": "default",
        "judges": [
            {"id": "test-judge-a", "type": "openai_compatible", "provider": "grokbot", "model": "test-judge-a",
             "base_url": f"http://127.0.0.1:{ports['judgeA']}/v1", "auth_env": "LIVE_JUDGE_A_KEY",
             "upstream": "api.x.ai", "timeout": 20},
            {"id": "test-judge-b", "type": "openai_compatible", "provider": "grokbot", "model": "test-judge-b",
             "base_url": f"http://127.0.0.1:{ports['judgeB']}/v1", "auth_env": "LIVE_JUDGE_B_KEY",
             "upstream": "api.x.ai", "timeout": 20}],
        "monitored_agent": {"id": "test-monitored-agent", "model": "test-monitored-agent", "provider": "grokbot",
                            "base_url": f"http://127.0.0.1:{ports['agent']}/v1", "credential_env": "LIVE_AGENT_API_KEY",
                            "upstream": "api.x.ai"},
        "rules_file": str(ctx["rules"]), "prose_file": str(ctx["prose"]),
        "upstream": {"command": ctx["server_cmd"]},
        "agent_session_env": "LIVE_AGENT_API_KEY",
    }
    base.update(over)
    return base


def write_answers(ctx, name, **over) -> Path:
    path = ctx["work"] / f"answers_{name}.json"
    path.write_text(json.dumps(answers(ctx, **over), indent=1))
    os.chmod(path, 0o600)
    return path


def private_file(path: Path, text: str, mode=0o600) -> Path:
    path.write_text(text)
    os.chmod(path, mode)
    return path


def run(ctx) -> dict:
    """The whole story. `ctx` has: pkg, env, work (a folder only this account can change), log, ports, rules, prose,
    server_cmd."""
    na = not_applicable()
    if na:
        return {"_not_applicable": na}
    work: Path = ctx["work"]
    out: dict = {}

    def step(name, args, *, answer=None, facts=None):
        res = run_cli(ctx, args, answer=answer)
        try:
            res["facts"] = facts() if callable(facts) else (facts or {})
        except Exception as exc:          # a fact that cannot be read is a failed expectation, not a crashed pass
            res["facts"] = {"facts_error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        out[name] = res
        return res

    # ---- deployment A: setup, then changes one at a time
    a = work / "deploy_a"
    pa = a / "proxy.yaml"

    def modes_ok():
        loose = [p.name for p in sorted(a.iterdir()) if p.is_file() and p.name != "principal.pub.pem"
                 and stat.S_IMODE(p.stat().st_mode) & 0o077]
        return loose

    def after_setup():
        cc = ledger_bodies(ctx, a)
        roles = {f["role"]: f for c in cc for f in c["files"]}
        return {"loose_modes": modes_ok(), "config_changed_entries": len(cc), "first_command": cc[0]["command"],
                "first_confirmed": cc[0]["confirmed"], "key_file_named": "key" in roles or "principal.pem" in
                {f["file"] for c in cc for f in c["files"]},
                "key_digest_recorded": any(f.get("role") == "key" and (f.get("new_sha256") or f.get("old_sha256"))
                                           for c in cc for f in c["files"]),
                "signed_constitution_digest": bool(cc[0]["constitution_hash"])}

    step("setup", ["setup", "--dir", a, "--answers", write_answers(ctx, "a")], facts=after_setup)
    if not pa.is_file():
        return out                       # nothing after this has anything to run on

    def snapshot():
        return {"proxy_sha": sha_file(pa), "cc": len(ledger_bodies(ctx, a))}

    base = snapshot()

    def unchanged():
        now = snapshot()
        return {"proxy_unchanged": now["proxy_sha"] == base["proxy_sha"], "ledger_unchanged": now["cc"] == base["cc"]}

    step("setup_dir_exists", ["setup", "--dir", a, "--answers", write_answers(ctx, "a")], facts=unchanged)
    step("setup_unknown_answer", ["setup", "--dir", work / "deploy_x", "--answers",
                                  write_answers(ctx, "x", colour="blue")],
         facts=lambda: {"dir_created": (work / "deploy_x").exists()})
    short = private_file(work / "pass_short", "short")
    step("setup_passphrase_short", ["setup", "--dir", work / "deploy_s", "--answers",
                                    write_answers(ctx, "s", key_passphrase_file=str(short))],
         facts=lambda: {"dir_created": (work / "deploy_s").exists()})
    wide = private_file(work / "pass_wide", PASSPHRASE, 0o644)
    step("setup_passphrase_readable", ["setup", "--dir", work / "deploy_w", "--answers",
                                       write_answers(ctx, "w", key_passphrase_file=str(wide))],
         facts=lambda: {"dir_created": (work / "deploy_w").exists()})

    step("set_weaker_refused", ["config", "set", "--config", pa, "on_agent_access", "warn"], facts=unchanged)
    step("set_weaker_no_terminal", ["config", "set", "--config", pa, "on_agent_access", "warn", "--confirm-weaker"],
         facts=unchanged)
    step("set_secret_on_command_line", ["config", "set", "--config", pa, "upstream.env.API_TOKEN", CANARY],
         facts=lambda: dict(unchanged(), canary_written=CANARY.encode() in tree_text(a)))
    step("set_unknown_setting", ["config", "set", "--config", pa, "ttl_secnds", "1"], facts=unchanged)
    step("set_not_settable", ["config", "set", "--config", pa, "ledger", str(work / "elsewhere")], facts=unchanged)
    step("set_signed_without_key", ["config", "set", "--config", pa, "tool_specs.lookup.irreversible", "true"],
         facts=unchanged)

    # a change that is neither weaker nor signed: recorded, undoable
    before = sha_file(pa)

    def last_cc():
        cc = ledger_bodies(ctx, a)
        return {"command": cc[-1]["command"], "settings": cc[-1]["settings"], "signed": cc[-1]["signed"],
                "weaker": cc[-1]["weaker"], "confirmed": cc[-1]["confirmed"], "entries": len(cc),
                "value_in_entry": "45" in json.dumps({k: v for k, v in cc[-1].items() if k not in ("files", "account")})}

    step("set_plain", ["config", "set", "--config", pa, "upstream.call_timeout_seconds", "45"], facts=last_cc)
    step("undo_plain", ["config", "undo", "--config", pa],
         facts=lambda: dict(last_cc(), restored=sha_file(pa) == before, prev_kept=(a / "proxy.yaml.prev").is_file()))
    step("set_plain_again", ["config", "set", "--config", pa, "upstream.call_timeout_seconds", "45"], facts=last_cc)
    with pa.open("a", encoding="utf-8") as f:           # someone edits the file by hand after the change
        f.write("# edited by hand after the change\n")
    base = snapshot()
    step("undo_after_hand_edit", ["config", "undo", "--config", pa], facts=unchanged)

    # a weaker change a human confirms, and a signed change a human confirms
    base = snapshot()
    weaker_args = ["config", "set", "--config", pa, "on_agent_access", "warn", "--confirm-weaker"]
    step("set_weaker_typed_no", weaker_args, answer="no", facts=unchanged)
    step("set_weaker_typed_yes", weaker_args, answer="yes", facts=last_cc)
    base = snapshot()
    rules_sha = sha_file(a / "hard_rules.yaml")
    signed_sha = sha_file(a / "constitution.signed.json")
    signed_args = ["config", "set", "--config", pa, "tool_specs.lookup.irreversible", "true", "--key",
                   a / "principal.pem", "--rules", a / "hard_rules.yaml"]
    step("set_signed_no_terminal", signed_args, facts=lambda: dict(
        unchanged(), rules_unchanged=sha_file(a / "hard_rules.yaml") == rules_sha,
        constitution_unchanged=sha_file(a / "constitution.signed.json") == signed_sha))
    step("set_signed_typed_no", signed_args, answer="no", facts=lambda: dict(
        unchanged(), constitution_unchanged=sha_file(a / "constitution.signed.json") == signed_sha))
    first_hash = ledger_bodies(ctx, a)[0]["constitution_hash"]
    step("set_signed_typed_yes", signed_args, answer="yes", facts=lambda: dict(
        last_cc(), constitution_changed=sha_file(a / "constitution.signed.json") != signed_sha,
        rules_changed=sha_file(a / "hard_rules.yaml") != rules_sha,
        new_hash_recorded=ledger_bodies(ctx, a)[-1]["constitution_hash"] not in (None, first_hash)))
    step("check_after_changes", ["config", "check", "--config", pa], facts=lambda: {})
    step("audit_after_changes", ["audit", "--ledger", a / "ledger", "--key", a / "principal.pem"],
         facts=lambda: {})

    # ---- deployment B: the principal key encrypted with a passphrase
    b = work / "deploy_b"
    pb = b / "proxy.yaml"
    pf = private_file(work / "principal.pass", PASSPHRASE)
    plain_head = b"-----BEGIN PRIVATE KEY-----"

    def key_state():
        return {"key_encrypted": not (b / "principal.pem").read_bytes().startswith(plain_head),
                "passphrase_file_set": "passphrase_file" in pb.read_text(encoding="utf-8")}

    step("setup_encrypted_key", ["setup", "--dir", b, "--answers", write_answers(ctx, "b", key_passphrase_file=str(pf))],
         facts=key_state)
    if not pb.is_file():
        return out
    # setup writes the settings the operator did not choose; the tools: block, which claims each tool's data
    # class and names its fact hooks, and the scan: block are the operator's own and go in by hand (docs/HOWTO.md).
    import yaml
    pb_text = pb.read_text(encoding="utf-8") + yaml.safe_dump({"tools": ctx["claims"], "scan": ctx["scan"]},
                                                                   sort_keys=False)
    pb.write_text(pb_text.replace("on_agent_access: refuse", "on_agent_access: warn"), encoding="utf-8")
    # The harness starts the proxy under its own account, which on_agent_access refuses by default (docs/CONNECTING.md).
    out["start_with_encrypted_key"] = proxy_start(ctx, pb)
    pb.write_text("".join(line for line in pb.read_text(encoding="utf-8").splitlines(keepends=True)
                          if "passphrase_file" not in line), encoding="utf-8")
    out["start_without_passphrase_file"] = proxy_start(ctx, pb)
    pb.write_text(pb_text.replace("on_agent_access: refuse", "on_agent_access: warn"), encoding="utf-8")
    os.chmod(pf, 0o644)
    out["start_passphrase_file_readable"] = proxy_start(ctx, pb)
    os.chmod(pf, 0o600)
    key_before = (b / "principal.pem").read_bytes()
    step("key_remove_no_terminal", ["config", "key-passphrase", "--config", pb, "--remove", "--confirm-weaker"],
         facts=lambda: dict(key_state(), key_unchanged=(b / "principal.pem").read_bytes() == key_before))
    step("key_remove_typed_yes", ["config", "key-passphrase", "--config", pb, "--remove", "--confirm-weaker"],
         answer="yes", facts=lambda: dict(key_state(), cc=ledger_bodies(ctx, b)[-1]["command"],
                                          weaker=bool(ledger_bodies(ctx, b)[-1]["weaker"]),
                                          confirmed=ledger_bodies(ctx, b)[-1]["confirmed"]))
    step("key_encrypt_no_terminal", ["config", "key-passphrase", "--config", pb, "--new-from", pf],
         facts=key_state)
    step("key_encrypt_typed_yes", ["config", "key-passphrase", "--config", pb, "--new-from", pf], answer="yes",
         facts=lambda: dict(key_state(), cc=ledger_bodies(ctx, b, passphrase_file=pf)[-1]["command"],
                            key_named=any(f.get("role") == "key"
                                          for f in ledger_bodies(ctx, b, passphrase_file=pf)[-1]["files"]),
                            key_digest_recorded=any(f.get("role") == "key" and (f.get("new_sha256") or f.get("old_sha256"))
                                                    for f in ledger_bodies(ctx, b, passphrase_file=pf)[-1]["files"])))
    step("check_encrypted_key", ["config", "check", "--config", pb], facts=key_state)

    # ---- deployment C: high_assurance keeps what it forbids forbidden
    c = work / "deploy_c"
    pc = c / "proxy.yaml"
    judges = answers(ctx)["judges"]
    judges[0]["maker"] = "harness-a"
    judges[1].update(maker="harness-local", local_weights=True)
    agent = dict(answers(ctx)["monitored_agent"])
    step("setup_high_assurance", ["setup", "--dir", c, "--answers",
                                  write_answers(ctx, "c", profile="high_assurance", judges=judges,
                                                monitored_agent=agent)],
         facts=lambda: {"proxy_written": pc.is_file()})
    if pc.is_file():
        base_c = (sha_file(pc), len(ledger_bodies(ctx, c)))
        step("high_assurance_weaker_typed_yes", ["config", "set", "--config", pc, "on_agent_access", "warn",
                                                 "--confirm-weaker"], answer="yes",
             facts=lambda: {"proxy_unchanged": sha_file(pc) == base_c[0],
                            "ledger_unchanged": len(ledger_bodies(ctx, c)) == base_c[1]})
    return out


def proxy_start(ctx, config: Path) -> dict:
    """`mcp-proxy` on a deployment's config with no input: it checks, says "serving" (or why not), and exits."""
    r = subprocess.run([sys.executable, "-m", "two_key", "mcp-proxy", "--config", str(config)], cwd=ctx["pkg"],  # nosec
                       capture_output=True, text=True, env=ctx["env"], timeout=120, stdin=subprocess.DEVNULL)
    ctx["log"]("cli", args=["mcp-proxy", str(config)], rc=r.returncode, stdout=r.stdout[-1000:],
               stderr=r.stderr[-3000:], tty=False)
    return {"rc": r.returncode, "stdout": r.stdout[-2000:], "stderr": r.stderr[-4000:], "facts": {}}

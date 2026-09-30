#!/usr/bin/env python3
"""Compact Kernel micro-benchmarks (offline; no network).

    python bench.py                 # full run, prints a Markdown table
    python bench.py --quick         # fewer iterations
    python bench.py --json out.json # also write raw results

Measures: Path A (Policy VM) eval, capability token issue/verify, the full
gateway check (invoke), ledger append with a signed head, signature
sign/verify for classic vs hybrid post-quantum suites, the full authorize
path with local test-double judges, simulated network-bound judges
(parallel vs sequential), and memory (peak RSS and tracemalloc peaks).

Numbers depend on the machine; PERFORMANCE.md records one run and its
environment. Real judge latency is dominated by the network and the model
provider and is NOT measured here.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import platform
import resource
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from compact_kernel import keys  # noqa: E402
from compact_kernel.action import normalize_action  # noqa: E402
from compact_kernel.capability import CapabilityIssuer, args_hash  # noqa: E402
from compact_kernel.constitution import build_document, sign_document  # noqa: E402
from compact_kernel.crypto import CryptoProvider, PrivateKeySet, openssl_fips_status  # noqa: E402
from compact_kernel.judges.base import Ballot, Judge  # noqa: E402
from compact_kernel.kernel import CompactKernel  # noqa: E402
from compact_kernel.ledger import PersonalLedger  # noqa: E402
from compact_kernel.quorum import QuorumPolicy, convene  # noqa: E402
from compact_kernel.testing import FixedJudge  # noqa: E402

RULES = json.loads((Path(__file__).resolve().parent / "examples" / "hard_rules.json").read_text())["hard_rules"]
TEXT = "I am the principal. The agent is my fiduciary. No wires. No medical data off-device."
PAY = {"tool": "pay_bill", "amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}
PAY_ARGS = {"payee": "power-co.example", "amount": 42.5, "invoice": "INV-7"}
PAY_FIELDS = {"amount_usd": 42.5, "counterparty": "power-co.example", "data_class": "financial"}
SUITES = ["ed25519", "ecdsa-p384", "hybrid-mldsa65-ed25519", "hybrid-mldsa65-p384"]


def rss_mb() -> float:
    """Peak resident set size of this process in MiB.

    Uses VmHWM from /proc/self/status (per address space; reset by exec). Falls back to
    getrusage ru_maxrss, which on Linux is inherited across fork+exec and so overstates
    a child's peak when the parent was larger."""
    try:
        for line in open("/proc/self/status"):
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0  # Linux: KiB


def timeit(fn, n: int, warmup: int = 20) -> dict:
    for _ in range(min(warmup, n)):
        fn()
    samples = []
    pc = time.perf_counter_ns
    gc_was = gc.isenabled()
    gc.disable()
    try:
        for _ in range(n):
            t0 = pc()
            fn()
            samples.append(pc() - t0)
    finally:
        if gc_was:
            gc.enable()
    samples.sort()
    return {"n": n, "median_us": samples[len(samples) // 2] / 1000, "p99_us": samples[int(len(samples) * 0.99) - 1] / 1000
            if len(samples) >= 100 else samples[-1] / 1000, "mean_us": statistics.fmean(samples) / 1000}


def traced_peak_kib(fn) -> float:
    gc.collect()
    tracemalloc.start()
    tracemalloc.reset_peak()
    try:
        fn()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak / 1024.0


class SleepJudge(Judge):
    """Simulated network-bound judge (sleeps; no network)."""
    is_test_double = True

    def __init__(self, jid, ms):
        self.judge_id, self.provider, self.ms = jid, f"sim-{jid}", ms

    def score(self, c, a, p):
        time.sleep(self.ms / 1000)
        return Ballot(self.judge_id, self.provider, "yes", 0.9, "simulated")


def rss_child(suite: str, n: int) -> int:
    """Run in a fresh process: kernel + n authorize/invoke cycles for one suite; print peak RSS (MiB)."""
    base = rss_mb()
    with tempfile.TemporaryDirectory() as dd:
        ks = PrivateKeySet.generate(suite) if suite != "ed25519" else keys.generate_private_key()
        pub = ks.public() if suite != "ed25519" else ks.public_key()
        env = sign_document(build_document("did:ck:bench", TEXT, RULES), ks)
        kk = CompactKernel(env, pub, Path(dd) / "k.jsonl",
                           [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), FixedJudge("c", "yes", "p3")],
                           ledger_signing_key=ks, allow_test_doubles=True, ledger_fsync=False)
        gw = kk.gateway(tools={"pay_bill": lambda **a: "paid"})
        for _ in range(n):
            dd_ = kk.authorize(PAY, "Pay the electric bill.", PAY_ARGS)
            gw.invoke(dd_.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
        print(json.dumps({"suite": suite, "imports_rss_mib": round(base, 1), "peak_rss_mib": round(rss_mb(), 1),
                          "ledger_entries": len(kk.ledger.entries)}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--json")
    ap.add_argument("--rss-child", help=argparse.SUPPRESS)
    ap.add_argument("--rss-n", type=int, default=1000, help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.rss_child:
        return rss_child(args.rss_child, args.rss_n)
    N = 300 if args.quick else 2000
    NS = 100 if args.quick else 400     # slower signature ops
    rows: list[tuple[str, str, dict]] = []
    mem: list[tuple[str, str]] = []

    def add(group, name, r):
        rows.append((group, name, r))
        print(f"  {group:<14} {name:<58} median {r['median_us']:>10.2f} us   p99 {r['p99_us']:>10.2f} us",
              file=sys.stderr)

    provider = CryptoProvider()
    t0 = time.perf_counter()
    provider.ensure_selftest()
    selftest_ms = (time.perf_counter() - t0) * 1000
    pq = provider.pq_backend()
    env_info = {
        "python": sys.version.split()[0], "platform": platform.platform(),
        "cpu": next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "?")
        if os.path.exists("/proc/cpuinfo") else platform.processor(),
        "cpus": os.cpu_count(), "openssl": openssl_fips_status(),
        "pq_backend": None if pq is None else pq.describe(), "selftest_ms": round(selftest_ms, 2),
    }
    mem.append(("baseline after imports + self-test (peak RSS)", f"{rss_mb():.1f} MiB"))
    suites = [s for s in SUITES if pq is not None or "mldsa" not in s]
    tmp = tempfile.TemporaryDirectory()
    d = Path(tmp.name)

    # ---- Path A ----------------------------------------------------------------
    ks0 = keys.generate_private_key()
    env0 = sign_document(build_document("did:ck:bench", TEXT, RULES), ks0)
    k = CompactKernel(env0, ks0.public_key(), d / "a.jsonl", [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")],
                      ledger_signing_key=ks0, allow_test_doubles=True, ledger_fsync=False)
    act = normalize_action(PAY)
    add("Path A", f"PolicyVM.eval ({len(k.bytecode)} instr, {len(RULES)} rules, allow)", timeit(lambda: k.vm.eval(act), N * 5))
    bad = normalize_action(dict(PAY, amount_usd=500))
    add("Path A", "PolicyVM.eval (deny: spend-cap)", timeit(lambda: k.vm.eval(bad), N * 5))
    add("Path A", "normalize_action (input validation)", timeit(lambda: normalize_action(PAY), N * 5))

    # ---- tokens ------------------------------------------------------------------
    issuers = [("ck1 (HMAC-SHA-256)", CapabilityIssuer(os.urandom(32), mode="ck1")),
               ("ck1-hs384 (HMAC-SHA-384)", CapabilityIssuer(os.urandom(48), mode="ck1-hs384"))]
    if pq is not None:
        issuers.append(("ck1-sig (hybrid ML-DSA-65+Ed25519)",
                        CapabilityIssuer(mode="ck1-sig", signing_key=PrivateKeySet.generate("hybrid-mldsa65-ed25519"))))
    for name, iss in issuers:
        issue = lambda iss=iss: iss.issue(principal="did:ck:bench", tool="pay_bill", scope=PAY_FIELDS,  # noqa: E731
                                          args_digest="0" * 64, ledger_root="0" * 64, constitution_digest="0" * 64,
                                          ttl_seconds=30)
        n = NS if "sig" in name else N
        add("Token", f"issue {name}", timeit(issue, n))
        tok = issue().token
        add("Token", f"verify {name} [{len(tok)} B token]", timeit(lambda iss=iss, tok=tok: iss.verify(tok), n))
    add("Token", "args_hash sha256", timeit(lambda: args_hash("pay_bill", PAY_ARGS), N))
    add("Token", "args_hash sha384", timeit(lambda: args_hash("pay_bill", PAY_ARGS, "sha384"), N))

    # ---- signatures ----------------------------------------------------------------
    msg = b"x" * 256
    for s in suites:
        ks = PrivateKeySet.generate(s)
        pub = ks.public()
        sig = ks.sign(msg)
        add("Signature", f"sign   {s}", timeit(lambda ks=ks: ks.sign(msg), NS))
        add("Signature", f"verify {s} [{len(sig)} B b64 sig]", timeit(lambda pub=pub, sig=sig: pub.verify(msg, sig), NS))
        add("Signature", f"keygen {s}", timeit(lambda s=s: PrivateKeySet.generate(s), max(20, NS // 4), warmup=2))
        mem.append((f"key set object {s} (tracemalloc, Python-side only)",
                    f"{traced_peak_kib(lambda s=s: PrivateKeySet.generate(s)):.1f} KiB"))

    # ---- ledger append with signed head --------------------------------------------------
    for s in suites:
        for fsync in (False, True):
            ks = PrivateKeySet.generate(s) if s != "ed25519" else keys.generate_private_key()
            L = PersonalLedger(d / f"l-{s}-{fsync}.jsonl", signing_key=ks, auto_sign_every=1, fsync=fsync)
            n = NS // 2 if fsync else NS
            add("Ledger", f"append + signed head, {s}, fsync={'on' if fsync else 'off'}",
                timeit(lambda L=L: L.append("event", {"i": 1, "note": "bench"}), n, warmup=5))
    for fsync in (False, True):
        L = PersonalLedger(d / f"l-nosign-{fsync}.jsonl", signing_key=keys.generate_private_key(), auto_sign_every=0,
                           fsync=fsync)
        add("Ledger", f"append only (head signed later by checkpoint), fsync={'on' if fsync else 'off'}",
            timeit(lambda L=L: L.append("event", {"i": 1, "note": "bench"}), N // (4 if fsync else 1), warmup=5))
    big = PersonalLedger(d / "big.jsonl", fsync=False)
    for i in range(10_000):
        big.append("e", {"i": i})
    add("Ledger", "merkle_root() on a 10,000-entry ledger (incremental)", timeit(big.merkle_root, N))
    mem.append(("10,000-entry ledger in memory (tracemalloc)",
                f"{traced_peak_kib(lambda: PersonalLedger(d / 'big.jsonl')) / 1024:.2f} MiB"))

    # ---- full gateway check + full authorize --------------------------------------------
    for s in suites:
        for fsync in (False, True):
            ks = PrivateKeySet.generate(s) if s != "ed25519" else keys.generate_private_key()
            env = sign_document(build_document("did:ck:bench", TEXT, RULES), ks)
            pub = ks.public() if s != "ed25519" else ks.public_key()
            kk = CompactKernel(env, pub, d / f"k-{s}-{fsync}.jsonl",
                               [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), FixedJudge("c", "yes", "p3")],
                               ledger_signing_key=ks, allow_test_doubles=True, ledger_fsync=fsync)
            gw = kk.gateway(tools={"pay_bill": lambda **a: "paid"})
            n = NS // 4 if fsync else NS // 2
            decs = [kk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
            assert all(x.allowed for x in decs)
            it = iter(decs)
            fs = "on" if fsync else "off"
            add("Gateway", f"invoke (all checks + redeem + tool + signed head), {s}, fsync={fs}",
                timeit(lambda: gw.invoke(next(it).capability, "pay_bill", PAY_ARGS, PAY_FIELDS), n, warmup=5))
            if s == "ed25519" and not fsync:
                gw0 = kk.gateway(tools={"pay_bill": lambda **a: "paid"}, checkpoint_every=0)
                decs = [kk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
                it0 = iter(decs)
                add("Gateway", "invoke, head signing deferred (checkpoint_every=0), fsync=off",
                    timeit(lambda: gw0.invoke(next(it0).capability, "pay_bill", PAY_ARGS, PAY_FIELDS), n, warmup=5))
                kk.ledger.checkpoint()
                decs = [kk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
                it1 = iter(decs)
                a_ = act

                def checks_only():
                    tok = next(it1).capability
                    p_ = kk.issuer.verify(tok)
                    args_hash("pay_bill", PAY_ARGS) == p_["args_hash"] and normalize_action(
                        {"tool": "pay_bill", **PAY_FIELDS}) and kk.ledger.index_of(p_["ledger_root"])
                add("Gateway", "checks only: token verify + args hash + field normalize + root lookup",
                    timeit(checks_only, n, warmup=5))
            add("Authorize", f"authorize (A + B[3 local judges] + token + ledger), {s}, fsync={fs}",
                timeit(lambda: kk.authorize(PAY, "Pay the electric bill.", PAY_ARGS), n, warmup=5))
            if not fsync:
                mem.append((f"kernel construction incl. self-test, {s} (tracemalloc)",
                            f"{traced_peak_kib(lambda: CompactKernel(env, pub, d / f'm-{s}.jsonl', [FixedJudge('a', 'yes')], ledger_signing_key=ks, allow_test_doubles=True, quorum_policy=QuorumPolicy(required_yes=1), crypto=CryptoProvider())):.1f} KiB"))

    # ---- judge fan-out (simulated network latency; not real provider numbers) ------------
    for ms in (50, 200):
        js = [SleepJudge(f"j{i}", ms) for i in range(3)]
        par = timeit(lambda: convene(js, TEXT, act, "p", QuorumPolicy(required_yes=3)), 10, warmup=1)
        seq = timeit(lambda: convene(js, TEXT, act, "p", QuorumPolicy(required_yes=3, parallel=False,
                                                                       timeout_seconds=None)), 5, warmup=1)
        add("Judges (sim)", f"3 judges x {ms} ms simulated latency, parallel", par)
        add("Judges (sim)", f"3 judges x {ms} ms simulated latency, sequential", seq)
    js = [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), SleepJudge("hung", 5000)]
    add("Judges (sim)", "3 judges, one hung (5 s), timeout_seconds=0.25",
        timeit(lambda: convene(js, TEXT, act, "p", QuorumPolicy(required_yes=2, timeout_seconds=0.25)), 3, warmup=0))

    mem.append(("process peak RSS at end of this benchmark run (all suites, 10k-entry ledger loaded)",
                f"{rss_mb():.1f} MiB"))
    import subprocess
    n_child = 200 if args.quick else 1000
    for s in suites:
        r = json.loads(subprocess.run([sys.executable, __file__, "--rss-child", s, "--rss-n", str(n_child)],
                                      capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1])
        mem.append((f"fresh process, {s}: after imports -> peak after {n_child} authorize+invoke cycles "
                    f"({r['ledger_entries']} ledger entries)", f"{r['imports_rss_mib']} -> {r['peak_rss_mib']} MiB"))
    tmp.cleanup()

    out = ["| Group | Operation | Median | p99 |", "|---|---|---:|---:|"]

    def fmt(us):
        return f"{us / 1000:.2f} ms" if us >= 1000 else f"{us:.1f} µs" if us >= 10 else f"{us:.2f} µs"
    for g, name, r in rows:
        out.append(f"| {g} | {name} | {fmt(r['median_us'])} | {fmt(r['p99_us'])} |")
    out += ["", "| Memory | Value |", "|---|---:|"] + [f"| {a} | {b} |" for a, b in mem]
    print("\n".join(out))
    print("\nEnvironment: " + json.dumps(env_info, default=str))
    if args.json:
        Path(args.json).write_text(json.dumps({"env": env_info, "rows": rows, "memory": mem}, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

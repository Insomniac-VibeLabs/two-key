#!/usr/bin/env python3
"""Two-Key micro-benchmarks (offline; no network).

    python bench.py                 # full run, prints a Markdown table
    python bench.py --quick         # fewer iterations
    python bench.py --json out.json # also write raw results

Measures: Path A (Policy VM) eval, capability token issue/verify, the full
gateway check (invoke), ledger append with a signed head, signature
sign/verify for classic vs hybrid post-quantum suites, the full authorize
path with local test-double judges, simulated network-bound judges
(parallel vs sequential), and memory (peak RSS and tracemalloc peaks).
Also the PRIOR_ART.md §4 additions: Merkle consistency and inclusion
proofs, the gateway's ledger-root binding checks (view refresh, ancestor
proof, hash and revocation lookups) on short and 10,000-entry ledgers, and
load-time constitution compilation (both paths plus hashes).

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

from two_key import keys  # noqa: E402
from two_key.action import normalize_action  # noqa: E402
from two_key.capability import CapabilityIssuer, args_hash  # noqa: E402
from two_key.constitution import build_document, sign_document, verify_signed  # noqa: E402
from two_key.crypto import CryptoProvider, PrivateKeySet, openssl_fips_status  # noqa: E402
from two_key.judges.base import Ballot, Judge  # noqa: E402
from two_key.core import TwoKey  # noqa: E402
from two_key.ledger import PersonalLedger  # noqa: E402
from two_key.quorum import QuorumPolicy, convene  # noqa: E402
from two_key.testing import FixedJudge  # noqa: E402

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
    """Run in a fresh process: TwoKey + n authorize/invoke cycles for one suite; print peak RSS (MiB)."""
    base = rss_mb()
    with tempfile.TemporaryDirectory() as dd:
        ks = PrivateKeySet.generate(suite) if suite != "ed25519" else keys.generate_private_key()
        pub = ks.public() if suite != "ed25519" else ks.public_key()
        env = sign_document(build_document("did:twokey:bench", TEXT, RULES), ks)
        tk = TwoKey(env, pub, Path(dd) / "k.jsonl",
                           [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), FixedJudge("c", "yes", "p3")],
                           ledger_signing_key=ks, allow_test_doubles=True, ledger_fsync=False)
        gw = tk.gateway(tools={"pay_bill": lambda **a: "paid"})
        for _ in range(n):
            dd_ = tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS)
            gw.invoke(dd_.capability, "pay_bill", PAY_ARGS, PAY_FIELDS)
        print(json.dumps({"suite": suite, "imports_rss_mib": round(base, 1), "peak_rss_mib": round(rss_mb(), 1),
                          "ledger_entries": len(tk.ledger.entries)}))
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
    env0 = sign_document(build_document("did:twokey:bench", TEXT, RULES), ks0)
    tk = TwoKey(env0, ks0.public_key(), d / "a.jsonl", [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2")],
                      ledger_signing_key=ks0, allow_test_doubles=True, ledger_fsync=False)
    act = normalize_action(PAY)
    add("Path A", f"PolicyVM.eval ({len(tk.bytecode)} instr, {len(RULES)} rules, allow)", timeit(lambda: tk.vm.eval(act), N * 5))
    bad = normalize_action(dict(PAY, amount_usd=500))
    add("Path A", "PolicyVM.eval (deny: spend-cap)", timeit(lambda: tk.vm.eval(bad), N * 5))
    add("Path A", "normalize_action (input validation)", timeit(lambda: normalize_action(PAY), N * 5))

    # ---- tokens ------------------------------------------------------------------
    issuers = [("tk1 (HMAC-SHA-256)", CapabilityIssuer(os.urandom(32), mode="tk1")),
               ("tk1-hs384 (HMAC-SHA-384)", CapabilityIssuer(os.urandom(48), mode="tk1-hs384"))]
    if pq is not None:
        issuers.append(("tk1-sig (hybrid ML-DSA-65+Ed25519)",
                        CapabilityIssuer(mode="tk1-sig", signing_key=PrivateKeySet.generate("hybrid-mldsa65-ed25519"))))
    for name, iss in issuers:
        issue = lambda iss=iss: iss.issue(principal="did:twokey:bench", tool="pay_bill", scope=PAY_FIELDS,  # noqa: E731
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
    bench_key = keys.generate_private_key()
    big = PersonalLedger(d / "big.jsonl", signing_key=bench_key, auto_sign_every=0, fsync=False)
    for i in range(10_000):
        big.append("e", {"i": i})
    add("Ledger", "merkle_root() on a 10,000-entry ledger (incremental)", timeit(big.merkle_root, N))
    if hasattr(big, "consistency_proof"):  # §4 (i) additions (absent in older revisions)
        import random
        from two_key import merkle as _mk
        rnd = random.Random(1)
        h = big.hash_fn()
        new_root = big.root_bytes()

        def cons_far():
            m = rnd.randrange(1, 10_000)
            return _mk.verify_consistency(m, 10_000, big.root_bytes(m), new_root, big.consistency_path(m), h)
        add("Ledger", "consistency proof + verify, random old size -> 10,000 entries", timeit(cons_far, N))
        add("Ledger", "consistency proof + verify, 9,994 -> 10,000 (typical gateway view refresh)",
            timeit(lambda: _mk.verify_consistency(9_994, 10_000, big.root_bytes(9_994), new_root,
                                                  big.consistency_path(9_994), h), N))
        add("Ledger", "merkle_root(size) for a historical size, 10,000 entries",
            timeit(lambda: big.root_bytes(rnd.randrange(1, 10_000)), N))
    add("Ledger", "inclusion_proof() on a 10,000-entry ledger", timeit(lambda: big.inclusion_proof(4321), N // 10))
    mem.append(("10,000-entry ledger in memory (tracemalloc)",
                f"{traced_peak_kib(lambda: PersonalLedger(d / 'big.jsonl', signing_key=bench_key, auto_sign_every=0)) / 1024:.2f} MiB"))

    # ---- full gateway check + full authorize --------------------------------------------
    for s in suites:
        for fsync in (False, True):
            ks = PrivateKeySet.generate(s) if s != "ed25519" else keys.generate_private_key()
            env = sign_document(build_document("did:twokey:bench", TEXT, RULES), ks)
            pub = ks.public() if s != "ed25519" else ks.public_key()
            tk = TwoKey(env, pub, d / f"k-{s}-{fsync}.jsonl",
                               [FixedJudge("a", "yes", "p1"), FixedJudge("b", "yes", "p2"), FixedJudge("c", "yes", "p3")],
                               ledger_signing_key=ks, allow_test_doubles=True, ledger_fsync=fsync)
            gw = tk.gateway(tools={"pay_bill": lambda **a: "paid"})
            n = NS // 4 if fsync else NS // 2
            decs = [tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
            assert all(x.allowed for x in decs)
            it = iter(decs)
            fs = "on" if fsync else "off"
            add("Gateway", f"invoke (all checks + redeem + tool + signed head), {s}, fsync={fs}",
                timeit(lambda: gw.invoke(next(it).capability, "pay_bill", PAY_ARGS, PAY_FIELDS), n, warmup=5))
            if s == "ed25519" and not fsync:
                gw0 = tk.gateway(tools={"pay_bill": lambda **a: "paid"}, checkpoint_every=0)
                decs = [tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
                it0 = iter(decs)
                add("Gateway", "invoke, head signing deferred (checkpoint_every=0), fsync=off",
                    timeit(lambda: gw0.invoke(next(it0).capability, "pay_bill", PAY_ARGS, PAY_FIELDS), n, warmup=5))
                tk.ledger.checkpoint()
                decs = [tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
                it1 = iter(decs)
                a_ = act

                def checks_only():
                    tok = next(it1).capability
                    p_ = tk.issuer.verify(tok)
                    args_hash("pay_bill", PAY_ARGS) == p_["args_hash"] and normalize_action(
                        {"tool": "pay_bill", **PAY_FIELDS}) and tk.ledger.index_of(p_["ledger_root"])
                add("Gateway", "checks only: token verify + args hash + field normalize + root lookup",
                    timeit(checks_only, n, warmup=5))
                if hasattr(gw0, "_check_ledger_binding"):
                    decs = [tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
                    it2 = iter(decs)

                    def binding_only():
                        # each token is newer than the view by one decision (8 entries), as in real use
                        p_ = tk.issuer.verify(next(it2).capability)
                        assert gw0._view_intact() and gw0._check_ledger_binding(p_)[0] is None
                    add("Gateway", "§4 (i) binding checks only: token verify + view check + 1 consistency proof "
                        "+ hash/revocation lookups", timeit(binding_only, n, warmup=5))
                    tk.ledger.checkpoint()
            add("Authorize", f"authorize (A + B[3 local judges] + token + ledger), {s}, fsync={fs}",
                timeit(lambda: tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS), n, warmup=5))
            if s == "ed25519" and not fsync:
                for _ in range(10_000):  # long ledger: the §4 (i) proofs are O(log^2 n)
                    tk.ledger.append("filler", {"i": 1})
                tk.ledger.checkpoint()
                gwl = tk.gateway(tools={"pay_bill": lambda **a: "paid"})
                decs = [tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS) for _ in range(n + 5)]
                itl = iter(decs)
                add("Gateway", f"invoke on a ledger with >10,000 entries ({len(tk.ledger.entries)}), {s}, fsync=off",
                    timeit(lambda: gwl.invoke(next(itl).capability, "pay_bill", PAY_ARGS, PAY_FIELDS), n, warmup=5))
                add("Authorize", f"authorize on a ledger with >10,000 entries, {s}, fsync=off",
                    timeit(lambda: tk.authorize(PAY, "Pay the electric bill.", PAY_ARGS), n, warmup=5))
            if not fsync:
                mem.append((f"TwoKey construction incl. self-test, {s} (tracemalloc)",
                            f"{traced_peak_kib(lambda: TwoKey(env, pub, d / f'm-{s}.jsonl', [FixedJudge('a', 'yes')], ledger_signing_key=ks, allow_test_doubles=True, quorum_policy=QuorumPolicy(required_yes=1), crypto=CryptoProvider())):.1f} KiB"))

    # ---- constitution load (not on the hot path) -------------------------------------------
    try:
        from two_key.compiler import compile_both
        from two_key.constitution import build_source_document
        src = (Path(__file__).resolve().parent / "examples" / "constitution_single_source.md").read_text()
        env2 = sign_document(build_source_document("did:twokey:bench", src), ks0)
        add("Constitution", "verify_signed + split (single-source /2 document, Ed25519)",
            timeit(lambda: verify_signed(env2, ks0.public_key()), N // 4))
        c2 = verify_signed(env2, ks0.public_key())
        add("Constitution", "compile_both: bytecode + static check + both hashes (sha256)",
            timeit(lambda: compile_both(c2), N // 4))
    except ImportError:
        pass

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

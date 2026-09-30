# Performance and resource use

Measured on 2026-09-30 (about 05:10 MDT) with `bench.py` at the repository
root. The numbers below come from one run on one machine; rerun the script on
your own hardware before relying on them.

```bash
python bench.py            # full run (about 30 s); prints the tables below
python bench.py --quick    # fewer iterations
python bench.py --json results.json
```

**Environment.** Shared cloud VM, 8 vCPU "Intel(R) Xeon(R) Processor", 16 GB
RAM, Linux 6.12 (x86_64), overlay filesystem (so the fsync figures reflect
this VM's storage, not a laptop SSD). Python 3.13.5; pyca `cryptography`
50.0.1 with bundled OpenSSL 4.0.2 (the ML-DSA backend); CPython `hashlib` on
system OpenSSL 3.5.7. No FIPS provider was active. Judges were local test
doubles, and **no network was used**. Each figure is the median (and p99) of
individual timed calls after warm-up, with the garbage collector paused
during timing.

## Summary

| What | Classic (Ed25519) | Hybrid PQ (ML-DSA-65 + Ed25519) | Notes |
|---|---:|---:|---|
| Path A policy eval (6 rules, 32 instructions) | 12.2 µs (deny: 7.2 µs) | same | Pure Python VM; no crypto |
| Token issue / verify (HMAC) | 9.9 / 8.2 µs (`ck1`) | 11.0 / 9.5 µs (`ck1-hs384`) | HMAC key schedule computed once per issuer |
| Token issue / verify, signed (`ck1-sig`) | n/a | 678 / 293 µs | Optional mode; 6.8 KB token |
| Gateway: security checks only | 18.1 µs | ≈ same (+HMAC-SHA-384) | token verify + args hash + field normalization + ledger-root lookup |
| Gateway `invoke`, full (checks + redeem entry + tool + signed head), fsync off / on | 271 µs / 631 µs | 1.11 ms / 1.99 ms | The signed head and file I/O dominate |
| Gateway `invoke` with head signing deferred (`checkpoint_every=0`) | 123 µs | n/a (no signature on the call path) | Caller or timer runs `ledger.checkpoint()` |
| Ledger append + signed head, fsync off / on | 140 µs / 341 µs | 830 µs / 1.25 ms | per append (`auto_sign_every=1`) |
| Ledger append only (head signed at next checkpoint), fsync off / on | 27 µs / 106 µs | same | Kernel default: one head per decision |
| Sign / verify | 30 / 93 µs | 640 µs / 254 µs | Hybrid signature is 6.1 KB (base64) |
| Sign / verify, P-384 variants | 150 / 324 µs (ECDSA P-384) | 723 / 473 µs (ML-DSA-65 + P-384) | |
| Full `authorize` (A + B with 3 local judges + token + 8 ledger entries + 1 signed head), fsync off / on | 1.05 ms / 1.87 ms | 2.00 ms / 3.12 ms | Excludes real judge latency (see below) |
| Crypto self-test at start-up | 8.0 ms (incl. ML-DSA PCT) | same | Once per provider |
| Peak RSS, fresh process, 1000 authorize+invoke cycles (8,001 ledger entries) | 42.8 MiB | 43.3 MiB | 32.9 MiB after imports; the growth is the in-memory ledger |

## Hot-path properties (and how they are enforced)

* **Path A is in microseconds**: 7–12 µs per evaluation on this machine.
* **Key parsing is cached.** Public key sets are parsed once
  (`public_keyset_from_encoded` is LRU-cached; the kernel keeps the parsed
  trusted key). Token issuers compute the HMAC key schedule once and copy it
  per call. Test: `ClassicSuites.test_public_key_parsing_is_cached`.
* **No network in the kernel/gateway path.** Test
  `NoNetworkInGatewayPath` replaces `socket.socket`, `create_connection`, and
  `getaddrinfo` with functions that fail, then runs a full authorize and
  invoke.
* **Signed-head updates are batched and configurable.** Signing the head
  is the most expensive local step (Ed25519 about 30 µs; hybrid about
  0.65 ms, with a p99 of about 2.5–3 ms because ML-DSA signing uses rejection
  sampling). Options:
  * kernel `head_signing="decision"` (default): one signature covers every
    ledger entry of a decision (8 entries for an allowed action). A decision
    whose checkpoint fails is denied, so no token is released without a
    signed head;
  * kernel `head_signing="append"`: sign after every append;
  * ledger `auto_sign_every=N` (1 by default for direct use; 0 means only on
    `checkpoint()`);
  * gateway `checkpoint_every=N` (1 by default; 0 means the caller
    checkpoints, e.g. on a timer). Until the next checkpoint, `verify` reports
    `size_mismatch` for the unsigned tail.
* **Incremental Merkle root.** `merkle.MerkleFrontier` keeps the root in
  O(log n): 2 µs on a 10,000-entry ledger. The previous implementation
  rebuilt the whole tree on every signed head (O(n) per append).
* **fsync is configurable** (`PersonalLedger(fsync=…)`,
  `CompactKernel(ledger_fsync=…)`). The default is on, for durability. On
  this VM each fsync'd write costs roughly 0.1–0.2 ms extra (append only:
  27 µs → 106 µs).

## Path B judges: network-bound latency (separate from the numbers above)

Real judges call remote or local model APIs. Their latency is set by the
network, the provider, the model, prompt length (the full constitution is
sent), output length, and load. **It was not measured**: no live API call
was made in this work. Expect it to dominate end-to-end latency by orders of
magnitude. A single hosted-model call typically takes hundreds of
milliseconds to several seconds, and a local model (Ollama) depends on your
hardware. Measure your own providers before setting `timeout_seconds`.

How the kernel bounds it:

* Judges run **in parallel** (one daemon thread per judge), so Path B takes
  about as long as the *slowest* judge, not the sum. Simulated with sleeping
  judges (no network): 3 × 50 ms took 51.0 ms parallel vs 150.4 ms
  sequential; 3 × 200 ms took 201.1 ms vs 600.6 ms.
* An **overall deadline** (`QuorumPolicy.timeout_seconds`, default 45 s)
  caps Path B. A judge that has not answered is recorded as an abstention
  (`error="timeout…"`), which never counts as "yes". Simulated: one judge
  hung for 5 s with `timeout_seconds=0.25`, and the quorum returned in
  250.2 ms.
* Each LLM judge also has its own HTTP timeout (`timeout`, default 30 s).
  A hung judge's thread ends when that timeout fires; being a daemon thread,
  it does not block process exit.
* With the default `short_circuit_path_b=True`, a Path A deny returns
  without calling any judge, in microseconds plus the ledger write.

End-to-end estimate: `authorize` ≈ local cost from the table (about 1–3 ms)
+ the slowest judge's latency, capped at `timeout_seconds`.

## Without a PQ library

Under the system interpreter (`cryptography` 43.0.0, no ML-DSA),
`bench.py --quick` runs the classic rows only. The figures matched the
table above within noise (e.g. Path A 11.4 µs, `ck1` verify 8.1 µs, gateway
invoke with Ed25519 head 266 µs). Hybrid suites are unavailable there and
raise `PQUnavailableError`, as designed.

## Full results (this run)

| Group | Operation | Median | p99 |
|---|---|---:|---:|
| Path A | PolicyVM.eval (32 instr, 6 rules, allow) | 12.2 µs | 23.4 µs |
| Path A | PolicyVM.eval (deny: spend-cap) | 7.18 µs | 9.71 µs |
| Path A | normalize_action (input validation) | 3.33 µs | 5.57 µs |
| Token | issue ck1 (HMAC-SHA-256) | 9.90 µs | 14.2 µs |
| Token | verify ck1 (HMAC-SHA-256) [704 B token] | 8.18 µs | 11.5 µs |
| Token | issue ck1-hs384 (HMAC-SHA-384) | 11.0 µs | 16.5 µs |
| Token | verify ck1-hs384 (HMAC-SHA-384) [731 B token] | 9.46 µs | 12.2 µs |
| Token | issue ck1-sig (hybrid ML-DSA-65+Ed25519) | 678.2 µs | 2.83 ms |
| Token | verify ck1-sig (hybrid ML-DSA-65+Ed25519) [6763 B token] | 292.8 µs | 350.8 µs |
| Token | args_hash sha256 | 3.82 µs | 4.53 µs |
| Token | args_hash sha384 | 4.42 µs | 5.51 µs |
| Signature | sign   ed25519 | 30.0 µs | 35.5 µs |
| Signature | verify ed25519 [88 B b64 sig] | 93.1 µs | 114.6 µs |
| Signature | keygen ed25519 | 32.2 µs | 34.9 µs |
| Signature | sign   ecdsa-p384 | 149.6 µs | 178.0 µs |
| Signature | verify ecdsa-p384 [248 B b64 sig] | 323.6 µs | 391.8 µs |
| Signature | keygen ecdsa-p384 | 127.8 µs | 153.9 µs |
| Signature | sign   hybrid-mldsa65-ed25519 | 640.3 µs | 2.46 ms |
| Signature | verify hybrid-mldsa65-ed25519 [6100 B b64 sig] | 253.6 µs | 408.6 µs |
| Signature | keygen hybrid-mldsa65-ed25519 | 188.8 µs | 309.3 µs |
| Signature | sign   hybrid-mldsa65-p384 | 723.4 µs | 2.78 ms |
| Signature | verify hybrid-mldsa65-p384 [6172 B b64 sig] | 473.4 µs | 558.2 µs |
| Signature | keygen hybrid-mldsa65-p384 | 281.7 µs | 348.8 µs |
| Ledger | append + signed head, ed25519, fsync=off | 140.4 µs | 323.1 µs |
| Ledger | append + signed head, ed25519, fsync=on | 341.1 µs | 1.02 ms |
| Ledger | append + signed head, ecdsa-p384, fsync=off | 277.9 µs | 419.8 µs |
| Ledger | append + signed head, ecdsa-p384, fsync=on | 528.6 µs | 1.92 ms |
| Ledger | append + signed head, hybrid-mldsa65-ed25519, fsync=off | 830.1 µs | 2.96 ms |
| Ledger | append + signed head, hybrid-mldsa65-ed25519, fsync=on | 1.25 ms | 3.27 ms |
| Ledger | append + signed head, hybrid-mldsa65-p384, fsync=off | 1.04 ms | 3.41 ms |
| Ledger | append + signed head, hybrid-mldsa65-p384, fsync=on | 1.50 ms | 4.86 ms |
| Ledger | append only (head signed later by checkpoint), fsync=off | 26.9 µs | 49.7 µs |
| Ledger | append only (head signed later by checkpoint), fsync=on | 106.4 µs | 347.4 µs |
| Ledger | merkle_root() on a 10,000-entry ledger (incremental) | 1.96 µs | 3.26 µs |
| Gateway | invoke (all checks + redeem + tool + signed head), ed25519, fsync=off | 270.8 µs | 526.2 µs |
| Gateway | invoke, head signing deferred (checkpoint_every=0), fsync=off | 123.1 µs | 281.8 µs |
| Gateway | checks only: token verify + args hash + field normalize + root lookup | 18.1 µs | 25.8 µs |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ed25519, fsync=off | 1.05 ms | 1.71 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), ed25519, fsync=on | 630.9 µs | 1.26 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ed25519, fsync=on | 1.87 ms | 4.29 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), ecdsa-p384, fsync=off | 455.7 µs | 815.0 µs |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ecdsa-p384, fsync=off | 1.28 ms | 1.88 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), ecdsa-p384, fsync=on | 887.2 µs | 1.55 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ecdsa-p384, fsync=on | 2.28 ms | 3.99 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-ed25519, fsync=off | 1.11 ms | 3.59 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-ed25519, fsync=off | 2.00 ms | 4.47 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-ed25519, fsync=on | 1.99 ms | 4.32 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-ed25519, fsync=on | 3.12 ms | 6.09 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-p384, fsync=off | 1.20 ms | 3.18 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-p384, fsync=off | 2.08 ms | 3.67 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-p384, fsync=on | 1.98 ms | 4.20 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-p384, fsync=on | 3.35 ms | 6.20 ms |
| Judges (sim) | 3 judges x 50 ms simulated latency, parallel | 50.99 ms | 51.65 ms |
| Judges (sim) | 3 judges x 50 ms simulated latency, sequential | 150.41 ms | 150.46 ms |
| Judges (sim) | 3 judges x 200 ms simulated latency, parallel | 201.13 ms | 201.28 ms |
| Judges (sim) | 3 judges x 200 ms simulated latency, sequential | 600.56 ms | 600.76 ms |
| Judges (sim) | 3 judges, one hung (5 s), timeout_seconds=0.25 | 250.22 ms | 250.32 ms |

| Memory | Value |
|---|---:|
| baseline after imports + self-test (peak RSS) | 35.0 MiB |
| key set object ed25519 (tracemalloc, Python-side only) | 1.2 KiB |
| key set object ecdsa-p384 (tracemalloc, Python-side only) | 3.2 KiB |
| key set object hybrid-mldsa65-ed25519 (tracemalloc, Python-side only) | 13.7 KiB |
| key set object hybrid-mldsa65-p384 (tracemalloc, Python-side only) | 14.1 KiB |
| 10,000-entry ledger in memory (tracemalloc) | 8.64 MiB |
| kernel construction incl. self-test, ed25519 (tracemalloc) | 26.0 KiB |
| kernel construction incl. self-test, ecdsa-p384 (tracemalloc) | 26.9 KiB |
| kernel construction incl. self-test, hybrid-mldsa65-ed25519 (tracemalloc) | 60.2 KiB |
| kernel construction incl. self-test, hybrid-mldsa65-p384 (tracemalloc) | 59.6 KiB |
| process peak RSS at end of this benchmark run (all suites, 10k-entry ledger loaded) | 60.3 MiB |
| fresh process, ed25519: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.9 -> 42.8 MiB |
| fresh process, ecdsa-p384: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.8 -> 43.2 MiB |
| fresh process, hybrid-mldsa65-ed25519: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.9 -> 43.3 MiB |
| fresh process, hybrid-mldsa65-p384: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.8 -> 43.5 MiB |

tracemalloc figures count Python allocations only. Memory allocated inside
OpenSSL is not included; the RSS figures include it.

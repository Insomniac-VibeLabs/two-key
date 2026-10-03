# Performance and resource use

Measured on 2026-09-30 (about 07:33 MDT) with `bench.py` at the repository
root, after the PRIOR_ART.md §4 (i)–(iii) changes. The previous code
(commit 0d3a3c9) was measured with the same script in the same session,
immediately before; see "§4 (i)–(iii) phase: what changed". The numbers below come from one run on one machine; rerun the script on
your own hardware before relying on them.

**Defaults changed after these measurements** (F_REVIEW fixes,
CONCEPTION_NOTES Entry 10): every profile now uses SHA-384. Tokens are signed (`tk1-sig`) by default; the HMAC numbers below are the opt-in `tk1-hs384` path,
and `args_hash` is computed over the typed two-key-enc/2 encoding. The
`tk1` and SHA-256 rows below measure options that still exist but are no
longer the default. The numbers were not re-measured for this change.
Ledger records and the signed head are now AES-256-GCM, with the ledger key
and witness outside the ledger directory. Append, `invoke`, and `authorize`
rows below were measured before that sealing, so a current `bench.py` run
is the one to trust for those.

```bash
python bench.py            # full run (about 40 s); prints the tables below
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
| Path A policy eval (6 rules, 32 instructions) | 12.1 µs (deny: 7.2 µs) | same | Pure Python VM; no crypto |
| Token issue / verify (HMAC) | 10.8 / 8.7 µs (`tk1`) | 11.6 / 9.7 µs (`tk1-hs384`) | Bench tokens without the §4 (i) fields (704 B). Two-Key-issued tokens now carry them: 1,051 B, verify about +2 µs |
| Token issue / verify, signed (`tk1-sig`) | n/a | 683 / 300 µs | Optional mode; 6.8 KB token |
| Gateway: §4 (i) binding checks (token verify + view check + 1 consistency proof + hash/revocation lookups) | 34 µs | ≈ same (SHA-384) | New in this phase |
| Gateway `invoke`, full (checks + redeem entry + tool + signed head), fsync off / on | 322 µs / 780 µs | 1.04 ms / 1.91 ms | The signed head and file I/O dominate |
| Gateway `invoke` on an 18,201-entry ledger, fsync off | 356 µs | n/a | Proofs are O(log n) hashes |
| Gateway `invoke` with head signing deferred (`checkpoint_every=0`) | 155 µs | n/a (no signature on the call path) | Caller or timer runs `ledger.checkpoint()` |
| Ledger append + signed head, fsync off / on | 151 µs / 391 µs | 944 µs / 1.40 ms | per append (`auto_sign_every=1`) |
| Ledger append only (head signed at next checkpoint), fsync off / on | 27 µs / 113 µs | same | Two-Key default: one head per decision |
| Merkle consistency proof + verify, 10,000 entries (random old size / 6 entries back) | 22.5 / 10.5 µs | ≈ same | RFC 9162 |
| Merkle inclusion proof, 10,000 entries | 5.7 µs | ≈ same | Was 13.9 ms (rebuilt the whole tree) |
| Sign / verify | 30 / 95 µs | 664 µs / 270 µs | Hybrid signature is 6.1 KB (base64) |
| Sign / verify, P-384 variants | 154 / 324 µs (ECDSA P-384) | 789 / 494 µs (ML-DSA-65 + P-384) | |
| Full `authorize` (A + B with 3 local judges + token + 8 ledger entries + 1 signed head), fsync off / on | 1.12 ms / 2.10 ms | 2.14 ms / 2.97 ms | Excludes real judge latency (see below) |
| Constitution load: verify + split a single-source document; compile both paths + hashes | 169 µs; 56 µs | n/a | Once per load, not on the hot path |
| Crypto self-test at start-up | 6.7 ms (incl. ML-DSA PCT) | same | Once per provider |
| Peak RSS, fresh process, 1000 authorize+invoke cycles (8,001 ledger entries) | 45.8 MiB | 46.7 MiB | 32.6 MiB after imports; the growth is the in-memory ledger and Merkle tree |

## §4 (i)–(iii) phase: what changed (same machine, same session, ed25519 unless noted)

"Old" is commit 0d3a3c9, measured with this `bench.py` immediately before the new code.

| Operation | Old | New | Change |
|---|---:|---:|---|
| Path A eval (allow / deny) | 12.5 / 7.5 µs | 12.1 / 7.2 µs | none (noise) |
| Token verify, Two-Key-issued token | 8.4 µs (699 B) | 10.6 µs (1,051 B) | **+2 µs**: four more payload fields (isolated re-measurement) |
| Gateway checks-only row (token verify + args hash + normalize + root lookup) | 19.2 µs | 38.2 µs in the full run; **19.7 µs** vs 17.8 µs isolated | The full-run figure did not reproduce; isolated it is +2 µs (the larger token) |
| **Gateway invoke, head signing deferred** | 131 µs | 155 µs | **+23 µs (+18%). Hot-path regression**: the §4 (i) consistency proof, view check, and hash/revocation checks, plus the linked, larger ledger entries |
| **Gateway invoke, full, fsync off / on** | 297 / 684 µs | 322 / 780 µs | **+25 µs (+9%) / +96 µs (+14%)**. Hot-path regression, same causes; fsync-on figures are noisy on this VM |
| **Gateway invoke, ~18,000-entry ledger** | 303 µs | 356 µs | **+53 µs (+17%)**. Proof cost grows with log n |
| Gateway invoke, hybrid / P-384 suites | 1.15 ms / 505 µs | 1.04 ms / 546 µs | within noise; the signature dominates |
| **authorize, fsync off / on** | 1.00 / 1.98 ms | 1.12 / 2.10 ms | **+117 µs (+12%) / +117 µs (+6%)**. Regression: ballot binding (hashes attached to every ballot), larger token and capability entry, and the Merkle root taken at issuance. An isolated re-measurement gave +66 µs |
| authorize, hybrid-mldsa65-ed25519 fsync off | 2.08 ms | 2.14 ms | +3% |
| Ledger append only | 30.4 µs | 26.6 µs | faster (`Entry.to_json` no longer deep-copies the body) |
| merkle_root() / inclusion_proof(), 10,000 entries | 2.2 µs / 13.9 ms | 0.24 µs / 5.7 µs | faster (`MerkleTree` keeps subtree roots) |
| Peak RSS after 1000 cycles (8,001 entries) | 42.9 MiB | 45.8 MiB | **+2.9 MiB** (about 370 B per entry): the tree keeps about 2n subtree roots, and entries are larger |

What was done to keep the cost down: one consistency proof per `invoke`
(the view advances to the token's authenticated root instead of proving
view → current and token → view separately); a bounded memo for right-edge
subtree roots; `_split` using bit operations; the round's ballot binding
written once per `quorum_result` instead of on every ballot (the record
went from 1,777 to 1,117 bytes; it was 659 bytes before the §4 phase); no `dataclasses.asdict` or
`replace` on the ballot and ledger paths; and O(1) indexes for the latest
constitution load, revocations, and the token's own entry. The previous
gateway scanned the entries after the token's root (`kinds_after`), which
was O(n).

## Shared single-use record (2026-09-30 evening): what changed

Measured 2026-09-30 about 18:20–18:45 MDT on the same VM. Single use is now
tracked by the ledger (`PersonalLedger.redeem`) and shared by every gateway
on Two-Key, instead of a per-gateway set. On each invoke the gateway holds
the ledger's lock across its ledger checks and the redemption. The redemption
also takes an `flock` on the ledger file and `stat`s it to detect another
writer, and every `append` takes the lock and counts the bytes it wrote.
The lock later moved off the ledger file onto `<ledger-directory>.lock` and
now covers every append and checkpoint. The timings below are from before
that move.

**Interleaved A/B (the reliable figure).** Previous code (5b43f41) and the new
code ran in alternating processes, 6 rounds each, 1,450 timed invokes per
round, Ed25519, fsync off, 2 local judges:

| Gateway `invoke` | Previous (median of 6 rounds) | New | Change |
|---|---:|---:|---:|
| head signing deferred (`checkpoint_every=0`) | 159.3 µs | 168.8 µs | **+9 µs (+6%)** |
| full, one signed head per call | 330.5 µs | 348.2 µs | **+18 µs (+5%)**, of which about 9 µs is above the deferred figure and within this VM's noise |

**Hot-path regression, flagged:** about +9 µs per `invoke`. Measured
directly: a `redeem` costs 6.5 µs more than a plain `append` (stat about
1.1 µs, flock/unlock 0.5 µs, the rest locking and bookkeeping), and each
`append` costs about 1.8 µs more (lock, byte count, the redeemed index). A
redundant `mkdir` on the redemption path (3.7 µs) was removed before these
figures were taken. Nothing changes asymptotically, and no network or key
parsing is added to the path.

**`bench.py` gateway rows, re-run** (one full run before the change, one
after; the full-run medians move ±10–15% between runs on this shared VM,
which is larger than the effect, so read these with the A/B above):

| Row | Before (5b43f41) | After | Change |
|---|---:|---:|---:|
| invoke (all checks + redeem + tool + signed head), ed25519, fsync=off | 320.4 µs | 326.4 µs | +2% |
| invoke, head signing deferred (checkpoint_every=0), fsync=off | 159.5 µs | 153.6 µs | -4% |
| checks only: token verify + args hash + field normalize + root lookup | 23.9 µs | 22.5 µs | -6% |
| §4 (i) binding checks only: token verify + view check + 1 consistency proof + hash/revocation lookups | 31.3 µs | 34.3 µs | +10% |
| invoke on a ledger with >10,000 entries (18201), ed25519, fsync=off | 336.2 µs | 337.3 µs | +0% |
| invoke (all checks + redeem + tool + signed head), ed25519, fsync=on | 829.4 µs | 749.5 µs | -10% |
| invoke (all checks + redeem + tool + signed head), ecdsa-p384, fsync=off | 547.5 µs | 498.5 µs | -9% |
| invoke (all checks + redeem + tool + signed head), ecdsa-p384, fsync=on | 935.3 µs | 957.3 µs | +2% |
| invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-ed25519, fsync=off | 1.07 ms | 1.24 ms | +15% |
| invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-ed25519, fsync=on | 1.90 ms | 2.04 ms | +8% |
| invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-p384, fsync=off | 1.31 ms | 1.36 ms | +3% |
| invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-p384, fsync=on | 2.26 ms | 2.02 ms | -11% |

The "Full results" table below is from the earlier §4 (i)–(iii) run and was
not replaced.

## Hot-path properties (and how they are enforced)

* **Path A is in microseconds**: 7–12 µs per evaluation on this machine.
* **Key parsing is cached.** Public key sets are parsed once
  (`public_keyset_from_encoded` is LRU-cached; Two-Key keeps the parsed
  trusted key). Token issuers compute the HMAC key schedule once and copy it
  per call. Test: `ClassicSuites.test_public_key_parsing_is_cached`.
* **No network in the Two-Key/gateway path.** Test
  `NoNetworkInGatewayPath` replaces `socket.socket`, `create_connection`, and
  `getaddrinfo` with functions that fail, then runs a full authorize and
  invoke.
* **Signed-head updates are batched and configurable.** Signing the head
  is the most expensive local step (Ed25519 about 30 µs; hybrid about
  0.65 ms, with a p99 of about 2.5–3 ms because ML-DSA signing uses rejection
  sampling). Options:
  * `TwoKey(head_signing="decision")` (default): one signature covers every
    ledger entry of a decision (8 entries for an allowed action). A decision
    whose checkpoint fails is denied, so no token is released without a
    signed head;
  * `TwoKey(head_signing="append")`: sign after every append;
  * ledger `auto_sign_every=N` (1 by default for direct use; 0 means only on
    `checkpoint()`);
  * gateway `checkpoint_every=N` (1 by default; 0 means the caller
    checkpoints, e.g. on a timer). Until the next checkpoint, `verify` reports
    `size_mismatch` for the unsigned tail.
* **Merkle tree with stored subtree roots.** `merkle.MerkleTree` (since the
  §4 (i) phase) keeps every completed perfect-subtree root, so the current
  root (cached; 0.24 µs), a historical root (5.7 µs), an inclusion proof
  (5.7 µs), and an RFC 9162 consistency proof (10–23 µs including
  verification) all cost O(log n) to O(log² n) hash operations on a
  10,000-entry ledger. Before the §4 phase, `MerkleFrontier` gave an
  O(log n) current root, but historical roots and inclusion proofs rebuilt
  the whole tree. The very first version rebuilt it on every signed head.
* **Gateway §4 (i) checks are O(log n) and allocation-light**: one
  consistency proof per call, dictionary lookups for the latest
  constitution load, revocations, and the token's `capability_issued`
  entry.
* **fsync is configurable** (`PersonalLedger(fsync=…)`,
  `TwoKey(ledger_fsync=…)`). The default is on, for durability. On
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

How Two-Key bounds it:

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
* The default judge transport reuses one connection per thread and origin
  and retries a dropped connection or HTTP 429/502/503/504 at most twice
  inside that timeout. Redirects are not followed. Streaming and vendor SDKs
  are not used. OpenAI and xAI are asked for a strict ballot schema (xAI also
  `reasoning_effort: low`); Anthropic caches only the system prompt and the
  constitution. A 400 on those knobs falls back once. None of this changes
  the local ballot parser.
* Both paths always answer. A Path A deny still returns
  without calling any judge, in microseconds plus the ledger write.

End-to-end estimate: `authorize` ≈ local cost from the table (about 1–3 ms)
+ the slowest judge's latency, capped at `timeout_seconds`.

## Without a PQ library

Under the system interpreter (`cryptography` 43.0.0, no ML-DSA),
`bench.py --quick` runs the classic rows only. The figures matched the
table above within noise (e.g. Path A 12.4 µs, `tk1` verify 8.2 µs, §4 (i)
binding checks 31.1 µs, gateway invoke with Ed25519 head 327 µs, authorize
1.07 ms). Hybrid suites are unavailable there and
raise `PQUnavailableError`, as designed.

## Full results (this run)

| Group | Operation | Median | p99 |
|---|---|---:|---:|
| Path A | PolicyVM.eval (32 instr, 6 rules, allow) | 12.1 µs | 19.0 µs |
| Path A | PolicyVM.eval (deny: spend-cap) | 7.24 µs | 9.05 µs |
| Path A | normalize_action (input validation) | 3.28 µs | 4.96 µs |
| Token | issue tk1 (HMAC-SHA-256) | 10.8 µs | 15.7 µs |
| Token | verify tk1 (HMAC-SHA-256) [704 B token] | 8.74 µs | 11.7 µs |
| Token | issue tk1-hs384 (HMAC-SHA-384) | 11.6 µs | 14.2 µs |
| Token | verify tk1-hs384 (HMAC-SHA-384) [731 B token] | 9.67 µs | 13.0 µs |
| Token | issue tk1-sig (hybrid ML-DSA-65+Ed25519) | 683.4 µs | 2.99 ms |
| Token | verify tk1-sig (hybrid ML-DSA-65+Ed25519) [6765 B token] | 299.7 µs | 348.0 µs |
| Token | args_hash sha256 | 3.98 µs | 4.57 µs |
| Token | args_hash sha384 | 4.44 µs | 5.21 µs |
| Signature | sign   ed25519 | 30.1 µs | 36.0 µs |
| Signature | verify ed25519 [88 B b64 sig] | 95.1 µs | 112.2 µs |
| Signature | keygen ed25519 | 33.5 µs | 35.4 µs |
| Signature | sign   ecdsa-p384 | 153.8 µs | 181.2 µs |
| Signature | verify ecdsa-p384 [252 B b64 sig] | 323.5 µs | 376.7 µs |
| Signature | keygen ecdsa-p384 | 128.9 µs | 143.9 µs |
| Signature | sign   hybrid-mldsa65-ed25519 | 664.3 µs | 2.41 ms |
| Signature | verify hybrid-mldsa65-ed25519 [6100 B b64 sig] | 270.2 µs | 312.9 µs |
| Signature | keygen hybrid-mldsa65-ed25519 | 213.5 µs | 251.0 µs |
| Signature | sign   hybrid-mldsa65-p384 | 789.2 µs | 3.06 ms |
| Signature | verify hybrid-mldsa65-p384 [6164 B b64 sig] | 493.9 µs | 568.7 µs |
| Signature | keygen hybrid-mldsa65-p384 | 323.3 µs | 364.9 µs |
| Ledger | append + signed head, ed25519, fsync=off | 150.8 µs | 489.0 µs |
| Ledger | append + signed head, ed25519, fsync=on | 391.4 µs | 764.1 µs |
| Ledger | append + signed head, ecdsa-p384, fsync=off | 295.4 µs | 407.1 µs |
| Ledger | append + signed head, ecdsa-p384, fsync=on | 605.7 µs | 1.47 ms |
| Ledger | append + signed head, hybrid-mldsa65-ed25519, fsync=off | 944.4 µs | 3.09 ms |
| Ledger | append + signed head, hybrid-mldsa65-ed25519, fsync=on | 1.40 ms | 4.20 ms |
| Ledger | append + signed head, hybrid-mldsa65-p384, fsync=off | 1.15 ms | 3.13 ms |
| Ledger | append + signed head, hybrid-mldsa65-p384, fsync=on | 1.56 ms | 3.90 ms |
| Ledger | append only (head signed later by checkpoint), fsync=off | 26.6 µs | 48.6 µs |
| Ledger | append only (head signed later by checkpoint), fsync=on | 112.5 µs | 315.2 µs |
| Ledger | merkle_root() on a 10,000-entry ledger (incremental) | 0.24 µs | 0.30 µs |
| Ledger | consistency proof + verify, random old size -> 10,000 entries | 22.5 µs | 34.2 µs |
| Ledger | consistency proof + verify, 9,994 -> 10,000 (typical gateway view refresh) | 10.5 µs | 15.5 µs |
| Ledger | merkle_root(size) for a historical size, 10,000 entries | 5.71 µs | 11.0 µs |
| Ledger | inclusion_proof() on a 10,000-entry ledger | 5.68 µs | 9.46 µs |
| Gateway | invoke (all checks + redeem + tool + signed head), ed25519, fsync=off | 322.2 µs | 485.6 µs |
| Gateway | invoke, head signing deferred (checkpoint_every=0), fsync=off | 154.8 µs | 191.5 µs |
| Gateway | checks only: token verify + args hash + field normalize + root lookup | 38.2 µs | 47.4 µs |
| Gateway | §4 (i) binding checks only: token verify + view check + 1 consistency proof + hash/revocation lookups | 33.6 µs | 47.8 µs |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ed25519, fsync=off | 1.12 ms | 1.79 ms |
| Gateway | invoke on a ledger with >10,000 entries (18201), ed25519, fsync=off | 356.1 µs | 658.2 µs |
| Authorize | authorize on a ledger with >10,000 entries, ed25519, fsync=off | 1.09 ms | 1.86 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), ed25519, fsync=on | 780.5 µs | 1.98 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ed25519, fsync=on | 2.10 ms | 3.38 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), ecdsa-p384, fsync=off | 545.9 µs | 965.1 µs |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ecdsa-p384, fsync=off | 1.34 ms | 2.09 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), ecdsa-p384, fsync=on | 1.01 ms | 1.93 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), ecdsa-p384, fsync=on | 2.37 ms | 3.62 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-ed25519, fsync=off | 1.04 ms | 2.72 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-ed25519, fsync=off | 2.14 ms | 4.82 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-ed25519, fsync=on | 1.91 ms | 4.22 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-ed25519, fsync=on | 2.97 ms | 5.83 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-p384, fsync=off | 1.37 ms | 3.54 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-p384, fsync=off | 2.42 ms | 5.60 ms |
| Gateway | invoke (all checks + redeem + tool + signed head), hybrid-mldsa65-p384, fsync=on | 2.09 ms | 3.95 ms |
| Authorize | authorize (A + B[3 local judges] + token + ledger), hybrid-mldsa65-p384, fsync=on | 3.70 ms | 6.78 ms |
| Constitution | verify_signed + split (single-source /2 document, Ed25519) | 168.8 µs | 247.7 µs |
| Constitution | compile_both: bytecode + static check + both hashes (sha256) | 56.2 µs | 78.9 µs |
| Judges (sim) | 3 judges x 50 ms simulated latency, parallel | 50.97 ms | 51.27 ms |
| Judges (sim) | 3 judges x 50 ms simulated latency, sequential | 150.73 ms | 150.80 ms |
| Judges (sim) | 3 judges x 200 ms simulated latency, parallel | 201.09 ms | 201.52 ms |
| Judges (sim) | 3 judges x 200 ms simulated latency, sequential | 600.51 ms | 600.89 ms |
| Judges (sim) | 3 judges, one hung (5 s), timeout_seconds=0.25 | 250.32 ms | 250.46 ms |

| Memory | Value |
|---|---:|
| baseline after imports + self-test (peak RSS) | 35.3 MiB |
| key set object ed25519 (tracemalloc, Python-side only) | 1.2 KiB |
| key set object ecdsa-p384 (tracemalloc, Python-side only) | 3.2 KiB |
| key set object hybrid-mldsa65-ed25519 (tracemalloc, Python-side only) | 13.7 KiB |
| key set object hybrid-mldsa65-p384 (tracemalloc, Python-side only) | 14.1 KiB |
| 10,000-entry ledger in memory (tracemalloc) | 8.64 MiB |
| TwoKey construction incl. self-test, ed25519 (tracemalloc) | 27.1 KiB |
| TwoKey construction incl. self-test, ecdsa-p384 (tracemalloc) | 28.2 KiB |
| TwoKey construction incl. self-test, hybrid-mldsa65-ed25519 (tracemalloc) | 60.5 KiB |
| TwoKey construction incl. self-test, hybrid-mldsa65-p384 (tracemalloc) | 59.9 KiB |
| process peak RSS at end of this benchmark run (all suites, 10k-entry ledger loaded) | 76.8 MiB |
| fresh process, ed25519: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.6 -> 45.8 MiB |
| fresh process, ecdsa-p384: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.7 -> 46.6 MiB |
| fresh process, hybrid-mldsa65-ed25519: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.6 -> 46.7 MiB |
| fresh process, hybrid-mldsa65-p384: after imports -> peak after 1000 authorize+invoke cycles (8001 ledger entries) | 32.6 -> 46.7 MiB |

tracemalloc figures count Python allocations only. Memory allocated inside
OpenSSL is not included; the RSS figures include it.


# Judges and quorum

This document describes judge and quorum behavior in `two-key` 0.5.0 (tag `v0.5.0` on `main`). It is not an independent review or a claim of formal verification. If this document disagrees with the implementation, the code wins; correct the document after verifying the intended behavior.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the threat register, [SCOPE.md](SCOPE.md) for the project's boundaries, and [FIT.md](FIT.md) for when this package is or is not suitable.

## Contents

<!-- toc -->
- [What a judge is](#what-a-judge-is)
- [One judge](#one-judge)
- [The quorum threshold](#the-quorum-threshold)
- [YES, NO, and ABSTAIN](#yes-no-and-abstain)
- [Diversity and local judges](#diversity-and-local-judges)
- [How Path A and Path B combine](#how-path-a-and-path-b-combine)
- [What a quorum pass means](#what-a-quorum-pass-means)
- [Operator checklist](#operator-checklist)
- [Implementation references](#implementation-references)
<!-- /toc -->

## What a judge is

A Path B judge is a configured evaluator that returns a ballot on an authorization attempt. A judge is not the authorization system by itself, and an affirmative ballot is not proof that an action is safe.

The operator configures the judges. Two-Key requires at least one judge and performs startup checks to prevent a judge from sharing the monitored agent's credential or qualifying as the same agent under the configured identity checks.

A ballot is affirmative, negative, or unusable. A missing, malformed, errored, mismatched, or timed-out ballot cannot count as an affirmative vote.

Each ballot is one stateless request. Two-Key's judge adapters send a system prompt and one user message (the normalized record, and the proposal text when configured) at temperature 0, with no earlier calls. So the same request gets the same answer, and two judges on one model answer word for word alike: they fail together, which is why `high_assurance` asks for two makers.

A judge endpoint that keeps its own memory across ballots (a persistent agent, or a chat with saved memory) changes this. Every earlier call's agent-written text is then in the judge's context, so an injection in one call can steer the vote on a later one, and the ledger cannot explain a vote that depends on that memory. Two-Key cannot see or detect it. The judge's identity, credential, and service can be long-lived; give it a fresh context for every ballot. A history of recent decisions is planned as a summary Two-Key builds from its own ledger, with structured fields only (#1, before 1.0; [ROADMAP.md](../ROADMAP.md)).

## One judge

```mermaid
flowchart TD
    A["Authorization request"] --> B["Build normalized action record"]
    B --> C["Prepare configured judge input"]
    C --> D["Call judge adapter"]
    D --> E{"Usable ballot?"}
    E -->|Yes| F{"Vote"}
    F -->|YES| G["One affirmative ballot"]
    F -->|NO| H["One negative ballot"]
    E -->|No| I["Abstention"]
    G --> J["Quorum evaluation"]
    H --> J
    I --> J
```

This diagram shows one judge's contribution, not the final authorization decision.

The convenor checks ballot identity and binding. A ballot that reports inconsistent binding hashes becomes an abstention. With `ballot_binding="echo"`, a judge must also return the required binding information itself.

By default, `judge_inputs="record_only"` gives judges the normalized action record and constitution, not the agent's proposal text. `judge_inputs="record_and_proposal"` permits the proposal to be included. After a derive deny, tool arguments are withheld unless `tool_args_on_derive_deny=True`. Path B still runs either way.

## The quorum threshold

The quorum policy separates the affirmative threshold (`required_yes`) from the minimum number of valid responses (`min_responding`).

- `required_yes` is the number of affirmative ballots needed to pass the vote threshold.
- `min_responding` is the minimum number of valid ballots required before the round can be counted.
- If `required_yes` is unset, Two-Key resolves it to `min(2, number_of_judges)`.
- If `min_responding` is unset, it follows the effective `required_yes`.

```mermaid
flowchart TD
    A["Configured judges: N"] --> B{"required_yes set?"}
    B -->|Yes| C["Use configured threshold"]
    B -->|No| D["Use min(2, N)"]
    C --> E["Resolve min_responding"]
    D --> E
    E --> F["Collect and validate ballots"]
    F --> G["Apply quorum and diversity requirements"]
    G --> H{"All requirements met?"}
    H -->|Yes| I["Path B passes"]
    H -->|No| J["Path B denies"]
```

With the default policy:

| Configured judges | Required YES ballots |
| ---: | ---: |
| 1 | 1 |
| 2 | 2 |
| 3 | 2 |
| 4 | 2 |
| 5 | 2 |

This is **not a majority rule**. Two affirmative ballots can meet the default threshold with five configured judges. Operators who need a majority or unanimity must configure an appropriate `required_yes` value.

**With `required_yes: 1` and two or more judges, one judge approves a call alone whenever the others are down, time out, or abstain,** because `min_responding` then follows `required_yes` and is 1. In live run 6x a 1-of-2 deployment executed a call with judge B on a dead port. `TwoKey` prints a `two-key: WARNING: quorum: required_yes 1 with N judges and min_responding 1 ...` line at start. Set `min_responding` to the number of judges to require every judge to answer, or `required_yes: 2` for two approvals.

The configured set must be capable of satisfying the policy. If the affirmative threshold, response floor, provider floor, or judge-set diversity requirements cannot be met, configuration may be rejected at startup. `convene` also denies when the configured policy cannot be met.

## YES, NO, and ABSTAIN

The quorum evaluator distinguishes affirmative ballots, negative ballots, and abstentions.

- **YES:** a usable affirmative ballot.
- **NO:** a usable negative ballot.
- **ABSTAIN:** a missing, malformed, errored, timed-out, identity-mismatched, binding-mismatched, or otherwise unusable ballot.

An abstention is never a YES. If fewer than `min_responding` valid ballots arrive, the round denies without counting the vote tally. The recorded result has `counted=False` and does not report a YES/NO tally.

Judges run in parallel by default, under the overall `timeout_seconds` deadline (45 seconds by default). Two-Key refuses a configuration without a positive hard deadline. A judge that does not return a usable ballot by the deadline cannot supply a YES for that round.

## Diversity and local judges

The default policy has minimal diversity requirements:

- `min_makers=1`.
- `min_local_judges=0`.
- `require_local_yes=False`.
- `min_distinct_providers=1`.

A provider floor of one does not require provider diversity. The default policy does not require a local judge or a local affirmative vote.

`QuorumPolicy.high_assurance()` opts into stronger requirements:

- At least two distinct model-maker labels.
- At least one local judge.
- An affirmative vote from a local judge.
- `required_yes=2` by default, unless the caller overrides it.
- Two-Key does not start when another account could change a file or
  folder it runs or reads (`writable_path`, docs/CONNECTING.md), and
  `on_writable_paths: warn` is refused.

`QuorumPolicy.section4()` applies those same diversity requirements and sets `require_path_a_first=True`. In the current implementation, however, `TwoKey.authorize` does not read that flag to skip Path B. Both paths run once a request is well-formed and within limits; the one exception is a call Path A cannot read under its spec (`derive_failed:`), which is not sent to the judges unless `tool_args_on_derive_deny` is set.

These requirements do not prove that judges are independent:

- A judge's maker label is operator-supplied configuration, not an independently verified claim about model ownership.
- Locality is determined by the configured judge's effective locality checks. It is not hardware or model attestation.
- Different provider names or maker labels do not establish statistical, organizational, or operational independence.
- With `heterogeneity_scope="responding"`, the diversity floor also applies to the judges that return valid ballots; the default is `"selection"`.

For high-impact tools, configure the judge set deliberately, check the actual endpoints and credentials, and choose thresholds according to the risk.

## How Path A and Path B combine

Path A evaluates deterministic policy rules against the normalized structured action record. Path B evaluates the action using the configured judge quorum. Neither path alone is sufficient for authorization.

```mermaid
flowchart TD
    A["Well-formed request within limits"] --> B["Path A: deterministic policy VM"]
    A --> C["Path B: configured judges and quorum"]
    B --> D{"Path A allows?"}
    C --> E{"Path B passes?"}
    D -->|No| F["Deny authorization"]
    E -->|No| F
    D -->|Yes| G{"Any other deny condition?"}
    E -->|Yes| G
    G -->|Yes| F
    G -->|No| H["Capability may be issued"]
```

The final decision allows the action only if Path A allows, the quorum passes, and no other deny condition remains. Capability issuance can still fail, including when the issuer key is unavailable or a required ledger write fails.

A Path A deny does not skip Path B. After a derive deny, judge input omits argument bytes by default. A call that cannot be read under its spec (`derive_failed:`) is the one exception: the judges would get a form with nothing derived in it and no arguments, so they are not asked, and Path B is ledgered as `skipped:derive_failed` (0.5.0). With `tool_args_on_derive_deny: true` they see the arguments and are asked. A mismatch (`amount_mismatch` and the like) and a rule deny still go to the judges. `require_path_a_first` does not change this behavior.

With a content scanner configured (0.6.0, on `working`), a scanned call reaches the judges with a trusted `<scan_result>` section (scanner label, verdict, categories) before the untrusted record, and each declared file appears in the record as its digest and size, never its content. When the verdict is flagged, the arguments and the proposal are withheld unless the quorum sets `tool_args_on_scan_flag: true`. The verdict `encrypted` (an encrypted file on a tool the principal signed `encrypted: pass`) comes with a line saying the scanner could not look inside, and the arguments are sent. A scan deny is a Path A deny, so the judges still vote. See [SCANNERS.md](SCANNERS.md).

Malformed or oversized requests can be denied before either path runs.

## What a quorum pass means

A quorum pass means the configured Path B requirements were met for that authorization attempt. It does not establish that:

- The judges are correct, infallible, or independent.
- The maker labels are truthful.
- The proposal or action is safe in every relevant context.
- The payload has been scanned for malware, data loss, or sensitive information. That holds only for a tool the signed constitution marks for scanning with a content scanner configured (0.6.0, on `working`), and then the judges were told the verdict, not shown the content; see [SCANNERS.md](SCANNERS.md).
- The deployment has been independently audited or formally verified.
- The package is a FIPS 140-3 validated cryptographic module.

The capability and gateway controls add restrictions but do not eliminate these limitations. The capability private key is separate from the gateway verifier's key, but the gateway shares the Two-Key process and ledger object; a gateway in another process or host is not supported (#45). There is no process-level isolation between them; see [THREAT_MODEL.md](THREAT_MODEL.md).

## Operator checklist

Before relying on a deployment:

1. Configure the monitored agent and at least one judge explicitly.
2. Confirm that judge identities and credentials match the actual deployment.
3. Set `required_yes` and `min_responding` intentionally. Do not assume the default is a majority. With `required_yes: 1` and more than one judge, set `min_responding` too, or one judge decides alone while the others are down.
4. For higher-impact actions, consider `QuorumPolicy.high_assurance()` and check the configured local judge and maker labels.
5. Decide whether judges receive only the normalized record or also the proposal text.
6. Give each judge a fresh context for every ballot: turn off any memory its endpoint keeps across requests.
7. Review `tool_args_on_derive_deny`; argument bytes are withheld by default after a derive deny, and a call that cannot be read is then not sent to the judges at all. With a content scanner, review `tool_args_on_scan_flag` the same way.
8. Test timeout, malformed ballot, binding mismatch, insufficient response, and deny cases.
9. Read [THREAT_MODEL.md](THREAT_MODEL.md) and [FIT.md](FIT.md) before deployment.

## Implementation references

- [`two_key/quorum.py`](../two_key/quorum.py) — quorum policy, threshold resolution, ballot validation, response floors, and diversity requirements.
- [`two_key/core.py`](../two_key/core.py) — Path A/Path B execution and final authorization decision.
- [THREAT_MODEL.md](THREAT_MODEL.md) — threats, assumptions, and residual risks.
- [SCOPE.md](SCOPE.md) — project boundaries.
- [FIT.md](FIT.md) — intended users and reasons not to use this package.

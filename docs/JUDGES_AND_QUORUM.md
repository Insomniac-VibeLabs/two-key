Judges and Quorum

Status and scope

This document describes the judge and quorum behavior implemented on the working branch. It is an explanation of the current implementation, not a claim of independent validation, formal verification, or production readiness.

Implementation references:

* two_key/quorum.py — quorum policy, ballot handling, thresholds, and diversity requirements.
* two_key/core.py — authorization flow and the final decision.
* docs/THREAT_MODEL.md — threats, limitations, and residual risk.
* docs/FIT.md — when this package is or is not the appropriate control.

1. What is a judge?

A judge is a configured Path B evaluator that returns a ballot on an authorization attempt. A judge is not the authorization system by itself, and one affirmative ballot is not proof that an action is safe.

Each judge is configured by the operator. Two-Key does not automatically select or create judges. The monitored agent and judges have separate roles and are subject to startup identity-separation checks.

A judge may return an affirmative vote, a negative vote, or an unusable response. A missing, malformed, errored, mismatched, or timed-out ballot cannot count as an affirmative vote.

2. A single judge’s role

flowchart TD
    A["Authorization request"] --> B["Build normalized action record"]
    B --> C["Prepare configured judge input"]
    C --> D["Call the judge adapter"]
    D --> E{"Is the ballot usable?"}
    E -->|Yes| F{"Vote"}
    F -->|YES| G["One affirmative ballot"]
    F -->|NO| H["One negative ballot"]
    E -->|No| I["Abstention"]
    G --> J["Send ballot to quorum evaluator"]
    H --> J
    I --> J

The diagram represents one judge’s contribution, not the final authorization decision.

A usable ballot is checked against the configured ballot and binding rules. A ballot that reports an inconsistent binding is treated as an abstention. The convenor binds ballots to the action record and constitution; with ballot_binding="echo", the judge must also provide the required binding information itself.

By default, judges receive the normalized action record and constitution, not the agent’s proposal text. This is controlled by judge_inputs="record_only". The alternative record_and_proposal permits the proposal text to be included. Tool arguments are withheld from judges after a derive failure unless tool_args_on_derive_deny=True.

3. How the default affirmative threshold works

The quorum policy separates two questions:

* Approval threshold (required_yes): how many affirmative ballots are required.
* Availability floor (min_responding): how many valid ballots must be received before the round can be counted.

When required_yes is not explicitly configured, the implementation resolves it to min(2, number_of_judges). The default min_responding follows the effective affirmative threshold.

flowchart TD
    A["Count configured judges: N"] --> B{"Is required_yes configured?"}
    B -->|Yes| C["Use configured required_yes"]
    B -->|No| D["Resolve to min(2, N)"]
    C --> E["Resolve min_responding"]
    D --> E
    E --> F["Collect ballots and apply policy floors"]
    F --> G{"All requirements met?"}
    G -->|Yes| H["Path B passes"]
    G -->|No| I["Path B denies"]

With the default policy, the affirmative threshold is:

Configured judges	Required YES ballots
1	1
2	2
3	2
4	2
5	2

This is not a majority rule. For example, two YES ballots can meet the default threshold in a five-judge configuration. Operators who require a majority or unanimity must explicitly configure an appropriate threshold.

The configured judge set must be capable of meeting the policy. If the affirmative or response threshold cannot be met with the configured judges, startup is refused.

4. YES, NO, and ABSTAIN

The quorum evaluator distinguishes affirmative votes, negative votes, and abstentions.

* YES: a usable affirmative ballot.
* NO: a usable negative ballot.
* ABSTAIN: a ballot that is missing, malformed, errored, timed out, mismatched, or otherwise unusable.

An abstention is not a YES. If the valid-response availability floor is not met, the round denies without counting the vote tally; the recorded result marks the round as not counted.

Judges run in parallel by default under an overall hard deadline. A judge that has not returned a usable ballot by the deadline cannot make the round wait indefinitely or contribute a late affirmative vote.

5. Diversity and local-judge requirements

The default quorum policy has minimal diversity requirements:

* At least one configured judge.
* At least one distinct model-maker label.
* No requirement for a local judge.
* No requirement that a local judge vote YES.
* min_distinct_providers defaults to one, so it does not itself require provider diversity.

QuorumPolicy.high_assurance() opts into stronger judge-set requirements:

* At least two distinct model-maker labels.
* At least one local judge.
* At least one YES vote from a local judge.
* An affirmative threshold of two by default, unless the caller overrides it.

The section4() policy includes those diversity requirements and sets require_path_a_first=True. However, in the current implementation, TwoKey.authorize does not use that flag to skip Path B. Both paths still run once a request is well-formed and within limits.

These settings should not be described as independent proof of diversity:

* Maker labels are operator-supplied configuration, not independently verified claims about model ownership.
* Locality is determined by the configured judge’s local-weight and endpoint-host checks; it is not remote attestation of the hardware or model.
* Different providers or maker labels do not, by themselves, prove statistical or operational independence.

For high-impact tools, operators should choose and configure the judge set deliberately, review the actual endpoints and credentials, and set the threshold appropriate to their risk.

6. How the two authorization paths combine

Path A and Path B have different responsibilities. Path A evaluates deterministic policy rules against the normalized structured action. Path B evaluates the action using the configured judge quorum.

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

The overall decision is allowed only when Path A allows, the quorum passes, and no other deny condition remains.

A Path A deny does not skip Path B in the current implementation. After a derive deny, judge input omits the argument bytes by default, but the normalized record is still evaluated by Path B. The require_path_a_first setting does not change that execution order today.

Malformed or oversized requests may be denied before either path runs.

7. What a quorum pass does—and does not—mean

A quorum pass means that the configured Path B requirements were met for that authorization attempt. It does not establish that:

* The judges are infallible or truly independent.
* The model-maker labels are truthful.
* A judge’s reasoning is correct.
* The tool’s payload has been scanned for malware or sensitive information.
* The deployment has been independently audited or formally verified.
* The package is a FIPS 140-3 validated cryptographic module.

The capability and gateway controls provide additional restrictions, but they do not eliminate these limitations. The gateway is intended to be separated from the minting keys; the current project documentation notes that the fully separated gateway-only ledger role is designed but not yet built.

8. Operator checklist

Before relying on a deployment:

1. Configure the monitored agent and at least one judge explicitly.
2. Ensure judge credentials and identity declarations match the actual deployment.
3. Choose required_yes and min_responding intentionally; do not assume the default is a majority.
4. For higher-impact actions, consider QuorumPolicy.high_assurance() and verify the configured local judge and maker labels.
5. Decide whether judges should receive only the normalized record or also the proposal text.
6. Review the effect of tool_args_on_derive_deny; argument bytes are withheld by default after a derive deny.
7. Test timeout, malformed-ballot, binding-mismatch, insufficient-response, and deny scenarios.
8. Read docs/THREAT_MODEL.md and docs/FIT.md before deployment.

Sources of truth

The implementation in two_key/quorum.py and two_key/core.py is authoritative for runtime behavior. If this document conflicts with the code, treat the document as incorrect and update it after verifying the intended behavior.

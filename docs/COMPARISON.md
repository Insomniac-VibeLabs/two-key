# Comparison

This page says what `two-key` decides, and what it does not. It is
not a ranking and it has no scores. The other rows are categories people
already search for when they want to stop an agent from acting. Confirm the
current behavior of those projects in their own docs before you rely on them.

A call runs only if Path A and Path B both allow, and only if the gateway
later redeems a single-use token bound to that tool and those argument
bytes. Path A does not read English. There is no MCP proxy in this release (branch `working` has one; it forwards an upstream server's signed tools and offers none of its own).
There are no scanner hooks in this package. Key backup (0.3.0) is three
passphrase bundles of this package's own keys, not a seed phrase and not a
substitute for a password manager.

| Category | What that category decides | This package |
| --- | --- | --- |
| Content and injection filters, such as Llama Guard, Prompt Guard, NeMo input rails, and Guardrails AI | Whether text looks unsafe, off-topic, or injected | Does not. Path A never reads the proposal. A filter can run before this package. It is not the authorization decision. |
| Dialogue and execution rails, such as NeMo execution rails | Whether a step in a conversation script may call a tool | Does not model a dialogue. The gateway runs a registered function only after both paths allow and the token matches the argument bytes. |
| Deterministic policy engines, such as Cedar, OPA, and Cerbos | Whether a request is permitted by policy, independent of a model | Path A is this kind of check, and only for the normalized action record and the compiled hard rules. It is not a general policy engine for the rest of the application. The second key is the judge quorum. The token and the ledger are part of the decision. |
| Identity and MCP transport authorization | Whether a client may open a session or act as a user | Not user login or MCP session authorization. The MCP proxy (branch `working`) authorizes each `tools/call`, not who may connect. This package has no X.509 or PKI check. |
| Audit products and DLP | Whether a payload is sensitive, and whether an outside system stores the decision | The ledger is an encrypted hash chain with a signed head. Nothing is exported to a SIEM. There is no DLP or antivirus hook, and no built-in scan of argument text. |

## Do not use this instead of

- a content filter or a moderation API
- user login, OAuth for your users, or MCP session authorization
- a hosted DLP or antivirus product
- a FIPS 140-3 validated module

Path A is only as good as the fields the signed tool spec can read. Those
fields, the built-in ones and any custom fields the principal declares,
are derived from the argument bytes and a disagreeing claim is a
deny. A constitution without `tool_specs` does not load. An unnamed argument
key does not reach the tool. `deny_unmapped` (off by default) denies the call
instead of dropping the key. A copied counterparty must be on that path's
`allow` list. A payload `shape`, when set, checks only the kind of value.
It does not read the contents. This package does
not classify free text and does not track per-value information flow. This
package has no scanning, PKI, or anchoring.
What this repository leaves out is [SCOPE.md](SCOPE.md).

# Comparison

This page says what `two-key` decides, and what it does not. It is not a
ranking and it has no scores. The other rows are categories people already
search for when they want to stop an agent from acting. Confirm the current
behavior of those projects in their own docs before you rely on them.

A call runs only if Path A and Path B both allow, and only if the gateway
later redeems a single-use token bound to that tool and those argument
bytes. Path A does not read English. There is no MCP server in this release.

| Category | What that category decides | This package |
| --- | --- | --- |
| Content and injection filters, such as Llama Guard, Prompt Guard, NeMo input rails, and Guardrails AI | Whether text looks unsafe, off-topic, or injected | Does not. Path A never reads the proposal. A filter can run before this package. It is not the authorization decision. |
| Dialogue and execution rails, such as NeMo execution rails | Whether a step in a conversation script may call a tool | Does not model a dialogue. The gateway runs a registered function only after both paths allow and the token matches the frozen argument bytes. |
| Deterministic policy engines, such as Cedar, OPA, and Cerbos | Whether a request is permitted by policy, independent of a model | Path A is this kind of check, and only for the normalized action record and the compiled hard rules. It is not a general policy engine for the rest of the application. The second key is the judge quorum. The token and the ledger are part of the decision. |
| Identity and MCP transport authorization | Whether a client may open a session or act as a user | Not an MCP server, and not user login. Enterprise mode can require X.509 identities, which you supply, for the principal, agents, and judges. That check is fail-closed when enterprise mode is on. It is not on in personal mode. |
| Audit products and DLP | Whether a payload is sensitive, and whether an outside system stores the decision | The ledger is an encrypted hash chain with a signed head. Enterprise mode can send each decision to a SIEM over syslog TLS. A down SIEM is recorded and does not change the decision. DLP and antivirus are optional hooks on the gateway. With no scanners configured, nothing is scanned. The included scanners are examples, and the tests use fakes. |

## Do not use this instead of

- a content filter or a moderation API
- user login, OAuth for your users, or MCP session authorization
- a hosted DLP or antivirus product
- a FIPS 140-3 validated module

Path A is only as good as the structured fields it is given. Who produces
that record is still an open question. See [THREAT_MODEL.md](THREAT_MODEL.md).
The smaller package that leaves scanning, PKI, and anchoring out is
[two-key-concept](https://github.com/Insomniac-VibeLabs/two-key-concept).

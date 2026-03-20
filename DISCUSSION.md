# Open Questions

## Should the policy commitment be published on-chain for persistent auditability?

A policy commitment published to a blockchain would give verifiers a tamper-proof reference point — they could confirm that the policy commitment in a proof matches one that was publicly registered at a known time. The tradeoff is cost, latency, and the question of which chain (or whether an append-only log without full blockchain overhead would suffice).

## Can the circuit extend to cover structured LLM outputs — e.g. JSON tool call responses?

The current circuit covers tool call inputs (what the agent asked to do) but not tool call outputs (what the tool returned). If the tool returns structured data — a JSON object, a file listing, a database result — that data could be hashed and included in the session log. The open question is whether this adds meaningful assurance or just expands the proof surface without changing the trust model.

## What is the right policy schema for agentic AI systems — rules-based or capability-based?

This proof-of-concept uses a deny-list / constraint model: specify what the agent must NOT do. An alternative is a capability model: specify what the agent IS allowed to do, with everything else denied by default. Capability-based policies are more restrictive but easier to reason about. The right answer likely depends on the deployment context and the risk tolerance of the verifier.

## How does this compose with MCP's existing authorization model?

The Model Context Protocol already defines how agents connect to tool servers, including authentication and scoping. A ZK compliance proof could layer on top of MCP — the MCP server logs tool calls, the operator proves compliance against the log. The question is whether MCP's architecture needs changes to support this cleanly, or whether it works as an external add-on.

## Is groth16 the right proof system, or should this use STARKs to eliminate the trusted setup?

groth16 produces small, fast-to-verify proofs but requires a trusted setup ceremony. STARKs (Scalable Transparent ARguments of Knowledge) eliminate the trusted setup entirely — no toxic waste — at the cost of larger proofs (~100KB vs. ~200 bytes) and slower verification. For a system where proof size matters less than trust assumptions, STARKs may be the better foundation.

---

Open a GitHub Discussion or file an issue to contribute.

## Related work

- **zk-MCP** ([arxiv.org/abs/2512.14737](https://arxiv.org/abs/2512.14737))

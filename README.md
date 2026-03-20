AI agents operate on instruction documents — policies that govern what tools they can use, what data they can access, and what sequences of actions they're allowed to take. There is currently no way to prove an agent followed those instructions without either revealing the instructions to the verifier or trusting the agent's own report.

## What this is

AgentProof is a minimal proof-of-concept showing that a zero-knowledge proof (groth16 via snarkjs) can verify an agent's action log was compliant with a policy document — without exposing the policy contents to the verifier. The verifier learns exactly one bit: compliant or not. See [SPEC.md](SPEC.md) for the full technical specification.

## Interactive Demo

**[https://dvelton.github.io/agentproof](https://dvelton.github.io/agentproof)**

Edit a policy, build an agent session, generate a real groth16 proof in your browser, and see what the verifier learns — and doesn't.

(Screenshot placeholder — add after first deploy)

## What is and isn't proved

| Proved by this system | Not proved |
|---|---|
| Action log complies with compiled policy rules | LLM inference or model identity |
| Policy commitment matches the policy used | Prompt or system prompt contents |
| Session log is unmodified (Merkle root) | That the agent ran the policy at all |

## Run the demo (CLI)

```
npm install
bash scripts/build_circuit.sh    # compiles circuit, ~2-5 min
npm run demo
```

## Architecture

Policy compiler encodes rules as field elements and produces a Poseidon commitment hash. The circom circuit takes the policy (private) and session log (private) and outputs three public signals: policy commitment, session root, and compliance result. The verifier checks the proof using only those public signals — the policy document is never shared.

## Open questions

See [DISCUSSION.md](DISCUSSION.md).

## Security note

The trusted setup uses a test toxic waste ceremony and is NOT secure for production use.

# AgentProof Technical Specification

## 1. Motivation

AI agents increasingly operate with real autonomy — reading files, calling APIs, modifying data — all governed by instruction documents (policies) provided by the agent operator. The operator has every reason to claim compliance. The downstream consumer of the agent's output has no reason to trust that claim.

This creates a verification gap. Either the operator shares the full policy with the verifier (exposing proprietary instructions, system prompts, and competitive advantages), or the verifier accepts the operator's word. Neither option scales. AgentProof demonstrates a third path: using zero-knowledge proofs to verify that a structured action log satisfies a set of policy rules, without revealing what those rules are. The verifier learns one bit — compliant or not — and nothing else about the policy.

## 2. Threat model

The verifier trusts three things:

- **The circuit.** It is open-source and auditable. Anyone can inspect the constraint system to confirm that a valid proof implies compliance.
- **The proof.** A valid groth16 proof is computationally binding — it cannot be forged without breaking the discrete logarithm assumption on the BN128 curve.
- **The public signals.** These are the policy commitment hash, the session root hash, and the compliance bit. They are produced by the circuit and visible to the verifier.

The verifier does NOT trust:

- **The prover's claims about the policy.** The prover could claim any policy. The commitment hash binds the proof to a specific policy, but the verifier cannot recover the policy from the hash.
- **The agent's logs.** The session root binds the proof to a specific set of tool calls, but the verifier cannot verify that these tool calls actually occurred.
- **Verbal or written assurances of compliance.** The entire point is to replace trust with proof.

## 3. Policy schema

A policy document is a JSON object containing an array of rules. Three rule types are supported:

```json
{
  "rules": [
    { "type": "deny_tool", "tool": "delete_file" },
    { "type": "param_constraint", "tool": "read_file", "param": "path", "not_prefix": "/etc" },
    { "type": "sequence_constraint", "first": "write_file", "then_deny": "read_file" }
  ]
}
```

**Field definitions:**

- `type` — One of three strings: `"deny_tool"`, `"param_constraint"`, or `"sequence_constraint"`. Encoded as field elements 0, 1, and 2 respectively.
- `tool` — The name of the tool this rule applies to. Encoded by converting each UTF-8 byte to a field element, then computing a Poseidon hash over the byte array (chunked into groups of 15 bytes to stay within the BN128 field size).
- `param` — (param_constraint only) The parameter name to constrain. Encoded identically to `tool`.
- `not_prefix` — (param_constraint only) A path prefix that, if matched, causes the rule to fail. Encoded identically to `tool`.
- `first` — (sequence_constraint only) The tool that, when followed by `then_deny`, triggers a violation. Encoded identically to `tool`.
- `then_deny` — (sequence_constraint only) The tool that must not follow `first`. Encoded identically to `tool`.

Each rule is encoded as a 3-element field vector: `[type, arg1, arg2]`, where:
- `deny_tool`: `[0, tool_hash, 0]`
- `param_constraint`: `[1, tool_hash, Poseidon(tool_hash, param_hash, prefix_hash)]`
- `sequence_constraint`: `[2, first_hash, then_deny_hash]`

## 4. Commitment scheme

The policy commitment is a single field element that binds the proof to a specific policy without revealing its contents.

Construction:

1. Each rule is encoded as a 3-element field vector as described above.
2. Each rule's hash is computed as `Poseidon(rule[0], rule[1], rule[2])`.
3. The rule matrix is padded to exactly 5 rows with zero vectors `[0, 0, 0]`.
4. The policy commitment is `Poseidon(rule_0_hash, rule_1_hash, rule_2_hash, rule_3_hash, rule_4_hash)`.

Poseidon is a zk-friendly hash function designed for efficiency inside arithmetic circuits. It operates natively over the BN128 scalar field (a prime field of order ~2^254), avoiding the bit-decomposition overhead that SHA-256 would require in a circuit context.

## 5. Session log format

Each tool call in the agent's session is a structured record:

```json
{ "tool": "read_file", "params": { "path": "/home/user/notes.txt" } }
```

**Encoding:**

1. The tool name is converted to a field element using the same byte-to-Poseidon encoding as policy rules.
2. Parameters are sorted by key. Each key-value pair is encoded as `Poseidon(key_hash, value_hash)`.
3. Parameter hashes are combined into a single `params_hash` by iteratively hashing groups of up to 5 elements.
4. The entry hash is `Poseidon(tool_hash, params_hash)`.

**Merkle tree:**

The 8-element entry hash array (padded with zeros for unused slots) is arranged as leaves of a binary Merkle tree:

```
         root
        /    \
      h01    h23
      / \    / \
    h0  h1  h2  h3
    /\ /\  /\  /\
   e0 e1 e2 e3 e4 e5 e6 e7
```

Each internal node is `Poseidon(left_child, right_child)`. The root is the **session root**, a public signal that binds the proof to a specific sequence of tool calls.

## 6. Circuit definition

The compliance circuit takes the following inputs:

**Private inputs:**
- `rules[5][3]` — A 5x3 matrix of field elements encoding up to 5 policy rules.
- `log_entries[8]` — An 8-element array of Poseidon hashes, one per tool call (zero-padded).
- `rule_active[5]` — A binary array indicating which rule slots contain real rules (1) vs. padding (0).

**Public inputs:**
- `policy_commitment` — A single field element: the Poseidon hash of all 5 rule hashes.
- `session_root` — A single field element: the Merkle root of the 8 log entries.
- `is_compliant` — A single bit: 1 if compliant, 0 if not.

**Constraints:**

1. **Policy binding.** The circuit recomputes the policy commitment from the private rule matrix and constrains it equal to the public `policy_commitment` input.
2. **Session binding.** The circuit recomputes the Merkle root from the private log entries and constrains it equal to the public `session_root` input.
3. **Compliance.** For each of the 8 log entries and each of the 5 rules, the circuit evaluates the rule against the entry:
   - `deny_tool` (type 0): fails if the entry hash equals `rule_arg1`.
   - `param_constraint` (type 1): fails if the entry hash equals `rule_arg2` (the combined tool+param+prefix hash).
   - `sequence_constraint` (type 2): fails if the previous entry hash equals `rule_arg1` AND the current entry hash equals `rule_arg2`.
4. The product of all 40 check results (8 entries x 5 rules) is constrained equal to `is_compliant`. A single failure zeros the product.

The circuit uses `IsEqual` and `Mux1` from circomlib for field-element comparisons. Total constraint count stays under 50,000.

## 7. Proof scheme

AgentProof uses **groth16**, a zk-SNARK (zero-knowledge Succinct Non-interactive ARgument of Knowledge) scheme. Key properties:

- **Zero-knowledge:** The proof reveals nothing about the private inputs (the policy rules and session log).
- **Succinct:** The proof is constant-size (~200 bytes) regardless of circuit complexity.
- **Non-interactive:** Verification requires no back-and-forth between prover and verifier.

**Implementation:** The proof is generated and verified using [snarkjs](https://github.com/iden3/snarkjs), a JavaScript implementation of groth16 over the BN128 elliptic curve.

**Trusted setup:** groth16 requires a one-time trusted setup ceremony that produces structured reference strings (the proving key and verification key). If the randomness ("toxic waste") used during setup is known to an attacker, they can forge proofs.

This proof-of-concept uses a test ceremony with deterministic entropy (`"agentproof_test_toxic_waste"`). This is explicitly NOT secure for production use. A production deployment would require a multi-party computation ceremony where the toxic waste is destroyed — for example, the Zcash Powers of Tau ceremony or Hermez's trusted setup.

## 8. Limitations

This proof-of-concept demonstrates the cryptographic mechanism. It has hard boundaries on what it proves and what it does not.

**What is proved:** Given a session log and a policy commitment, the log satisfies the policy. The policy commitment binds the proof to a specific set of rules. The session root binds the proof to a specific sequence of tool calls.

**What is NOT proved:**

- **Agent execution binding.** Nothing in this system proves that the agent actually executed under this policy. The prover could fabricate a compliant log. Binding agent execution to the proof — through secure enclaves, attested runtimes, or MCP server-side logging — is out of scope for this proof-of-concept.
- **LLM inference.** The proof covers structured tool call logs, not the language model's reasoning process. Whether the agent "intended" to follow the policy is not a meaningful cryptographic claim.
- **Model identity.** The proof says nothing about which model produced the actions.
- **Prompt contents.** System prompts, user prompts, and conversational context are not included in the proof.

These are deliberate scoping decisions, not oversights. Each represents a real open research problem in verifiable AI systems.

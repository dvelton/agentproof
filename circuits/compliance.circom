pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "circomlib/circuits/bitify.circom";

// Hash a single policy rule (3 field elements) using Poseidon
template RuleHash() {
    signal input rule[3];
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== rule[0];
    hasher.inputs[1] <== rule[1];
    hasher.inputs[2] <== rule[2];
    out <== hasher.out;
}

// Compute Poseidon commitment over all 5 rule hashes
template PolicyCommitment() {
    signal input rules[5][3];
    signal output commitment;

    component ruleHashers[5];
    for (var i = 0; i < 5; i++) {
        ruleHashers[i] = RuleHash();
        for (var j = 0; j < 3; j++) {
            ruleHashers[i].rule[j] <== rules[i][j];
        }
    }

    component commitHasher = Poseidon(5);
    for (var i = 0; i < 5; i++) {
        commitHasher.inputs[i] <== ruleHashers[i].out;
    }
    commitment <== commitHasher.out;
}

// Compute Merkle root from 8 leaves using Poseidon(2) at each node
template MerkleRoot() {
    signal input leaves[8];
    signal output root;

    // Layer 0: 4 hashes from 8 leaves
    component h0[4];
    for (var i = 0; i < 4; i++) {
        h0[i] = Poseidon(2);
        h0[i].inputs[0] <== leaves[2*i];
        h0[i].inputs[1] <== leaves[2*i + 1];
    }

    // Layer 1: 2 hashes from 4 nodes
    component h1[2];
    for (var i = 0; i < 2; i++) {
        h1[i] = Poseidon(2);
        h1[i].inputs[0] <== h0[2*i].out;
        h1[i].inputs[1] <== h0[2*i + 1].out;
    }

    // Layer 2: root from 2 nodes
    component h2 = Poseidon(2);
    h2.inputs[0] <== h1[0].out;
    h2.inputs[1] <== h1[1].out;
    root <== h2.out;
}

// Check a single rule against a single log entry
// Returns 1 if the rule passes (entry is compliant), 0 if it fails
template CheckRule() {
    signal input rule_type;     // 0=deny_tool, 1=param_constraint, 2=sequence_constraint
    signal input rule_arg1;     // tool hash (deny/param) or first tool hash (sequence)
    signal input rule_arg2;     // 0 (deny), combined hash (param), or then_deny hash (seq)
    signal input entry_hash;    // full entry hash (Poseidon of tool+params)
    signal input tool_hash;     // tool name hash only (for deny_tool, sequence matching)
    signal input prev_tool;     // previous entry's tool hash (for sequence rules)
    signal input rule_active;   // 1 if this rule slot is active
    signal output pass;         // 1 if passes, 0 if fails

    // deny_tool: tool matches arg1
    component eq_tool = IsEqual();
    eq_tool.in[0] <== tool_hash;
    eq_tool.in[1] <== rule_arg1;

    // param_constraint: entry matches arg2 (combined tool+param+prefix hash)
    component eq_entry = IsEqual();
    eq_entry.in[0] <== entry_hash;
    eq_entry.in[1] <== rule_arg2;

    // sequence: prev tool matches arg1
    component eq_prev_tool = IsEqual();
    eq_prev_tool.in[0] <== prev_tool;
    eq_prev_tool.in[1] <== rule_arg1;

    // sequence: current tool matches arg2
    component eq_seq_tool = IsEqual();
    eq_seq_tool.in[0] <== tool_hash;
    eq_seq_tool.in[1] <== rule_arg2;

    // Rule type checks
    component is_deny = IsEqual();
    is_deny.in[0] <== rule_type;
    is_deny.in[1] <== 0;

    component is_param = IsEqual();
    is_param.in[0] <== rule_type;
    is_param.in[1] <== 1;

    component is_seq = IsEqual();
    is_seq.in[0] <== rule_type;
    is_seq.in[1] <== 2;

    // deny_tool fails if tool matches arg1
    signal deny_fail <== is_deny.out * eq_tool.out;

    // param_constraint fails if tool matches arg1 AND entry matches arg2
    signal param_tool_match <== is_param.out * eq_tool.out;
    signal param_fail <== param_tool_match * eq_entry.out;

    // sequence_constraint fails if prev_tool matches arg1 AND current tool matches arg2
    signal seq_match <== eq_prev_tool.out * eq_seq_tool.out;
    signal seq_fail <== is_seq.out * seq_match;

    // Total failure: any of the three
    signal fail_01 <== deny_fail + param_fail;
    signal fail_total <== fail_01 + seq_fail;

    // If rule is not active, it always passes
    signal active_fail <== rule_active * fail_total;

    // pass = 1 - active_fail (active_fail is 0 or 1)
    pass <== 1 - active_fail;
}

// Main compliance circuit
template Compliance() {
    // Private inputs
    signal input rules[5][3];
    signal input log_entries[8];
    signal input log_tools[8];
    signal input rule_active[5];

    // Public inputs
    signal input policy_commitment;
    signal input session_root;
    signal input is_compliant;

    // 1. Verify policy commitment matches the provided rules
    component policyCommit = PolicyCommitment();
    for (var i = 0; i < 5; i++) {
        for (var j = 0; j < 3; j++) {
            policyCommit.rules[i][j] <== rules[i][j];
        }
    }
    policyCommit.commitment === policy_commitment;

    // 2. Verify session root matches the log entries
    component merkle = MerkleRoot();
    for (var i = 0; i < 8; i++) {
        merkle.leaves[i] <== log_entries[i];
    }
    merkle.root === session_root;

    // 3. Check every active rule against every log entry
    // compliance_product accumulates: starts at 1, multiplied by each check result
    component checks[8][5];
    signal running_compliance[41]; // 8*5 + 1 = 41 slots
    running_compliance[0] <== 1;

    for (var i = 0; i < 8; i++) {
        for (var j = 0; j < 5; j++) {
            checks[i][j] = CheckRule();
            checks[i][j].rule_type <== rules[j][0];
            checks[i][j].rule_arg1 <== rules[j][1];
            checks[i][j].rule_arg2 <== rules[j][2];
            checks[i][j].entry_hash <== log_entries[i];
            checks[i][j].tool_hash <== log_tools[i];
            if (i == 0) {
                checks[i][j].prev_tool <== 0;
            } else {
                checks[i][j].prev_tool <== log_tools[i-1];
            }
            checks[i][j].rule_active <== rule_active[j];

            var idx = i * 5 + j;
            running_compliance[idx + 1] <== running_compliance[idx] * checks[i][j].pass;
        }
    }

    // Final compliance: 1 if all checks passed, 0 otherwise
    running_compliance[40] === is_compliant;
}

component main {public [policy_commitment, session_root, is_compliant]} = Compliance();

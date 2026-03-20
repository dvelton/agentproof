import * as snarkjs from "snarkjs";
import {
  PolicyDocument,
  compilePolicy,
} from "./policy/compiler";
import { ToolCall, compileLog } from "./agent/log";

export interface ProofResult {
  proof: object;
  publicSignals: string[];
  policyCommitment: string;
  sessionRoot: string;
  isCompliant: boolean;
  provingTimeMs: number;
}

function checkCompliance(
  ruleMatrix: bigint[][],
  activeSlots: number[],
  entryHashes: bigint[]
): boolean {
  for (let i = 0; i < entryHashes.length; i++) {
    for (let j = 0; j < ruleMatrix.length; j++) {
      if (activeSlots[j] === 0) continue;

      const ruleType = ruleMatrix[j][0];
      const ruleArg1 = ruleMatrix[j][1];
      const ruleArg2 = ruleMatrix[j][2];
      const entry = entryHashes[i];
      const prevEntry = i > 0 ? entryHashes[i - 1] : BigInt(0);

      if (ruleType === BigInt(0)) {
        // deny_tool: fails if entry matches arg1
        if (entry === ruleArg1) return false;
      } else if (ruleType === BigInt(1)) {
        // param_constraint: fails if entry matches arg2
        if (entry === ruleArg2) return false;
      } else if (ruleType === BigInt(2)) {
        // sequence_constraint: fails if prev matches arg1 AND current matches arg2
        if (prevEntry === ruleArg1 && entry === ruleArg2) return false;
      }
    }
  }
  return true;
}

export async function prove(
  policy: PolicyDocument,
  session: ToolCall[],
  wasmPath: string,
  zkeyPath: string
): Promise<ProofResult> {
  const startTime = Date.now();

  const compiledPolicy = await compilePolicy(policy);
  const compiledLog = await compileLog(session);

  const isCompliant = checkCompliance(
    compiledPolicy.ruleMatrix,
    compiledPolicy.activeSlots,
    compiledLog.entryHashes
  );

  // Build witness input
  const input: Record<string, string | string[] | string[][]> = {
    // Private inputs
    rules: compiledPolicy.ruleMatrix.map((row) =>
      row.map((v) => v.toString())
    ),
    log_entries: compiledLog.entryHashes.map((v) => v.toString()),
    rule_active: compiledPolicy.activeSlots.map((v) => v.toString()),

    // Public inputs
    policy_commitment: compiledPolicy.commitment.toString(),
    session_root: compiledLog.root.toString(),
    is_compliant: isCompliant ? "1" : "0",
  };

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    wasmPath,
    zkeyPath
  );

  const provingTimeMs = Date.now() - startTime;

  return {
    proof,
    publicSignals,
    policyCommitment: "0x" + BigInt(publicSignals[0]).toString(16),
    sessionRoot: "0x" + BigInt(publicSignals[1]).toString(16),
    isCompliant,
    provingTimeMs,
  };
}

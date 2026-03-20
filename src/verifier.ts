import * as snarkjs from "snarkjs";
import * as fs from "fs";

export interface VerificationResult {
  valid: boolean;
  policyCommitment: string;
  sessionRoot: string;
  isCompliant: boolean;
}

export async function verify(
  proof: object,
  publicSignals: string[],
  verificationKeyPath: string
): Promise<VerificationResult> {
  const vkeyRaw = fs.readFileSync(verificationKeyPath, "utf-8");
  const vkey = JSON.parse(vkeyRaw);

  const valid = await snarkjs.groth16.verify(vkey, publicSignals, proof);

  return {
    valid,
    policyCommitment: "0x" + BigInt(publicSignals[0]).toString(16),
    sessionRoot: "0x" + BigInt(publicSignals[1]).toString(16),
    isCompliant: publicSignals[2] === "1",
  };
}

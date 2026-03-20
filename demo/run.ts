import * as path from "path";
import { PolicyDocument } from "../src/policy/compiler";
import { ToolCall } from "../src/agent/log";
import { prove, ProofResult } from "../src/prover";
import { verify, VerificationResult } from "../src/verifier";

const ARTIFACTS_DIR = path.join(__dirname, "..", "docs", "artifacts");
const WASM_PATH = path.join(ARTIFACTS_DIR, "compliance.wasm");
const ZKEY_PATH = path.join(ARTIFACTS_DIR, "compliance_final.zkey");
const VKEY_PATH = path.join(ARTIFACTS_DIR, "verification_key.json");

const policy: PolicyDocument = {
  rules: [
    { type: "deny_tool", tool: "delete_file" },
    {
      type: "param_constraint",
      tool: "read_file",
      param: "path",
      not_prefix: "/etc",
    },
  ],
};

const sessionA: ToolCall[] = [
  { tool: "list_dir", params: { path: "/home/user" } },
  { tool: "read_file", params: { path: "/home/user/notes.txt" } },
  { tool: "write_file", params: { path: "/tmp/output.txt", content: "hello" } },
];

const sessionB: ToolCall[] = [
  { tool: "list_dir", params: { path: "/etc" } },
  { tool: "read_file", params: { path: "/etc/passwd" } },
  { tool: "delete_file", params: { path: "/important/data.txt" } },
];

function printSeparator(): void {
  console.log("\u2550".repeat(55));
}

function formatProofSize(proof: object): number {
  return Buffer.byteLength(JSON.stringify(proof), "utf-8");
}

async function runSession(
  name: string,
  session: ToolCall[],
  expectedCompliant: boolean
): Promise<void> {
  printSeparator();
  console.log(
    `  Session ${name}: ${expectedCompliant ? "Compliant" : "Violating"}`
  );
  printSeparator();
  console.log("");

  console.log("  PROVER KNOWS:");
  console.log("    Policy: deny delete_file, constrain read_file path prefix");
  console.log(
    `    Session: ${session.length} tool calls (${session
      .map((c) => c.tool)
      .join(", ")})`
  );
  console.log("");

  let proofResult: ProofResult;
  try {
    proofResult = await prove(policy, session, WASM_PATH, ZKEY_PATH);
  } catch (err) {
    console.log(`  PROOF GENERATION FAILED: ${err}`);
    printSeparator();
    console.log("");
    return;
  }

  console.log(`  PROOF GENERATED in ${proofResult.provingTimeMs}ms`);
  console.log(`  Proof size: ${formatProofSize(proofResult.proof)} bytes`);
  console.log("");

  let verifyResult: VerificationResult;
  try {
    verifyResult = await verify(
      proofResult.proof,
      proofResult.publicSignals,
      VKEY_PATH
    );
  } catch (err) {
    console.log(`  VERIFICATION FAILED: ${err}`);
    printSeparator();
    console.log("");
    return;
  }

  console.log("  VERIFIER KNOWS ONLY:");
  console.log(`    Policy commitment : ${verifyResult.policyCommitment}`);
  console.log(`    Session root      : ${verifyResult.sessionRoot}`);
  console.log(
    `    Is compliant      : ${
      verifyResult.isCompliant ? "\u2713 YES" : "\u2717 NOT COMPLIANT"
    }`
  );
  console.log("");
  console.log(
    `  VERIFICATION: ${
      verifyResult.valid ? "\u2713 PROOF VALID" : "\u2717 PROOF INVALID"
    }`
  );
  console.log("");
  console.log(
    "  The verifier cannot reconstruct the policy from the above values."
  );
  printSeparator();
  console.log("");
}

async function main(): Promise<void> {
  console.log("");
  console.log("  AgentProof Demo");
  console.log(
    "  Zero-knowledge verification of AI agent policy compliance"
  );
  console.log("");

  await runSession("A", sessionA, true);
  await runSession("B", sessionB, false);
}

main().catch((err) => {
  console.error("Demo failed:", err);
  process.exit(1);
});

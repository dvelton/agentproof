import { buildPoseidon, Poseidon } from "circomlibjs";

export interface PolicyRule {
  type: "deny_tool" | "param_constraint" | "sequence_constraint";
  tool?: string;
  param?: string;
  not_prefix?: string;
  first?: string;
  then_deny?: string;
}

export interface PolicyDocument {
  rules: PolicyRule[];
}

export interface CompiledPolicy {
  ruleMatrix: bigint[][];
  commitment: bigint;
  activeSlots: number[];
}

const RULE_TYPE_MAP: Record<string, bigint> = {
  deny_tool: BigInt(0),
  param_constraint: BigInt(1),
  sequence_constraint: BigInt(2),
};

const MAX_RULES = 5;

let poseidonInstance: Poseidon | null = null;

async function getPoseidon(): Promise<Poseidon> {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
  }
  return poseidonInstance;
}

function poseidonHash(poseidon: Poseidon, inputs: bigint[]): bigint {
  const hash = poseidon(inputs.map((x) => x));
  return poseidon.F.toObject(hash);
}

export function stringToFieldElement(
  poseidon: Poseidon,
  s: string
): bigint {
  if (!s || s.length === 0) return BigInt(0);
  const bytes = Buffer.from(s, "utf-8");
  const elements: bigint[] = [];
  // Hash in chunks of 15 bytes (field element safe size)
  for (let i = 0; i < bytes.length; i += 15) {
    let val = BigInt(0);
    for (let j = 0; j < 15 && i + j < bytes.length; j++) {
      val = val + BigInt(bytes[i + j]) * (BigInt(256) ** BigInt(j));
    }
    elements.push(val);
  }
  if (elements.length === 1) return elements[0];
  // Hash multiple chunks together, in groups of up to 5 (Poseidon limit)
  while (elements.length > 1) {
    const newElements: bigint[] = [];
    for (let i = 0; i < elements.length; i += 5) {
      const chunk = elements.slice(i, Math.min(i + 5, elements.length));
      while (chunk.length < 2) chunk.push(BigInt(0));
      newElements.push(poseidonHash(poseidon, chunk));
    }
    elements.length = 0;
    elements.push(...newElements);
  }
  return elements[0];
}

function encodeRule(
  poseidon: Poseidon,
  rule: PolicyRule
): bigint[] {
  const typeVal = RULE_TYPE_MAP[rule.type];

  switch (rule.type) {
    case "deny_tool": {
      const toolHash = stringToFieldElement(poseidon, rule.tool || "");
      return [typeVal, toolHash, BigInt(0)];
    }
    case "param_constraint": {
      const toolHash = stringToFieldElement(poseidon, rule.tool || "");
      // Combine tool+param+prefix into a single entry hash that matches
      // what a violating log entry would produce
      const paramHash = stringToFieldElement(poseidon, rule.param || "");
      const prefixHash = stringToFieldElement(poseidon, rule.not_prefix || "");
      const combinedHash = poseidonHash(poseidon, [toolHash, paramHash, prefixHash]);
      return [typeVal, toolHash, combinedHash];
    }
    case "sequence_constraint": {
      const firstHash = stringToFieldElement(poseidon, rule.first || "");
      const thenDenyHash = stringToFieldElement(poseidon, rule.then_deny || "");
      return [typeVal, firstHash, thenDenyHash];
    }
    default:
      return [BigInt(0), BigInt(0), BigInt(0)];
  }
}

export async function compilePolicy(
  doc: PolicyDocument
): Promise<CompiledPolicy> {
  const poseidon = await getPoseidon();

  if (doc.rules.length > MAX_RULES) {
    throw new Error(`Maximum ${MAX_RULES} rules supported, got ${doc.rules.length}`);
  }

  const ruleMatrix: bigint[][] = [];
  const activeSlots: number[] = [];

  for (let i = 0; i < MAX_RULES; i++) {
    if (i < doc.rules.length) {
      ruleMatrix.push(encodeRule(poseidon, doc.rules[i]));
      activeSlots.push(1);
    } else {
      ruleMatrix.push([BigInt(0), BigInt(0), BigInt(0)]);
      activeSlots.push(0);
    }
  }

  // Compute commitment: Poseidon(hash(rule0), hash(rule1), ..., hash(rule4))
  const ruleHashes = ruleMatrix.map((rule) => poseidonHash(poseidon, rule));
  const commitment = poseidonHash(poseidon, ruleHashes);

  return { ruleMatrix, commitment, activeSlots };
}

export { getPoseidon, poseidonHash };

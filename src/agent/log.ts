import { buildPoseidon, Poseidon } from "circomlibjs";

export interface ToolCall {
  tool: string;
  params: Record<string, string>;
}

export interface CompiledLog {
  entryHashes: bigint[];
  toolHashes: bigint[];
  root: bigint;
  paths: bigint[][];
}

const MAX_ENTRIES = 8;

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

function stringToFieldElement(poseidon: Poseidon, s: string): bigint {
  if (!s || s.length === 0) return BigInt(0);
  const bytes = Buffer.from(s, "utf-8");
  const elements: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 15) {
    let val = BigInt(0);
    for (let j = 0; j < 15 && i + j < bytes.length; j++) {
      val = val + BigInt(bytes[i + j]) * (BigInt(256) ** BigInt(j));
    }
    elements.push(val);
  }
  if (elements.length === 1) return elements[0];
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

function hashToolCall(poseidon: Poseidon, call: ToolCall): bigint {
  const toolHash = stringToFieldElement(poseidon, call.tool);

  // Hash params: sort keys, hash each key-value pair, then combine
  const paramKeys = Object.keys(call.params).sort();
  if (paramKeys.length === 0) {
    return poseidonHash(poseidon, [toolHash, BigInt(0)]);
  }

  const paramElements: bigint[] = [];
  for (const key of paramKeys) {
    const keyHash = stringToFieldElement(poseidon, key);
    const valHash = stringToFieldElement(poseidon, call.params[key]);
    paramElements.push(poseidonHash(poseidon, [keyHash, valHash]));
  }

  // Combine all param hashes
  let paramsHash: bigint;
  if (paramElements.length === 1) {
    paramsHash = paramElements[0];
  } else {
    while (paramElements.length > 1) {
      const newElements: bigint[] = [];
      for (let i = 0; i < paramElements.length; i += 5) {
        const chunk = paramElements.slice(
          i,
          Math.min(i + 5, paramElements.length)
        );
        while (chunk.length < 2) chunk.push(BigInt(0));
        newElements.push(poseidonHash(poseidon, chunk));
      }
      paramElements.length = 0;
      paramElements.push(...newElements);
    }
    paramsHash = paramElements[0];
  }

  return poseidonHash(poseidon, [toolHash, paramsHash]);
}

function buildMerkleTree(
  poseidon: Poseidon,
  leaves: bigint[]
): { root: bigint; layers: bigint[][] } {
  const layers: bigint[][] = [leaves.slice()];
  let current = leaves.slice();

  while (current.length > 1) {
    const next: bigint[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : BigInt(0);
      next.push(poseidonHash(poseidon, [left, right]));
    }
    layers.push(next);
    current = next;
  }

  return { root: current[0], layers };
}

function getMerklePaths(layers: bigint[][], index: number): bigint[] {
  const path: bigint[] = [];
  let idx = index;
  // 3 layers for 8 leaves (depth = log2(8) = 3)
  for (let level = 0; level < 3; level++) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    const sibling =
      siblingIdx < layers[level].length ? layers[level][siblingIdx] : BigInt(0);
    path.push(sibling);
    idx = Math.floor(idx / 2);
  }
  return path;
}

export async function compileLog(calls: ToolCall[]): Promise<CompiledLog> {
  const poseidon = await getPoseidon();

  if (calls.length > MAX_ENTRIES) {
    throw new Error(
      `Maximum ${MAX_ENTRIES} log entries supported, got ${calls.length}`
    );
  }

  // Hash each tool call
  const entryHashes: bigint[] = [];
  const toolHashes: bigint[] = [];
  for (let i = 0; i < MAX_ENTRIES; i++) {
    if (i < calls.length) {
      entryHashes.push(hashToolCall(poseidon, calls[i]));
      toolHashes.push(stringToFieldElement(poseidon, calls[i].tool));
    } else {
      entryHashes.push(BigInt(0));
      toolHashes.push(BigInt(0));
    }
  }

  // Build Merkle tree
  const { root, layers } = buildMerkleTree(poseidon, entryHashes);

  // Extract paths for each entry
  const paths: bigint[][] = [];
  for (let i = 0; i < MAX_ENTRIES; i++) {
    paths.push(getMerklePaths(layers, i));
  }

  return { entryHashes, toolHashes, root, paths };
}

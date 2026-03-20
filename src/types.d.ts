declare module "circomlibjs" {
  export interface Poseidon {
    (inputs: any[]): any;
    F: {
      toObject(val: any): bigint;
    };
  }
  export function buildPoseidon(): Promise<Poseidon>;
}

declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, any>,
      wasmPath: string,
      zkeyPath: string
    ): Promise<{ proof: any; publicSignals: string[] }>;

    function verify(
      vkey: any,
      publicSignals: string[],
      proof: any
    ): Promise<boolean>;
  }
}

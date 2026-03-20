#!/usr/bin/env bash
set -euo pipefail

ARTIFACTS_DIR="docs/artifacts"
CIRCUIT_DIR="circuits"
CIRCUIT_NAME="compliance"
PTAU_SIZE=15
PTAU_FILE="powersOfTau28_hez_final_${PTAU_SIZE}.ptau"
PTAU_URL="https://storage.googleapis.com/zkevm/ptau/${PTAU_FILE}"

# Check for --force flag
FORCE=false
for arg in "$@"; do
    if [ "$arg" = "--force" ]; then
        FORCE=true
    fi
done

# Skip if already built (unless --force)
if [ -f "${ARTIFACTS_DIR}/${CIRCUIT_NAME}.wasm" ] && [ "$FORCE" = false ]; then
    echo "Artifacts already built. Use --force to rebuild."
    exit 0
fi

echo "=== AgentProof Circuit Build ==="
echo ""

# Check for circom
if ! command -v circom &> /dev/null; then
    echo "circom not found. Attempting install via cargo..."
    if command -v cargo &> /dev/null; then
        cargo install --git https://github.com/iden3/circom.git --tag v2.1.9
    else
        echo "ERROR: Neither circom nor cargo found."
        echo "Install circom: https://docs.circom.io/getting-started/installation/"
        exit 1
    fi
fi

# Check for snarkjs
if ! command -v snarkjs &> /dev/null; then
    echo "snarkjs not found. Installing globally..."
    npm install -g snarkjs
fi

# Install npm dependencies (for circomlib)
echo "Installing dependencies..."
npm install --quiet

# Create artifacts directory
mkdir -p "${ARTIFACTS_DIR}"

# Compile the circuit
echo "Compiling circuit..."
circom "${CIRCUIT_DIR}/${CIRCUIT_NAME}.circom" \
    --r1cs \
    --wasm \
    --sym \
    --output "${ARTIFACTS_DIR}" \
    -l node_modules

echo "Circuit compiled. Constraints:"
snarkjs r1cs info "${ARTIFACTS_DIR}/${CIRCUIT_NAME}.r1cs"

# Download Powers of Tau if not present
if [ ! -f "${PTAU_FILE}" ]; then
    echo "Downloading Powers of Tau (2^${PTAU_SIZE})..."
    curl -L -o "${PTAU_FILE}" "${PTAU_URL}"
fi

# groth16 setup
echo "Running groth16 setup..."
snarkjs groth16 setup \
    "${ARTIFACTS_DIR}/${CIRCUIT_NAME}.r1cs" \
    "${PTAU_FILE}" \
    "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_0000.zkey"

# Contribute to ceremony (test toxic waste — NOT production safe)
echo "Contributing to ceremony (TEST TOXIC WASTE — NOT PRODUCTION SAFE)..."
snarkjs zkey contribute \
    "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_0000.zkey" \
    "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_final.zkey" \
    --name="agentproof_test" \
    -v \
    -e="agentproof_test_toxic_waste"

# Export verification key
echo "Exporting verification key..."
snarkjs zkey export verificationkey \
    "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_final.zkey" \
    "${ARTIFACTS_DIR}/verification_key.json"

# Move wasm to expected location
if [ -d "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_js" ]; then
    cp "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm" "${ARTIFACTS_DIR}/${CIRCUIT_NAME}.wasm" 2>/dev/null || true
fi

# Clean up intermediate files
rm -f "${ARTIFACTS_DIR}/${CIRCUIT_NAME}_0000.zkey"

echo ""
echo "Build complete. Artifacts in ${ARTIFACTS_DIR}/"
echo "  - ${CIRCUIT_NAME}.wasm"
echo "  - ${CIRCUIT_NAME}_final.zkey"
echo "  - verification_key.json"
echo ""
echo "WARNING: Trusted setup used test toxic waste. NOT production safe."

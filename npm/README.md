# DSLRS (TypeScript / Node.js)

**Deanonymizable Scope-Linked Ring Signature (DSLRS)** implemented in TypeScript on the `secp256k1` elliptic curve via `@noble/curves`.

## Features

- **Dual ESM & CommonJS Support**: Ships with `.js` (ESM), `.cjs` (CommonJS), and `.d.ts` TypeScript declarations.
- **Ring Anonymity**: Sign messages anonymously within a ring of public keys $L$.
- **Scope-Bound Linkability**: Signatures from the same signer under the same `SID` share a scope tag $I_{\text{scope}}$, enabling linkability within a scope while preserving unlinkability across different scopes.
- **Threshold Traceability (Deanonymization)**: A $(k, N)$ Shamir secret-shared network can collaboratively recover the signer's public key $P_s$.

## Installation

```bash
npm install dslrs
```

## Quick Start

```typescript
import { DSLRS, KeyPair, RingSignature } from "dslrs";

// Initialize DSLRS (default: k=8 of N=12 threshold network)
const scheme = new DSLRS({ nMin: 3, nNodes: 12, threshold: 8 });

// 1. KeyGen
const keys: KeyPair[] = Array.from({ length: 5 }, () => scheme.keygen());
const ring = keys.map((kp) => kp.publicKey);

// 2. Sign
const signer = keys[1];
const sig1: RingSignature | null = scheme.sign("Consent_proof_V1", signer, ring, "SID_PROJECT_A");
const sig2: RingSignature | null = scheme.sign("Consent_proof_V2", signer, ring, "SID_PROJECT_A");
const sig3: RingSignature | null = scheme.sign("Consent_proof_V3", signer, ring, "SID_PROJECT_B");

// 3. Verify
console.log("Valid:", scheme.verify("Consent_proof_V1", sig1)); // true

// 4. Link
console.log("Same SID linked:", scheme.link(sig1, "Consent_proof_V1", sig2, "Consent_proof_V2")); // true
console.log("Diff SID linked:", scheme.link(sig1, "Consent_proof_V1", sig3, "Consent_proof_V3")); // false

// 5. Trace / Deanonymize
const { D_list, omega_list } = scheme.computeDecryptionShares(sig1!, scheme.shares.slice(0, 8));
const recoveredPk = scheme.trace(sig1!, D_list, omega_list);
console.log("Traced signer matches:", recoveredPk.equals(signer.publicKey)); // true
```

## License

Apache-2.0

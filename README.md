# DSLRS — Deanonymizable Scoped Linkable Ring Signatures

[![CI](https://github.com/montassar-isbored/DSLRS-packages/actions/workflows/ci.yml/badge.svg)](https://github.com/montassar-isbored/DSLRS-packages/actions/workflows/ci.yml)
[![Release](https://github.com/montassar-isbored/DSLRS-packages/actions/workflows/release.yml/badge.svg)](https://github.com/montassar-isbored/DSLRS-packages/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

**DSLRS** is a dual-target cryptographic library (Python & TypeScript/Node.js) implementing **Deanonymizable Scoped Linkable Ring Signatures** over the `secp256k1` elliptic curve.

---

## Repository Structure

```text
├── .github/workflows/
│   ├── ci.yml                 # Automated testing for both Python and Node.js
│   └── release.yml            # Automated publishing to PyPI & npm on Git tag
├── python/                    # Python package root (PEP 621 / Hatchling)
│   ├── src/dslrs/
│   │   ├── __init__.py        # Top-level exports (__all__)
│   │   ├── core.py            # KeyGen, Sign, Verify, Link, Trace
│   │   └── utils.py           # Curve & Shamir secret sharing utilities
│   ├── tests/
│   │   └── test_dslrs.py      # pytest test suite
│   ├── pyproject.toml
│   └── README.md
├── npm/                       # NPM package root (TypeScript / tsup / Vitest)
│   ├── src/
│   │   ├── index.ts           # Public API and types export
│   │   └── dslrs.ts           # secp256k1 implementation via @noble/curves
│   ├── tests/
│   │   └── dslrs.test.ts      # Vitest test suite
│   ├── package.json           # Dual ESM/CJS exports and metadata
│   ├── tsconfig.json
│   ├── tsup.config.ts
│   └── README.md
├── README.md                  # Unified root documentation
└── LICENSE                    # Apache-2.0 License
```

---

## Protocol Overview

DSLRS consists of five core operations over `secp256k1` (generator $G$, prime order $q$):

1. **KeyGen**: Generates a user key pair $(S_s, P_s = S_s \cdot G)$ and $(k, N)$ Shamir secret shares of the network tracing secret $S_{\text{net}}$ with public key $P_{\text{net}} = S_{\text{net}} \cdot G$.
2. **Sign**: Given message $m$, signer secret $S_s$, ring $L = \{P_0, \dots, P_{n-1}\}$, and Scope ID $\text{SID}$, computes a scope-bound tag $I_{\text{scope}} = S_s \cdot H_p(P_s, \text{SID})$, an ElGamal encryption $(C_1, C_2)$ of $P_s$ under $P_{\text{net}}$, and a non-interactive ring proof $\sigma = (I_{\text{scope}}, L, \text{SID}, P_{\text{net}}, C_1, C_2, ch_0, \mathbf{x}, \mathbf{z})$.
3. **Verify**: Verifies the ring equations around the challenge loop $ch_0, \dots, ch_{n-1}$ in $O(n)$ curve operations without revealing which ring member signed.
4. **Link**: Given two valid signatures $\sigma_1, \sigma_2$ under the same $\text{SID}$, checks whether $\sigma_1.I_{\text{scope}} = \sigma_2.I_{\text{scope}}$.
5. **Trace (Deanonymize)**: Given $k$-of-$N$ partial decryption shares $D_j = S_{\text{net},j} \cdot C_1$, reconstructs $V = \sum_{j=1}^k \lambda_j D_j$ via Lagrange interpolation in the exponent and recovers $P_s = C_2 - V$.

---

## Installation & Usage

### Python (`python/`)

```bash
pip install -e "python/.[dev]"
```

```python
from dslrs import DSLRS, KeyPair, RingSignature

scheme = DSLRS(n_min=3, n_nodes=12, threshold=8)
keys = [scheme.keygen() for _ in range(5)]
ring = [kp.public_key for kp in keys]

sig1 = scheme.sign("Consent_proof_V1", keys[1], ring, "SID_PROJECT_A")
sig2 = scheme.sign("Consent_proof_V2", keys[1], ring, "SID_PROJECT_A")

assert scheme.verify("Consent_proof_V1", sig1)
assert scheme.link(sig1, "Consent_proof_V1", sig2, "Consent_proof_V2")
assert scheme.trace(sig1) == keys[1].public_key
```

### Node.js / TypeScript (`npm/`)

```bash
cd npm && npm install
```

```typescript
import { DSLRS } from "dslrs";

const scheme = new DSLRS({ nMin: 3, nNodes: 12, threshold: 8 });
const keys = Array.from({ length: 5 }, () => scheme.keygen());
const ring = keys.map((kp) => kp.publicKey);

const sig1 = scheme.sign("Consent_proof_V1", keys[1], ring, "SID_PROJECT_A")!;
const sig2 = scheme.sign("Consent_proof_V2", keys[1], ring, "SID_PROJECT_A")!;

console.log(scheme.verify("Consent_proof_V1", sig1)); // true
console.log(scheme.link(sig1, "Consent_proof_V1", sig2, "Consent_proof_V2")); // true
console.log(scheme.trace(sig1).equals(keys[1].publicKey)); // true
```

---

## Verification & Build

### Python

```bash
pip install -e "python/.[dev]" && pytest python/tests/ && python -m build python/
```

### NPM

```bash
cd npm && npm install && npm test && npm run build && npm pack --dry-run && cd ..
```

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).

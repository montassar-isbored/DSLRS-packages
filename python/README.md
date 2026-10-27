# DSLRS (Python)

**Deanonymizable Scoped Linkable Ring Signatures (DSLRS)** implemented on the `secp256k1` elliptic curve.

DSLRS provides:
- **Ring Anonymity**: Sign messages anonymously on behalf of a ring of public keys $L$.
- **Scope-Bound Linkability**: Signatures produced by the same signer under the same Scope Identifier (`SID`) share a deterministic scope tag $I_{\text{scope}} = S_s \cdot H_p(P_s, \text{SID})$, enabling double-signing detection within a scope while remaining unlinkable across different scopes.
- **Threshold Traceability (Deanonymization)**: A $(k, N)$ Shamir secret-shared authority network can collaboratively recover the signer's public key $P_s$ via Lagrange interpolation in the exponent.

## Installation

```bash
pip install dslrs
```

For local development:

```bash
pip install -e "python/.[dev]"
```

## Quick Start

```python
from dslrs import DSLRS, KeyPair, RingSignature

# Initialize DSLRS parameters (default: k=8 of N=12 threshold network)
scheme = DSLRS(n_min=3, n_nodes=12, threshold=8)

# 1. KeyGen: Generate ring member keys
keys: list[KeyPair] = [scheme.keygen() for _ in range(5)]
ring = [kp.public_key for kp in keys]

# 2. Sign: Member 1 signs two messages in SID_PROJECT_A and one in SID_PROJECT_B
signer = keys[1]
sig1: RingSignature = scheme.sign("Consent_proof_V1", signer, ring, "SID_PROJECT_A")
sig2: RingSignature = scheme.sign("Consent_proof_V2", signer, ring, "SID_PROJECT_A")
sig3: RingSignature = scheme.sign("Consent_proof_V3", signer, ring, "SID_PROJECT_B")

# 3. Verify
assert scheme.verify("Consent_proof_V1", sig1) is True

# 4. Link: Same signer + same SID => linked; different SID => unlinked
assert scheme.link(sig1, "Consent_proof_V1", sig2, "Consent_proof_V2") is True
assert scheme.link(sig1, "Consent_proof_V1", sig3, "Consent_proof_V3") is False

# 5. Trace / Deanonymize: Threshold k-of-N authority nodes recover P_s
D_list, omega_list = scheme.compute_decryption_shares(sig1, scheme.shares[:8])
recovered_pk = scheme.trace(sig1, D_list, omega_list)
assert recovered_pk == signer.public_key
```

## License

Apache-2.0

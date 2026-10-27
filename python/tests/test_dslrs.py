from __future__ import annotations

import random

import dslrs
from dslrs import DSLRS, KeyPair, RingSignature
from dslrs.core import SystemParameters, deanonymize, keygen, link, sign, trace, verify
from dslrs.utils import generate_shares, get_signature_size_bytes, hash_to_point, point_to_str


def test_exports() -> None:
    assert dslrs.__all__ == ["DSLRS", "KeyPair", "RingSignature"]
    assert hasattr(dslrs, "DSLRS")
    assert hasattr(dslrs, "KeyPair")
    assert hasattr(dslrs, "RingSignature")


def test_keygen() -> None:
    scheme = DSLRS()
    kp = scheme.keygen()
    assert isinstance(kp, KeyPair)
    assert 1 <= kp.secret_key < scheme.q
    assert kp.public_key == kp.secret_key * scheme.G

    sk, pk = kp
    assert sk == kp.secret_key
    assert pk == kp.public_key


def test_sign_and_verify() -> None:
    scheme = DSLRS(n_min=3, n_nodes=6, threshold=4)
    keypairs = [scheme.keygen() for _ in range(5)]
    ring = [kp.public_key for kp in keypairs]
    scheme.register_ring(ring)

    signer = keypairs[2]
    msg = "Consent_proof_V1"
    sid = "SID_PROJECT_A"

    sig = scheme.sign(msg, signer.secret_key, ring, sid)
    assert sig is not None
    assert isinstance(sig, RingSignature)
    assert len(sig) == 9
    assert sig.SID == sid
    assert sig.size_bytes == get_signature_size_bytes(5)

    assert scheme.verify(msg, sig) is True
    assert scheme.verify("Wrong_message", sig) is False


def test_sign_preconditions() -> None:
    pp = SystemParameters(n_min=3)
    keys = [keygen(pp) for _ in range(4)]
    ring = [kp.public_key for kp in keys]
    outsider = keygen(pp)

    # Ring not registered in strict SystemParameters
    assert sign("msg", keys[0].secret_key, ring, "SID_PROJECT_A", pp) is None

    pp.L_registry.append(ring)

    # Signer not in ring
    assert sign("msg", outsider.secret_key, ring, "SID_PROJECT_A", pp) is None

    # Invalid SID
    assert sign("msg", keys[0].secret_key, ring, "UNKNOWN_SID", pp) is None

    # Ring smaller than n_min
    small_ring = ring[:2]
    pp.L_registry.append(small_ring)
    assert sign("msg", keys[0].secret_key, small_ring, "SID_PROJECT_A", pp) is None


def test_linkability_same_and_different_scopes() -> None:
    scheme = DSLRS()
    keypairs = [scheme.keygen() for _ in range(4)]
    ring = [kp.public_key for kp in keypairs]

    signer_a = keypairs[0]
    signer_b = keypairs[1]

    sig_a1 = scheme.sign("Message_1", signer_a, ring, "SID_PROJECT_A")
    sig_a2 = scheme.sign("Message_2", signer_a, ring, "SID_PROJECT_A")
    sig_a_diff_sid = scheme.sign("Message_3", signer_a, ring, "SID_PROJECT_B")
    sig_b1 = scheme.sign("Message_4", signer_b, ring, "SID_PROJECT_A")

    assert sig_a1 is not None
    assert sig_a2 is not None
    assert sig_a_diff_sid is not None
    assert sig_b1 is not None

    # Same signer, same SID -> Linked (both 4-arg and 2-arg)
    assert scheme.link(sig_a1, "Message_1", sig_a2, "Message_2") is True
    assert scheme.link(sig_a1, sig_a2) is True

    # Same signer, different SID -> Unlinked
    assert scheme.link(sig_a1, "Message_1", sig_a_diff_sid, "Message_3") is False
    assert scheme.link(sig_a1, sig_a_diff_sid) is False

    # Different signers, same SID -> Unlinked
    assert scheme.link(sig_a1, "Message_1", sig_b1, "Message_4") is False
    assert scheme.link(sig_a1, sig_b1) is False


def test_threshold_trace_deanonymize() -> None:
    scheme = DSLRS(n_nodes=8, threshold=5)
    keypairs = [scheme.keygen() for _ in range(6)]
    ring = [kp.public_key for kp in keypairs]

    signer_idx = 3
    signer = keypairs[signer_idx]
    sig = scheme.sign("Audit_Payload", signer, ring, "SID_PROJECT_A")
    assert sig is not None

    # Sample k-of-N shares randomly
    sampled_shares = random.sample(scheme.shares, scheme.k)
    D_list, omega_list = scheme.compute_decryption_shares(sig, sampled_shares)

    recovered_pk = scheme.trace(sig, D_list, omega_list)
    assert recovered_pk == signer.public_key
    assert point_to_str(recovered_pk) == point_to_str(signer.public_key)

    # Also test convenience 1-argument trace() and deanonymize()
    assert scheme.trace(sig) == signer.public_key
    assert scheme.deanonymize(sig, sampled_shares) == signer.public_key


def test_functional_api_compatibility() -> None:
    pp = SystemParameters()
    all_shares = generate_shares(pp.S_net, 6, 4, pp.q)
    keys = [keygen(pp) for _ in range(4)]
    ring = [kp.public_key for kp in keys]
    pp.L_registry.append(ring)

    m1 = "Doc_1"
    m2 = "Doc_2"
    sid = pp.SIDs[0]

    sigma1 = sign(m1, keys[1].secret_key, ring, sid, pp)
    sigma2 = sign(m2, keys[1].secret_key, ring, sid, pp)
    assert sigma1 is not None and sigma2 is not None

    assert verify(m1, sigma1, pp) == 1
    assert link(sigma1, m1, sigma2, m2, pp) == 1

    responding = all_shares[:4]
    omega_list = [node["omega"] for node in responding]
    D_list = [node["S_net_j"] * sigma1[4] for node in responding]

    extracted = deanonymize(sigma1, D_list, omega_list, pp.q)
    assert extracted == trace(sigma1, D_list, omega_list, pp.q)
    assert extracted == keys[1].public_key


def test_hash_to_point_deterministic() -> None:
    kp = DSLRS.keygen()
    p1 = hash_to_point(kp.public_key, "SID_PROJECT_A")
    p2 = hash_to_point(kp.public_key, "SID_PROJECT_A")
    p3 = hash_to_point(kp.public_key, "SID_PROJECT_B")
    assert p1 == p2
    assert p1 != p3

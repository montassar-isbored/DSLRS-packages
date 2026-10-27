from __future__ import annotations

import hashlib
import secrets
from typing import Any

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY, CurveFp, Point

CURVE: CurveFp = SECP256k1.curve
GENERATOR: Point = SECP256k1.generator
ORDER: int = SECP256k1.order
FIELD_PRIME: int = CURVE.p()
CURVE_A: int = CURVE.a()
CURVE_B: int = CURVE.b()


def point_to_str(pt: Point) -> str:
    """Serialize an elliptic curve point to its canonical string representation."""
    if pt == INFINITY:
        return "INFINITY"
    x_val = pt.x() if callable(pt.x) else pt.x
    y_val = pt.y() if callable(pt.y) else pt.y
    return f"{x_val},{y_val}"


def is_valid_point(pt: Any, curve: CurveFp = CURVE) -> bool:
    """Check whether pt is a valid non-infinity point on the elliptic curve group G."""
    if pt is None or pt == INFINITY:
        return False
    if not (hasattr(pt, "x") and hasattr(pt, "y")):
        return False
    try:
        x_val = pt.x() if callable(pt.x) else pt.x
        y_val = pt.y() if callable(pt.y) else pt.y
        return bool(curve.contains_point(x_val, y_val))
    except Exception:
        return False


def sub_points(P1: Point, P2: Point, q: int = ORDER) -> Point:
    """Compute elliptic curve point subtraction P1 - P2 = P1 + (q - 1) * P2."""
    if P2 == INFINITY:
        return P1
    neg_P2 = (q - 1) * P2
    if P1 == INFINITY:
        return neg_P2
    return P1 + neg_P2


def hash_func(q: int, *args: Any) -> int:
    """Cryptographic hash function H: {0,1}* -> Z_q using SHA-256."""
    hasher = hashlib.sha256()

    def update_hash(item: Any) -> None:
        if item == INFINITY:
            hasher.update(b"INFINITY")
        elif hasattr(item, "x") and hasattr(item, "y"):
            hasher.update(point_to_str(item).encode("utf-8"))
        elif isinstance(item, (list, tuple)):
            for sub_item in item:
                update_hash(sub_item)
        elif isinstance(item, bytes):
            hasher.update(item)
        else:
            hasher.update(str(item).encode("utf-8"))

    for arg in args:
        update_hash(arg)

    return int.from_bytes(hasher.digest(), byteorder="big") % q


def hash_to_point(
    P: Point,
    SID: str,
    curve: CurveFp = CURVE,
    p: int = FIELD_PRIME,
    a: int = CURVE_A,
    b: int = CURVE_B,
) -> Point:
    """Deterministically map a public key point P and scope ID (SID) to a curve point H_p(P, SID)."""
    ctr = 0
    p_str = point_to_str(P).encode("utf-8")
    sid_bytes = str(SID).encode("utf-8")

    while True:
        hasher = hashlib.sha256()
        hasher.update(p_str)
        hasher.update(sid_bytes)
        hasher.update(str(ctr).encode("utf-8"))

        x_cand = int.from_bytes(hasher.digest(), byteorder="big") % p
        y_sq = (pow(x_cand, 3, p) + (a * x_cand) + b) % p

        if pow(y_sq, (p - 1) // 2, p) == 1:
            y = pow(y_sq, (p + 1) // 4, p)
            try:
                return Point(curve, x_cand, y)
            except ValueError:
                pass
        ctr += 1


def generate_shares(
    S_net: int,
    N: int,
    k: int,
    q: int = ORDER,
    G: Point = GENERATOR,
) -> list[dict[str, Any]]:
    """Generate (k, N) Shamir secret shares {omega_j, S_{net-j}, P_{net-j}} for the network key."""
    if k < 1 or N < k:
        raise ValueError("Invalid threshold parameters: require 1 <= k <= N.")

    coefficients = [S_net % q] + [secrets.randbelow(q - 1) + 1 for _ in range(k - 1)]
    shares: list[dict[str, Any]] = []

    for j in range(1, N + 1):
        x = j
        y = 0
        for power, coeff in enumerate(coefficients):
            y = (y + coeff * pow(x, power, q)) % q
        P_net_j = y * G
        shares.append({"omega": x, "S_net_j": y, "P_net_j": P_net_j})

    return shares


def create_dleq_share(
    C_1: Point,
    omega_j: int,
    S_net_j: int,
    P_net_j: Point | None = None,
    G: Point = GENERATOR,
    q: int = ORDER,
) -> dict[str, Any]:
    """
    Compute a verifiable decryption share (D_j, c_j, y_j) with a Chaum-Pedersen NIZK DLEQ proof:
      1. D_j = S_{net-j} * C_1
      2. u <- Z_q^*
      3. c_j = H(G, P_{net-j}, C_1, D_j, u * G, u * C_1)
      4. y_j = u + c_j * S_{net-j} (mod q)
    """
    if P_net_j is None:
        P_net_j = S_net_j * G

    D_j = S_net_j * C_1
    u = secrets.randbelow(q - 1) + 1
    U = u * G
    U_prime = u * C_1
    c_j = hash_func(q, G, P_net_j, C_1, D_j, U, U_prime)
    y_j = (u + c_j * S_net_j) % q

    return {
        "omega": omega_j,
        "P_net_j": P_net_j,
        "D_j": D_j,
        "c_j": c_j,
        "y_j": y_j,
    }


def verify_dleq_share(
    C_1: Point,
    D_j: Point,
    c_j: int,
    y_j: int,
    P_net_j: Point,
    G: Point = GENERATOR,
    q: int = ORDER,
) -> bool:
    """
    Verify a node's Chaum-Pedersen NIZK DLEQ proof (c_j, y_j) for decryption share D_j:
      1. U  = y_j * G - c_j * P_{net-j}
      2. U' = y_j * C_1 - c_j * D_j
      3. Check c_j == H(G, P_{net-j}, C_1, D_j, U, U')
    """
    if not is_valid_point(D_j) or not is_valid_point(P_net_j):
        return False
    U = sub_points(y_j * G, c_j * P_net_j, q)
    U_prime = sub_points(y_j * C_1, c_j * D_j, q)
    expected_c_j = hash_func(q, G, P_net_j, C_1, D_j, U, U_prime)
    return bool(c_j == expected_c_j)


def get_signature_size_bytes(n: int) -> int:
    """Calculate the theoretical serialized byte size of a DSLRS signature for ring size n."""
    return 97 * n + 196

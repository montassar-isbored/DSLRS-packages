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
) -> list[dict[str, int]]:
    """Generate (k, N) Shamir secret shares for the network tracing secret key S_net."""
    if k < 1 or N < k:
        raise ValueError("Invalid threshold parameters: require 1 <= k <= N.")

    coefficients = [S_net % q] + [secrets.randbelow(q - 1) + 1 for _ in range(k - 1)]
    shares: list[dict[str, int]] = []

    for j in range(1, N + 1):
        x = j
        y = 0
        for power, coeff in enumerate(coefficients):
            y = (y + coeff * pow(x, power, q)) % q
        shares.append({"omega": x, "S_net_j": y})

    return shares


def get_signature_size_bytes(n: int) -> int:
    """Calculate the theoretical serialized byte size of a DSLRS signature for ring size n."""
    return 97 * n + 196

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any, Iterator, Sequence

from ecdsa.ellipticcurve import INFINITY, CurveFp, Point

from .utils import (
    CURVE,
    CURVE_A,
    CURVE_B,
    FIELD_PRIME,
    GENERATOR,
    ORDER,
    generate_shares,
    get_signature_size_bytes,
    hash_func,
    hash_to_point,
    point_to_str,
    sub_points,
)


@dataclass(frozen=True)
class KeyPair:
    """Represents a user's secp256k1 key pair (secret scalar S_s and public point P_s)."""

    secret_key: int
    public_key: Point

    @property
    def sk(self) -> int:
        return self.secret_key

    @property
    def private_key(self) -> int:
        return self.secret_key

    @property
    def pk(self) -> Point:
        return self.public_key

    def __iter__(self) -> Iterator[Any]:
        yield self.secret_key
        yield self.public_key

    def __getitem__(self, index: int) -> Any:
        return (self.secret_key, self.public_key)[index]


@dataclass
class RingSignature:
    """Represents a Deanonymizable Scope-Linked Ring Signature (DSLRS)."""

    I_scope: Point
    L: list[Point]
    SID: str
    P_net: Point
    C_1: Point
    C_2: Point
    ch_0: int
    x: list[int]
    z: list[int]
    _message: str | bytes | None = field(default=None, repr=False, compare=False)

    @property
    def key_image(self) -> Point:
        return self.I_scope

    @property
    def scope_tag(self) -> Point:
        return self.I_scope

    @property
    def ring(self) -> list[Point]:
        return self.L

    @property
    def sid(self) -> str:
        return self.SID

    @property
    def scope_id(self) -> str:
        return self.SID

    @property
    def p_net(self) -> Point:
        return self.P_net

    @property
    def c1(self) -> Point:
        return self.C_1

    @property
    def c2(self) -> Point:
        return self.C_2

    @property
    def c0(self) -> int:
        return self.ch_0

    @property
    def challenge(self) -> int:
        return self.ch_0

    @property
    def size_bytes(self) -> int:
        return get_signature_size_bytes(len(self.L))

    def to_tuple(self) -> tuple[Point, list[Point], str, Point, Point, Point, int, list[int], list[int]]:
        """Convert the signature to its canonical 9-tuple representation."""
        return (
            self.I_scope,
            self.L,
            self.SID,
            self.P_net,
            self.C_1,
            self.C_2,
            self.ch_0,
            self.x,
            self.z,
        )

    @classmethod
    def from_tuple(cls, sigma: Sequence[Any]) -> RingSignature:
        """Construct a RingSignature instance from a 9-tuple."""
        if isinstance(sigma, cls):
            return sigma
        if len(sigma) != 9:
            raise ValueError(f"Expected 9-element signature tuple, got {len(sigma)}")
        return cls(
            I_scope=sigma[0],
            L=list(sigma[1]),
            SID=str(sigma[2]),
            P_net=sigma[3],
            C_1=sigma[4],
            C_2=sigma[5],
            ch_0=int(sigma[6]),
            x=list(sigma[7]),
            z=list(sigma[8]),
        )

    def __iter__(self) -> Iterator[Any]:
        return iter(self.to_tuple())

    def __getitem__(self, index: int) -> Any:
        return self.to_tuple()[index]

    def __len__(self) -> int:
        return 9


class SystemParameters:
    """Public and authority system parameters for DSLRS."""

    def __init__(
        self,
        n_min: int = 3,
        sids: list[str] | None = None,
        s_net: int | None = None,
        enforce_registry: bool = True,
    ) -> None:
        self.curve: CurveFp = CURVE
        self.G: Point = GENERATOR
        self.q: int = ORDER
        self.p: int = FIELD_PRIME
        self.a: int = CURVE_A
        self.b: int = CURVE_B

        self.L_registry: list[list[Point]] = []
        self.SIDs: list[str] = list(sids) if sids is not None else ["SID_PROJECT_A", "SID_PROJECT_B"]
        self.n_min: int = n_min
        self.enforce_registry: bool = enforce_registry

        self.S_net: int = s_net if s_net is not None else (secrets.randbelow(self.q - 1) + 1)
        self.P_net: Point = self.S_net * self.G


def _normalize_ring(ring: Sequence[Point | KeyPair]) -> list[Point]:
    return [item.public_key if isinstance(item, KeyPair) else item for item in ring]


def keygen(PP: SystemParameters | DSLRS | None = None) -> KeyPair:
    """Generate a fresh secp256k1 key pair (S_s, P_s)."""
    q = PP.q if PP is not None else ORDER
    G = PP.G if PP is not None else GENERATOR
    secret_key = secrets.randbelow(q - 1) + 1
    public_key = secret_key * G
    return KeyPair(secret_key=secret_key, public_key=public_key)


def sign(
    m: str | bytes,
    S_s: int | KeyPair,
    L: Sequence[Point | KeyPair],
    SID: str,
    PP: SystemParameters | DSLRS | None = None,
) -> RingSignature | None:
    """Algorithm 1 (Sign): Generate a scope-linked, threshold-deanonymizable ring signature."""
    if PP is None:
        PP = SystemParameters(enforce_registry=False)

    secret_scalar = S_s.secret_key if isinstance(S_s, KeyPair) else int(S_s)
    ring_points = _normalize_ring(L)
    P_s = secret_scalar * PP.G

    if not getattr(PP, "enforce_registry", True):
        if ring_points not in PP.L_registry:
            PP.L_registry.append(ring_points)
        if SID not in PP.SIDs:
            PP.SIDs.append(SID)

    if (
        (P_s not in ring_points)
        or (ring_points not in PP.L_registry)
        or (SID not in PP.SIDs)
        or (len(ring_points) < PP.n_min)
    ):
        return None

    H_p_val = hash_to_point(P_s, SID, PP.curve, PP.p, PP.a, PP.b)
    I_scope = secret_scalar * H_p_val

    r = secrets.randbelow(PP.q - 1) + 1
    r_dean = secrets.randbelow(PP.q - 1) + 1
    r_z = secrets.randbelow(PP.q - 1) + 1

    C_1 = r_dean * PP.G
    C_2 = P_s + (r_dean * PP.P_net)

    L_s = r * PP.G
    R_s = r * H_p_val
    A_s = r_z * PP.G
    B_s = r_z * PP.P_net

    n = len(ring_points)
    s = ring_points.index(P_s)

    ch = [0] * n
    x = [0] * n
    z = [0] * n

    ch[(s + 1) % n] = hash_func(PP.q, m, ring_points, I_scope, SID, C_1, C_2, L_s, R_s, A_s, B_s)

    for j in range(1, n):
        i = (s + j) % n
        x[i] = secrets.randbelow(PP.q - 1) + 1
        z[i] = secrets.randbelow(PP.q - 1) + 1

        P_i = ring_points[i]
        H_p_i = hash_to_point(P_i, SID, PP.curve, PP.p, PP.a, PP.b)

        L_i = (x[i] * PP.G) + (ch[i] * P_i)
        R_i = (x[i] * H_p_i) + (ch[i] * I_scope)

        A_i = sub_points(z[i] * PP.G, ch[i] * C_1, PP.q)
        C2_minus_Pi = sub_points(C_2, P_i, PP.q)
        B_i = sub_points(z[i] * PP.P_net, ch[i] * C2_minus_Pi, PP.q)

        ch[(i + 1) % n] = hash_func(PP.q, m, ring_points, I_scope, SID, C_1, C_2, L_i, R_i, A_i, B_i)

    x[s] = (r - (ch[s] * secret_scalar)) % PP.q
    z[s] = (r_z + (ch[s] * r_dean)) % PP.q

    return RingSignature(
        I_scope=I_scope,
        L=ring_points,
        SID=SID,
        P_net=PP.P_net,
        C_1=C_1,
        C_2=C_2,
        ch_0=ch[0],
        x=x,
        z=z,
        _message=m,
    )


def verify(
    m: str | bytes | RingSignature | Sequence[Any],
    sigma: RingSignature | Sequence[Any] | str | bytes | None,
    PP: SystemParameters | DSLRS | None = None,
) -> bool:
    """Algorithm 2 (Verify): Verify a DSLRS ring signature against message m."""
    if isinstance(m, RingSignature) or (
        isinstance(m, tuple) and len(m) == 9 and hasattr(m[0], "x")
    ):
        m, sigma = sigma, m  # type: ignore[assignment]

    if not sigma or m is None:
        return False

    sig_obj = RingSignature.from_tuple(sigma)  # type: ignore[arg-type]
    I_scope, L, SID, P_net, C_1, C_2, ch_0, x, z = sig_obj.to_tuple()

    if PP is not None:
        enforce = getattr(PP, "enforce_registry", True)
        if enforce or PP.L_registry:
            if L not in PP.L_registry:
                return False
        if enforce or PP.SIDs:
            if SID not in PP.SIDs:
                return False
        if P_net != PP.P_net or len(L) < PP.n_min:
            return False
        curve, G, q, p, a, b = PP.curve, PP.G, PP.q, PP.p, PP.a, PP.b
    else:
        if len(L) < 2:
            return False
        curve, G, q, p, a, b = CURVE, GENERATOR, ORDER, FIELD_PRIME, CURVE_A, CURVE_B

    n = len(L)
    if len(x) != n or len(z) != n:
        return False

    ch = [0] * n
    ch[0] = ch_0

    P_0 = L[0]
    H_p_0 = hash_to_point(P_0, SID, curve, p, a, b)

    L_1_prime = (x[0] * G) + (ch[0] * P_0)
    R_1_prime = (x[0] * H_p_0) + (ch[0] * I_scope)

    A_1_prime = sub_points(z[0] * G, ch[0] * C_1, q)
    C2_minus_P0 = sub_points(C_2, P_0, q)
    B_1_prime = sub_points(z[0] * P_net, ch[0] * C2_minus_P0, q)

    ch[1 % n] = hash_func(q, m, L, I_scope, SID, C_1, C_2, L_1_prime, R_1_prime, A_1_prime, B_1_prime)

    for i in range(1, n):
        P_i = L[i]
        H_p_i = hash_to_point(P_i, SID, curve, p, a, b)

        L_i_prime = (x[i] * G) + (ch[i] * P_i)
        R_i_prime = (x[i] * H_p_i) + (ch[i] * I_scope)

        A_i_prime = sub_points(z[i] * G, ch[i] * C_1, q)
        C2_minus_Pi = sub_points(C_2, P_i, q)
        B_i_prime = sub_points(z[i] * P_net, ch[i] * C2_minus_Pi, q)

        computed_ch = hash_func(
            q, m, L, I_scope, SID, C_1, C_2, L_i_prime, R_i_prime, A_i_prime, B_i_prime
        )

        next_i = (i + 1) % n
        if next_i == 0:
            if computed_ch == ch[0]:
                return True
        else:
            ch[next_i] = computed_ch

    return False


def link(
    sigma_1: RingSignature | Sequence[Any] | None,
    m_1: Any = None,
    sigma_2: Any = None,
    m_2: Any = None,
    PP: SystemParameters | DSLRS | None = None,
) -> bool:
    """Algorithm 3 (Link): Check whether two valid signatures were produced by the same signer under the same SID."""
    if not sigma_1 or m_1 is None:
        return False

    # Support 2-argument call: link(sigma_1, sigma_2)
    if sigma_2 is None and m_2 is None:
        sig1 = RingSignature.from_tuple(sigma_1)
        sig2 = RingSignature.from_tuple(m_1)
        if sig1.SID != sig2.SID:
            return False
        if sig1._message is not None and not verify(sig1._message, sig1, PP):
            return False
        if sig2._message is not None and not verify(sig2._message, sig2, PP):
            return False
        return bool(sig1.I_scope == sig2.I_scope)

    if not sigma_2:
        return False

    sig1 = RingSignature.from_tuple(sigma_1)
    sig2 = RingSignature.from_tuple(sigma_2)

    if sig1.SID != sig2.SID:
        return False

    if verify(m_1, sig1, PP) and verify(m_2, sig2, PP):
        if sig1.I_scope == sig2.I_scope:
            return True

    return False


def trace(
    sigma: RingSignature | Sequence[Any],
    D_list: Sequence[Any] | None = None,
    omega_list: Sequence[int] | None = None,
    q: int = ORDER,
) -> Point:
    """Algorithm 4 (Trace / Deanonymize): Recover the signer's public key P_s via Lagrange interpolation."""
    sig_obj = RingSignature.from_tuple(sigma)
    C_1 = sig_obj.C_1
    C_2 = sig_obj.C_2

    if D_list is None:
        raise ValueError("Decryption shares (D_list or node shares) must be provided for tracing.")

    # Allow passing list of share dicts [{'omega': ..., 'S_net_j': ...}] directly as D_list
    if len(D_list) > 0 and isinstance(D_list[0], dict):
        share_dicts = D_list
        computed_D: list[Point] = []
        computed_omega: list[int] = []
        for node in share_dicts:
            computed_omega.append(int(node["omega"]))
            computed_D.append(int(node["S_net_j"]) * C_1)
        D_points = computed_D
        omegas = computed_omega
    else:
        if omega_list is None:
            raise ValueError("omega_list must be provided when D_list contains curve points.")
        D_points = list(D_list)
        omegas = list(omega_list)

    k = len(D_points)
    if k == 0 or len(omegas) != k:
        raise ValueError("Non-empty matching D_list and omega_list are required.")

    lam = [0] * k
    for j in range(k):
        num = 1
        den = 1
        for i in range(k):
            if i != j:
                num = (num * omegas[i]) % q
                diff = (omegas[i] - omegas[j]) % q
                den = (den * diff) % q
        den_inv = pow(den, -1, q)
        lam[j] = (num * den_inv) % q

    V: Point = INFINITY
    for j in range(k):
        term = lam[j] * D_points[j]
        if V == INFINITY:
            V = term
        else:
            V = V + term

    P_s = sub_points(C_2, V, q)
    return P_s


# Aliases for protocol terminology compatibility
deanonymize = trace
KeyGen = keygen
Sign = sign
Verify = verify
Link = link
Trace = trace
Deanonymize = trace


class DSLRS(SystemParameters):
    """High-level interface for Deanonymizable Scope-Linked Ring Signatures (DSLRS)."""

    def __init__(
        self,
        n_min: int = 3,
        sids: list[str] | None = None,
        s_net: int | None = None,
        n_nodes: int = 12,
        threshold: int = 8,
        enforce_registry: bool = False,
    ) -> None:
        super().__init__(
            n_min=n_min,
            sids=sids,
            s_net=s_net,
            enforce_registry=enforce_registry,
        )
        self.N: int = n_nodes
        self.k: int = threshold
        self.shares: list[dict[str, int]] = generate_shares(self.S_net, self.N, self.k, self.q)

    @staticmethod
    def keygen() -> KeyPair:
        """Generate a new user key pair (S_s, P_s) on secp256k1."""
        return keygen()

    def register_ring(self, ring: Sequence[Point | KeyPair]) -> list[Point]:
        """Register a ring of public keys in L_registry."""
        pts = _normalize_ring(ring)
        if pts not in self.L_registry:
            self.L_registry.append(pts)
        return pts

    def register_sid(self, sid: str) -> None:
        """Register a Scope Identifier (SID)."""
        if sid not in self.SIDs:
            self.SIDs.append(sid)

    def sign(
        self,
        message: str | bytes,
        signer: int | KeyPair,
        ring: Sequence[Point | KeyPair],
        sid: str = "SID_PROJECT_A",
    ) -> RingSignature | None:
        """Generate a ring signature for `message` under scope `sid`."""
        return sign(message, signer, ring, sid, self)

    def verify(
        self,
        message: str | bytes | RingSignature | Sequence[Any],
        signature: RingSignature | Sequence[Any] | str | bytes | None,
    ) -> bool:
        """Verify a ring signature against `message`."""
        return verify(message, signature, self)

    def link(
        self,
        sigma_1: RingSignature | Sequence[Any] | None,
        m_1: Any = None,
        sigma_2: Any = None,
        m_2: Any = None,
    ) -> bool:
        """Check if two signatures are linked under the same scope."""
        return link(sigma_1, m_1, sigma_2, m_2, self)

    def compute_decryption_shares(
        self,
        sigma: RingSignature | Sequence[Any],
        responding_shares: Sequence[dict[str, int]] | None = None,
    ) -> tuple[list[Point], list[int]]:
        """Compute partial ElGamal decryption points D_j = S_{net,j} * C_1 for k authority nodes."""
        sig_obj = RingSignature.from_tuple(sigma)
        nodes = list(responding_shares) if responding_shares is not None else self.shares[: self.k]
        omega_list: list[int] = []
        D_list: list[Point] = []
        for node in nodes:
            omega_list.append(int(node["omega"]))
            D_list.append(int(node["S_net_j"]) * sig_obj.C_1)
        return D_list, omega_list

    def trace(
        self,
        sigma: RingSignature | Sequence[Any],
        D_list: Sequence[Any] | None = None,
        omega_list: Sequence[int] | None = None,
    ) -> Point:
        """Recover the signer's public key P_s using threshold decryption shares."""
        if D_list is None and omega_list is None:
            D_pts, omegas = self.compute_decryption_shares(sigma)
            return trace(sigma, D_pts, omegas, self.q)
        return trace(sigma, D_list, omega_list, self.q)

    def deanonymize(
        self,
        sigma: RingSignature | Sequence[Any],
        D_list: Sequence[Any] | None = None,
        omega_list: Sequence[int] | None = None,
    ) -> Point:
        """Alias for trace()."""
        return self.trace(sigma, D_list, omega_list)

    @staticmethod
    def get_signature_size_bytes(n: int) -> int:
        """Return the theoretical byte size of a signature with ring size n."""
        return get_signature_size_bytes(n)

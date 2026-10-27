import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";
import { sha256 } from "@noble/hashes/sha256";

export type ECPoint = InstanceType<typeof secp256k1.ProjectivePoint>;

export const GENERATOR: ECPoint = secp256k1.ProjectivePoint.BASE;
export const INFINITY: ECPoint = secp256k1.ProjectivePoint.ZERO;
export const ORDER: bigint = secp256k1.CURVE.n;
export const FIELD_PRIME: bigint = secp256k1.CURVE.Fp.ORDER;
export const CURVE_A: bigint = 0n;
export const CURVE_B: bigint = 7n;

const utf8Encoder = new TextEncoder();

export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % m;
    }
    e >>= 1n;
    b = (b * b) % m;
  }
  return result;
}

export function modInv(a: bigint, m: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = mod(a, m);

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (r > 1n) {
    throw new Error("Value is not invertible modulo m");
  }
  if (t < 0n) {
    t += m;
  }
  return t;
}

export function randomScalar(q: bigint = ORDER): bigint {
  const privBytes = secp256k1.utils.randomPrivateKey();
  const n = bytesToNumberBE(privBytes);
  return mod(n - 1n, q - 1n) + 1n;
}

export function scalarMul(scalar: bigint, point: ECPoint, q: bigint = ORDER): ECPoint {
  const s = mod(scalar, q);
  if (s === 0n || point.equals(INFINITY)) {
    return INFINITY;
  }
  return point.multiply(s);
}

export function isECPoint(value: unknown): value is ECPoint {
  return (
    typeof value === "object" &&
    value !== null &&
    "toAffine" in value &&
    "multiply" in value &&
    "equals" in value
  );
}

export function pointToStr(pt: ECPoint): string {
  if (pt.equals(INFINITY)) {
    return "INFINITY";
  }
  const aff = pt.toAffine();
  return `${aff.x.toString()},${aff.y.toString()}`;
}

export function subPoints(P1: ECPoint, P2: ECPoint, _q: bigint = ORDER): ECPoint {
  return P1.subtract(P2);
}

export function hashFunc(q: bigint, ...args: unknown[]): bigint {
  const hasher = sha256.create();

  function updateHash(item: unknown): void {
    if (isECPoint(item)) {
      hasher.update(utf8Encoder.encode(pointToStr(item)));
    } else if (Array.isArray(item)) {
      for (const subItem of item) {
        updateHash(subItem);
      }
    } else if (item instanceof Uint8Array) {
      hasher.update(item);
    } else {
      hasher.update(utf8Encoder.encode(String(item)));
    }
  }

  for (const arg of args) {
    updateHash(arg);
  }

  const digest = hasher.digest();
  return mod(bytesToNumberBE(digest), q);
}

export function hashToPoint(
  P: ECPoint,
  SID: string,
  p: bigint = FIELD_PRIME,
  a: bigint = CURVE_A,
  b: bigint = CURVE_B
): ECPoint {
  let ctr = 0;
  const pBytes = utf8Encoder.encode(pointToStr(P));
  const sidBytes = utf8Encoder.encode(String(SID));
  const eulerExp = (p - 1n) / 2n;
  const sqrtExp = (p + 1n) / 4n;

  while (true) {
    const hasher = sha256.create();
    hasher.update(pBytes);
    hasher.update(sidBytes);
    hasher.update(utf8Encoder.encode(String(ctr)));

    const xCand = mod(bytesToNumberBE(hasher.digest()), p);
    const ySq = mod(modPow(xCand, 3n, p) + a * xCand + b, p);

    if (modPow(ySq, eulerExp, p) === 1n) {
      const y = modPow(ySq, sqrtExp, p);
      try {
        const pt = secp256k1.ProjectivePoint.fromAffine({ x: xCand, y });
        pt.assertValidity();
        return pt;
      } catch {
        // Point validation failed, increment counter
      }
    }
    ctr += 1;
  }
}

export interface Share {
  omega: bigint;
  S_net_j: bigint;
}

export function generateShares(
  S_net: bigint,
  N: number,
  k: number,
  q: bigint = ORDER
): Share[] {
  if (k < 1 || N < k) {
    throw new Error("Invalid threshold parameters: require 1 <= k <= N.");
  }

  const coefficients: bigint[] = [mod(S_net, q)];
  for (let i = 0; i < k - 1; i++) {
    coefficients.push(randomScalar(q));
  }

  const shares: Share[] = [];
  for (let j = 1; j <= N; j++) {
    const x = BigInt(j);
    let y = 0n;
    for (let power = 0; power < coefficients.length; power++) {
      const term = (coefficients[power] * modPow(x, BigInt(power), q)) % q;
      y = (y + term) % q;
    }
    shares.push({ omega: x, S_net_j: y });
  }

  return shares;
}

export function getSignatureSizeBytes(n: number): number {
  return 97 * n + 196;
}

export class KeyPair {
  public readonly secretKey: bigint;
  public readonly publicKey: ECPoint;

  constructor(secretKey: bigint, publicKey: ECPoint) {
    this.secretKey = secretKey;
    this.publicKey = publicKey;
  }

  get secret_key(): bigint {
    return this.secretKey;
  }

  get public_key(): ECPoint {
    return this.publicKey;
  }

  get sk(): bigint {
    return this.secretKey;
  }

  get pk(): ECPoint {
    return this.publicKey;
  }
}

export class RingSignature {
  public readonly I_scope: ECPoint;
  public readonly L: ECPoint[];
  public readonly SID: string;
  public readonly P_net: ECPoint;
  public readonly C_1: ECPoint;
  public readonly C_2: ECPoint;
  public readonly ch_0: bigint;
  public readonly x: bigint[];
  public readonly z: bigint[];
  public readonly _message?: string | Uint8Array;

  constructor(params: {
    I_scope: ECPoint;
    L: ECPoint[];
    SID: string;
    P_net: ECPoint;
    C_1: ECPoint;
    C_2: ECPoint;
    ch_0: bigint;
    x: bigint[];
    z: bigint[];
    message?: string | Uint8Array;
  }) {
    this.I_scope = params.I_scope;
    this.L = params.L;
    this.SID = params.SID;
    this.P_net = params.P_net;
    this.C_1 = params.C_1;
    this.C_2 = params.C_2;
    this.ch_0 = params.ch_0;
    this.x = params.x;
    this.z = params.z;
    this._message = params.message;
  }

  get keyImage(): ECPoint {
    return this.I_scope;
  }

  get scopeTag(): ECPoint {
    return this.I_scope;
  }

  get ring(): ECPoint[] {
    return this.L;
  }

  get sid(): string {
    return this.SID;
  }

  get pNet(): ECPoint {
    return this.P_net;
  }

  get c1(): ECPoint {
    return this.C_1;
  }

  get c2(): ECPoint {
    return this.C_2;
  }

  get c0(): bigint {
    return this.ch_0;
  }

  get sizeBytes(): number {
    return getSignatureSizeBytes(this.L.length);
  }
}

export interface SystemParametersOptions {
  nMin?: number;
  sids?: string[];
  sNet?: bigint;
  enforceRegistry?: boolean;
}

export class SystemParameters {
  public readonly G: ECPoint = GENERATOR;
  public readonly q: bigint = ORDER;
  public readonly p: bigint = FIELD_PRIME;
  public readonly a: bigint = CURVE_A;
  public readonly b: bigint = CURVE_B;

  public L_registry: ECPoint[][] = [];
  public SIDs: string[];
  public n_min: number;
  public enforceRegistry: boolean;
  public readonly S_net: bigint;
  public readonly P_net: ECPoint;

  constructor(options: SystemParametersOptions = {}) {
    this.n_min = options.nMin ?? 3;
    this.SIDs = options.sids ? [...options.sids] : ["SID_PROJECT_A", "SID_PROJECT_B"];
    this.enforceRegistry = options.enforceRegistry ?? true;
    this.S_net = options.sNet ?? randomScalar(this.q);
    this.P_net = scalarMul(this.S_net, this.G, this.q);
  }
}

function normalizeRing(ring: ReadonlyArray<ECPoint | KeyPair>): ECPoint[] {
  return ring.map((item) => (item instanceof KeyPair ? item.publicKey : item));
}

function findPointIndex(ring: ReadonlyArray<ECPoint>, target: ECPoint): number {
  return ring.findIndex((pt) => pt.equals(target));
}

function isRingInRegistry(ring: ReadonlyArray<ECPoint>, registry: ReadonlyArray<ReadonlyArray<ECPoint>>): boolean {
  return registry.some(
    (regRing) =>
      regRing.length === ring.length && regRing.every((pt, idx) => pt.equals(ring[idx]))
  );
}

export function keygen(PP?: SystemParameters): KeyPair {
  const q = PP ? PP.q : ORDER;
  const G = PP ? PP.G : GENERATOR;
  const secretKey = randomScalar(q);
  const publicKey = scalarMul(secretKey, G, q);
  return new KeyPair(secretKey, publicKey);
}

export function sign(
  m: string | Uint8Array,
  S_s: bigint | KeyPair,
  L: ReadonlyArray<ECPoint | KeyPair>,
  SID: string,
  PP?: SystemParameters
): RingSignature | null {
  const params = PP ?? new SystemParameters({ enforceRegistry: false });
  const secretScalar = S_s instanceof KeyPair ? S_s.secretKey : S_s;
  const ringPoints = normalizeRing(L);
  const P_s = scalarMul(secretScalar, params.G, params.q);

  if (!params.enforceRegistry) {
    if (!isRingInRegistry(ringPoints, params.L_registry)) {
      params.L_registry.push(ringPoints);
    }
    if (!params.SIDs.includes(SID)) {
      params.SIDs.push(SID);
    }
  }

  const s = findPointIndex(ringPoints, P_s);
  if (
    s === -1 ||
    !isRingInRegistry(ringPoints, params.L_registry) ||
    !params.SIDs.includes(SID) ||
    ringPoints.length < params.n_min
  ) {
    return null;
  }

  const H_p_val = hashToPoint(P_s, SID, params.p, params.a, params.b);
  const I_scope = scalarMul(secretScalar, H_p_val, params.q);

  const r = randomScalar(params.q);
  const r_dean = randomScalar(params.q);
  const r_z = randomScalar(params.q);

  const C_1 = scalarMul(r_dean, params.G, params.q);
  const C_2 = P_s.add(scalarMul(r_dean, params.P_net, params.q));

  const L_s = scalarMul(r, params.G, params.q);
  const R_s = scalarMul(r, H_p_val, params.q);
  const A_s = scalarMul(r_z, params.G, params.q);
  const B_s = scalarMul(r_z, params.P_net, params.q);

  const n = ringPoints.length;
  const ch: bigint[] = new Array(n).fill(0n);
  const x: bigint[] = new Array(n).fill(0n);
  const z: bigint[] = new Array(n).fill(0n);

  ch[(s + 1) % n] = hashFunc(
    params.q,
    m,
    ringPoints,
    I_scope,
    SID,
    C_1,
    C_2,
    L_s,
    R_s,
    A_s,
    B_s
  );

  for (let j = 1; j < n; j++) {
    const i = (s + j) % n;
    x[i] = randomScalar(params.q);
    z[i] = randomScalar(params.q);

    const P_i = ringPoints[i];
    const H_p_i = hashToPoint(P_i, SID, params.p, params.a, params.b);

    const L_i = scalarMul(x[i], params.G, params.q).add(scalarMul(ch[i], P_i, params.q));
    const R_i = scalarMul(x[i], H_p_i, params.q).add(scalarMul(ch[i], I_scope, params.q));

    const A_i = subPoints(
      scalarMul(z[i], params.G, params.q),
      scalarMul(ch[i], C_1, params.q),
      params.q
    );
    const C2_minus_Pi = subPoints(C_2, P_i, params.q);
    const B_i = subPoints(
      scalarMul(z[i], params.P_net, params.q),
      scalarMul(ch[i], C2_minus_Pi, params.q),
      params.q
    );

    ch[(i + 1) % n] = hashFunc(
      params.q,
      m,
      ringPoints,
      I_scope,
      SID,
      C_1,
      C_2,
      L_i,
      R_i,
      A_i,
      B_i
    );
  }

  x[s] = mod(r - ch[s] * secretScalar, params.q);
  z[s] = mod(r_z + ch[s] * r_dean, params.q);

  return new RingSignature({
    I_scope,
    L: ringPoints,
    SID,
    P_net: params.P_net,
    C_1,
    C_2,
    ch_0: ch[0],
    x,
    z,
    message: m,
  });
}

export function verify(
  m: string | Uint8Array,
  sigma: RingSignature | null | undefined,
  PP?: SystemParameters
): boolean {
  if (!sigma) {
    return false;
  }

  const { I_scope, L, SID, P_net, C_1, C_2, ch_0, x, z } = sigma;

  if (PP) {
    if (PP.enforceRegistry || PP.L_registry.length > 0) {
      if (!isRingInRegistry(L, PP.L_registry)) {
        return false;
      }
    }
    if (PP.enforceRegistry || PP.SIDs.length > 0) {
      if (!PP.SIDs.includes(SID)) {
        return false;
      }
    }
    if (!P_net.equals(PP.P_net) || L.length < PP.n_min) {
      return false;
    }
  } else if (L.length < 2) {
    return false;
  }

  const G = PP ? PP.G : GENERATOR;
  const q = PP ? PP.q : ORDER;
  const p = PP ? PP.p : FIELD_PRIME;
  const a = PP ? PP.a : CURVE_A;
  const b = PP ? PP.b : CURVE_B;

  const n = L.length;
  if (x.length !== n || z.length !== n) {
    return false;
  }

  const ch: bigint[] = new Array(n).fill(0n);
  ch[0] = ch_0;

  const P_0 = L[0];
  const H_p_0 = hashToPoint(P_0, SID, p, a, b);

  const L_1_prime = scalarMul(x[0], G, q).add(scalarMul(ch[0], P_0, q));
  const R_1_prime = scalarMul(x[0], H_p_0, q).add(scalarMul(ch[0], I_scope, q));

  const A_1_prime = subPoints(scalarMul(z[0], G, q), scalarMul(ch[0], C_1, q), q);
  const C2_minus_P0 = subPoints(C_2, P_0, q);
  const B_1_prime = subPoints(scalarMul(z[0], P_net, q), scalarMul(ch[0], C2_minus_P0, q), q);

  ch[1 % n] = hashFunc(
    q,
    m,
    L,
    I_scope,
    SID,
    C_1,
    C_2,
    L_1_prime,
    R_1_prime,
    A_1_prime,
    B_1_prime
  );

  for (let i = 1; i < n; i++) {
    const P_i = L[i];
    const H_p_i = hashToPoint(P_i, SID, p, a, b);

    const L_i_prime = scalarMul(x[i], G, q).add(scalarMul(ch[i], P_i, q));
    const R_i_prime = scalarMul(x[i], H_p_i, q).add(scalarMul(ch[i], I_scope, q));

    const A_i_prime = subPoints(scalarMul(z[i], G, q), scalarMul(ch[i], C_1, q), q);
    const C2_minus_Pi = subPoints(C_2, P_i, q);
    const B_i_prime = subPoints(scalarMul(z[i], P_net, q), scalarMul(ch[i], C2_minus_Pi, q), q);

    const computedCh = hashFunc(
      q,
      m,
      L,
      I_scope,
      SID,
      C_1,
      C_2,
      L_i_prime,
      R_i_prime,
      A_i_prime,
      B_i_prime
    );

    const nextI = (i + 1) % n;
    if (nextI === 0) {
      if (computedCh === ch[0]) {
        return true;
      }
    } else {
      ch[nextI] = computedCh;
    }
  }

  return false;
}

export function link(
  sigma1: RingSignature | null | undefined,
  m1: string | Uint8Array | RingSignature | null | undefined,
  sigma2?: RingSignature | null,
  m2?: string | Uint8Array,
  PP?: SystemParameters
): boolean {
  if (!sigma1 || !m1) {
    return false;
  }

  // Support 2-argument call: link(sigma1, sigma2)
  if (m1 instanceof RingSignature) {
    const sig2 = m1;
    if (sigma1.SID !== sig2.SID) {
      return false;
    }
    if (sigma1._message !== undefined && !verify(sigma1._message, sigma1, PP)) {
      return false;
    }
    if (sig2._message !== undefined && !verify(sig2._message, sig2, PP)) {
      return false;
    }
    return sigma1.I_scope.equals(sig2.I_scope);
  }

  if (!sigma2 || m2 === undefined) {
    return false;
  }

  if (sigma1.SID !== sigma2.SID) {
    return false;
  }

  if (verify(m1, sigma1, PP) && verify(m2, sigma2, PP)) {
    return sigma1.I_scope.equals(sigma2.I_scope);
  }

  return false;
}

export function trace(
  sigma: RingSignature,
  D_list: ReadonlyArray<ECPoint> | ReadonlyArray<Share>,
  omega_list?: ReadonlyArray<bigint | number>,
  q: bigint = ORDER
): ECPoint {
  const { C_1, C_2 } = sigma;
  if (D_list.length === 0) {
    throw new Error("Non-empty decryption shares are required for tracing.");
  }

  let dPoints: ECPoint[];
  let omegas: bigint[];

  if (!isECPoint(D_list[0])) {
    const shareNodes = D_list as ReadonlyArray<Share>;
    dPoints = shareNodes.map((node) => scalarMul(node.S_net_j, C_1, q));
    omegas = shareNodes.map((node) => BigInt(node.omega));
  } else {
    if (!omega_list || omega_list.length !== D_list.length) {
      throw new Error("Matching omega_list is required when D_list contains curve points.");
    }
    dPoints = D_list as ECPoint[];
    omegas = omega_list.map((w) => BigInt(w));
  }

  const k = dPoints.length;
  const lam: bigint[] = new Array(k).fill(0n);

  for (let j = 0; j < k; j++) {
    let num = 1n;
    let den = 1n;
    for (let i = 0; i < k; i++) {
      if (i !== j) {
        num = mod(num * omegas[i], q);
        const diff = mod(omegas[i] - omegas[j], q);
        den = mod(den * diff, q);
      }
    }
    const denInv = modInv(den, q);
    lam[j] = mod(num * denInv, q);
  }

  let V: ECPoint = INFINITY;
  for (let j = 0; j < k; j++) {
    const term = scalarMul(lam[j], dPoints[j], q);
    V = V.equals(INFINITY) ? term : V.add(term);
  }

  return subPoints(C_2, V, q);
}

export const deanonymize = trace;

export interface DSLRSOptions extends SystemParametersOptions {
  nNodes?: number;
  threshold?: number;
}

export class DSLRS extends SystemParameters {
  public readonly N: number;
  public readonly k: number;
  public readonly shares: Share[];

  constructor(options: DSLRSOptions = {}) {
    super({
      ...options,
      enforceRegistry: options.enforceRegistry ?? false,
    });
    this.N = options.nNodes ?? 12;
    this.k = options.threshold ?? 8;
    this.shares = generateShares(this.S_net, this.N, this.k, this.q);
  }

  static keygen(): KeyPair {
    return keygen();
  }

  keygen(): KeyPair {
    return keygen(this);
  }

  registerRing(ring: ReadonlyArray<ECPoint | KeyPair>): ECPoint[] {
    const pts = normalizeRing(ring);
    if (!isRingInRegistry(pts, this.L_registry)) {
      this.L_registry.push(pts);
    }
    return pts;
  }

  registerSid(sid: string): void {
    if (!this.SIDs.includes(sid)) {
      this.SIDs.push(sid);
    }
  }

  sign(
    message: string | Uint8Array,
    signer: bigint | KeyPair,
    ring: ReadonlyArray<ECPoint | KeyPair>,
    sid: string = "SID_PROJECT_A"
  ): RingSignature | null {
    return sign(message, signer, ring, sid, this);
  }

  verify(message: string | Uint8Array, signature: RingSignature | null | undefined): boolean {
    return verify(message, signature, this);
  }

  link(
    sigma1: RingSignature | null | undefined,
    m1: string | Uint8Array | RingSignature | null | undefined,
    sigma2?: RingSignature | null,
    m2?: string | Uint8Array
  ): boolean {
    return link(sigma1, m1, sigma2, m2, this);
  }

  computeDecryptionShares(
    sigma: RingSignature,
    respondingShares?: ReadonlyArray<Share>
  ): { D_list: ECPoint[]; omega_list: bigint[] } {
    const nodes = respondingShares ?? this.shares.slice(0, this.k);
    const omega_list: bigint[] = [];
    const D_list: ECPoint[] = [];
    for (const node of nodes) {
      omega_list.push(node.omega);
      D_list.push(scalarMul(node.S_net_j, sigma.C_1, this.q));
    }
    return { D_list, omega_list };
  }

  trace(
    sigma: RingSignature,
    D_list?: ReadonlyArray<ECPoint> | ReadonlyArray<Share>,
    omega_list?: ReadonlyArray<bigint | number>
  ): ECPoint {
    if (!D_list) {
      const computed = this.computeDecryptionShares(sigma);
      return trace(sigma, computed.D_list, computed.omega_list, this.q);
    }
    return trace(sigma, D_list, omega_list, this.q);
  }

  deanonymize(
    sigma: RingSignature,
    D_list?: ReadonlyArray<ECPoint> | ReadonlyArray<Share>,
    omega_list?: ReadonlyArray<bigint | number>
  ): ECPoint {
    return this.trace(sigma, D_list, omega_list);
  }

  static getSignatureSizeBytes(n: number): number {
    return getSignatureSizeBytes(n);
  }
}

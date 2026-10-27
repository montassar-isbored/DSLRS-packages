import { describe, expect, it } from "vitest";
import {
  DSLRS,
  KeyPair,
  RingSignature,
  SystemParameters,
  createDleqShare,
  deanonymize,
  generateShares,
  getSignatureSizeBytes,
  hashToPoint,
  keygen,
  link,
  pointToStr,
  scalarMul,
  sign,
  trace,
  verify,
  verifyDleqShare,
} from "../src/index.js";

describe("DSLRS TypeScript SDK", () => {
  it("generates valid secp256k1 key pairs", () => {
    const scheme = new DSLRS();
    const kp = scheme.keygen();
    expect(kp).toBeInstanceOf(KeyPair);
    expect(kp.secretKey > 0n && kp.secretKey < scheme.q).toBe(true);
    expect(kp.publicKey.equals(scalarMul(kp.secretKey, scheme.G, scheme.q))).toBe(true);
  });

  it("signs and verifies messages across a ring", () => {
    const scheme = new DSLRS({ nMin: 3, nNodes: 6, threshold: 4 });
    const keys = Array.from({ length: 5 }, () => scheme.keygen());
    const ring = keys.map((k) => k.publicKey);
    scheme.registerRing(ring);

    const signer = keys[2];
    const msg = "Consent_proof_V1";
    const sid = "SID_PROJECT_A";

    const sig = scheme.sign(msg, signer, ring, sid);
    expect(sig).not.toBeNull();
    expect(sig).toBeInstanceOf(RingSignature);
    expect(sig!.SID).toBe(sid);
    expect(sig!.sizeBytes).toBe(getSignatureSizeBytes(5));

    expect(scheme.verify(msg, sig)).toBe(true);
    expect(scheme.verify("Tampered_Message", sig)).toBe(false);
  });

  it("enforces sign preconditions when registry is strict", () => {
    const pp = new SystemParameters({ nMin: 3, enforceRegistry: true });
    const keys = Array.from({ length: 4 }, () => keygen(pp));
    const ring = keys.map((k) => k.publicKey);
    const outsider = keygen(pp);

    // Unregistered ring rejected
    expect(sign("msg", keys[0].secretKey, ring, "SID_PROJECT_A", pp)).toBeNull();

    pp.L_registry.push(ring);

    // Signer not in ring rejected
    expect(sign("msg", outsider.secretKey, ring, "SID_PROJECT_A", pp)).toBeNull();

    // Unregistered SID rejected
    expect(sign("msg", keys[0].secretKey, ring, "UNKNOWN_SID", pp)).toBeNull();

    // Ring smaller than n_min rejected
    const smallRing = ring.slice(0, 2);
    pp.L_registry.push(smallRing);
    expect(sign("msg", keys[0].secretKey, smallRing, "SID_PROJECT_A", pp)).toBeNull();
  });

  it("links signatures from the same signer in the same SID and unlinks across SIDs", () => {
    const scheme = new DSLRS();
    const keys = Array.from({ length: 4 }, () => scheme.keygen());
    const ring = keys.map((k) => k.publicKey);

    const signerA = keys[0];
    const signerB = keys[1];

    const sigA1 = scheme.sign("Message_1", signerA, ring, "SID_PROJECT_A");
    const sigA2 = scheme.sign("Message_2", signerA, ring, "SID_PROJECT_A");
    const sigADiffSid = scheme.sign("Message_3", signerA, ring, "SID_PROJECT_B");
    const sigB1 = scheme.sign("Message_4", signerB, ring, "SID_PROJECT_A");

    expect(sigA1).not.toBeNull();
    expect(sigA2).not.toBeNull();
    expect(sigADiffSid).not.toBeNull();
    expect(sigB1).not.toBeNull();

    // Same signer + same SID -> linked
    expect(scheme.link(sigA1, "Message_1", sigA2, "Message_2")).toBe(true);
    expect(scheme.link(sigA1, sigA2)).toBe(true);

    // Same signer + different SID -> unlinked
    expect(scheme.link(sigA1, "Message_1", sigADiffSid, "Message_3")).toBe(false);
    expect(scheme.link(sigA1, sigADiffSid)).toBe(false);

    // Different signers + same SID -> unlinked
    expect(scheme.link(sigA1, "Message_1", sigB1, "Message_4")).toBe(false);
    expect(scheme.link(sigA1, sigB1)).toBe(false);
  });

  it("verifies Chaum-Pedersen DLEQ decryption shares and rejects malicious shares", () => {
    const scheme = new DSLRS({ nNodes: 8, threshold: 5 });
    const keys = Array.from({ length: 6 }, () => scheme.keygen());
    const ring = keys.map((k) => k.publicKey);

    const signer = keys[3];
    const sig = scheme.sign("Audit_Payload", signer, ring, "SID_PROJECT_A");
    expect(sig).not.toBeNull();

    const respondingNodes = scheme.shares.slice(2, 7); // 5 of 8 shares
    const { D_list, omega_list } = scheme.computeDecryptionShares(sig!, respondingNodes);

    for (const ds of D_list) {
      expect(scheme.verifyDecryptionShare(sig!, ds)).toBe(true);
      expect(verifyDleqShare(sig!.C_1, ds.D_j, ds.c_j, ds.y_j, ds.P_net_j!)).toBe(true);
    }

    const recoveredPk = scheme.trace(sig!, D_list, omega_list);
    expect(recoveredPk).not.toBeNull();
    expect(recoveredPk!.equals(signer.publicKey)).toBe(true);
    expect(pointToStr(recoveredPk!)).toBe(pointToStr(signer.publicKey));

    // Convenience overloads
    expect(scheme.trace(sig!)!.equals(signer.publicKey)).toBe(true);
    expect(scheme.deanonymize(sig!, D_list)!.equals(signer.publicKey)).toBe(true);

    // Malicious node submits forged D_j -> rejected (returns null)
    const corrupted = [...D_list];
    corrupted[0] = {
      ...D_list[0],
      D_j: scheme.keygen().publicKey,
    };
    expect(scheme.verifyDecryptionShare(sig!, corrupted[0])).toBe(false);
    expect(scheme.deanonymize(sig!, corrupted, omega_list)).toBeNull();
  });

  it("supports functional API calls (keygen, sign, verify, link, trace, deanonymize)", () => {
    const pp = new SystemParameters();
    const allShares = generateShares(pp.S_net, 6, 4, pp.q, pp.G);
    for (const s of allShares) {
      pp.nodePublicKeys.set(s.omega, s.P_net_j);
    }
    const keys = Array.from({ length: 4 }, () => keygen(pp));
    const ring = keys.map((k) => k.publicKey);
    pp.L_registry.push(ring);

    const sid = pp.SIDs[0];
    const sigma1 = sign("Doc_1", keys[1].secretKey, ring, sid, pp);
    const sigma2 = sign("Doc_2", keys[1].secretKey, ring, sid, pp);
    expect(sigma1).not.toBeNull();
    expect(sigma2).not.toBeNull();

    expect(verify("Doc_1", sigma1, pp)).toBe(true);
    expect(link(sigma1, "Doc_1", sigma2, "Doc_2", pp)).toBe(true);

    const responding = allShares.slice(0, 4);
    const dleqShares = responding.map((n) =>
      createDleqShare(sigma1!.C_1, n.omega, n.S_net_j, n.P_net_j, pp.G, pp.q)
    );

    const extracted = deanonymize(sigma1!, dleqShares, pp);
    expect(extracted).not.toBeNull();
    expect(extracted!.equals(trace(sigma1!, dleqShares, pp)!)).toBe(true);
    expect(extracted!.equals(keys[1].publicKey)).toBe(true);
  });

  it("maps public keys and SIDs deterministically via hashToPoint", () => {
    const kp = DSLRS.keygen();
    const p1 = hashToPoint(kp.publicKey, "SID_PROJECT_A");
    const p2 = hashToPoint(kp.publicKey, "SID_PROJECT_A");
    const p3 = hashToPoint(kp.publicKey, "SID_PROJECT_B");
    expect(p1.equals(p2)).toBe(true);
    expect(p1.equals(p3)).toBe(false);
  });
});

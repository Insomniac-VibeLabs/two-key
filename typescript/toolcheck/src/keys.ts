// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * Two-Key's hybrid keys and signatures: an Ed25519 key and an ML-DSA-65 (FIPS 204) key, used as one. Both halves
 * sign `two-key-hybrid/1`, a zero byte, `ed25519+ml-dsa-65`, a zero byte, then the message; ML-DSA-65 with the
 * context string `two-key`. A signature is the 64-byte Ed25519 signature then the 3,309-byte ML-DSA-65 one, in
 * standard base64. Only hybrid keys are taken: a lone Ed25519 key or signature is refused.
 *
 * Key files are what Two-Key writes (`two-key tool-key new`): two PEM blocks, Ed25519 first. PKCS#8 for a private
 * key, with ML-DSA-65 in seed form; SubjectPublicKeyInfo for a public key.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

export const HYBRID_ALG = "ed25519+ml-dsa-65";
const HYBRID_LABEL = "two-key-hybrid/1";
const ML_DSA_CONTEXT = new TextEncoder().encode("two-key");
const ED_SIG_BYTES = 64;
const ML_SIG_BYTES = 3309;
const ED_PUB_BYTES = 32;
const ML_PUB_BYTES = 1952;
const SEED_BYTES = 32;
// PKCS#8 of an ML-DSA-65 key in seed form (OID 2.16.840.1.101.3.4.3.18, [0] the 32-byte seed): 22 bytes, then the seed.
const ML_PRIVATE_PREFIX = Buffer.from("3034020100300b0609608648016503040312042280" + "20", "hex");
// SubjectPublicKeyInfo of an ML-DSA-65 key: 22 bytes, then the 1,952-byte key.
const ML_PUBLIC_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export class KeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyError";
  }
}

/** The public half of a hybrid key. */
export class HybridPublicKey {
  readonly ed: KeyObject;
  readonly ml: Uint8Array;

  constructor(ed: KeyObject, ml: Uint8Array) {
    if (ed.asymmetricKeyType !== "ed25519" || ml.length !== ML_PUB_BYTES) {
      throw new KeyError("public_key_invalid: not a hybrid Ed25519 + ML-DSA-65 public key");
    }
    this.ed = ed;
    this.ml = ml;
  }

  /** The 32-byte Ed25519 key then the 1,952-byte ML-DSA-65 key: what fingerprints and pins hash. */
  raw(): Buffer {
    const jwk = this.ed.export({ format: "jwk" });
    return Buffer.concat([Buffer.from(jwk.x ?? "", "base64url"), this.ml]);
  }

  /** `hybrid-sha256:` and the hex SHA-256 of `raw()`. */
  fingerprint(): string {
    return "hybrid-sha256:" + createHash("sha256").update(this.raw()).digest("hex");
  }

  /** `raw()` in standard base64, as a receipt's `key` field carries it. */
  rawBase64(): string {
    return this.raw().toString("base64");
  }
}

/** A hybrid signing key. */
export class HybridPrivateKey {
  readonly ed: KeyObject;
  readonly #mlSecret: Uint8Array;
  readonly publicKey: HybridPublicKey;

  constructor(ed: KeyObject, mlSeed: Uint8Array) {
    if (ed.asymmetricKeyType !== "ed25519" || ed.type !== "private" || mlSeed.length !== SEED_BYTES) {
      throw new KeyError("key_file_invalid: not a hybrid Ed25519 + ML-DSA-65 private key");
    }
    const ml = ml_dsa65.keygen(mlSeed);
    this.ed = ed;
    this.#mlSecret = ml.secretKey;
    this.publicKey = new HybridPublicKey(createPublicKey(ed), ml.publicKey);
  }

  /** The hybrid signature over `message`, in standard base64. */
  sign(message: Uint8Array): string {
    const signed = hybridMessage(message);
    const ed = sign(null, signed, this.ed);
    const ml = ml_dsa65.sign(signed, this.#mlSecret, { context: ML_DSA_CONTEXT });
    return Buffer.concat([ed, ml]).toString("base64");
  }
}

/** What both halves sign: the label, the suite, then the message, separated by zero bytes. */
export function hybridMessage(message: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(`${HYBRID_LABEL}\0${HYBRID_ALG}\0`, "ascii"), message]);
}

/** Strict standard base64, as Python's `b64decode(..., validate=True)` reads it; null otherwise. */
export function decodeBase64(text: string): Buffer | null {
  return text.length % 4 === 0 && BASE64.test(text) ? Buffer.from(text, "base64") : null;
}

/** True only for a hybrid signature by `key` over `message`: both halves must verify. */
export function verifyHybrid(key: HybridPublicKey, message: Uint8Array, signature: unknown): boolean {
  if (typeof signature !== "string") {
    return false;
  }
  const data = decodeBase64(signature);
  if (data?.length !== ED_SIG_BYTES + ML_SIG_BYTES) {
    return false;
  }
  try {
    const signed = hybridMessage(message);
    return verify(null, signed, key.ed, data.subarray(0, ED_SIG_BYTES))
      && ml_dsa65.verify(data.subarray(ED_SIG_BYTES), signed, key.ml, { context: ML_DSA_CONTEXT });
  } catch {
    return false;
  }
}

/**
 * The base64 bodies of the PEM blocks in `text` when it is nothing but blocks with this label (blank lines between
 * are fine); null otherwise.
 */
export function pemBlocks(text: string, label: string): string[] | null {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  const blocks: string[] = [];
  let body: string[] | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (body === null && line.trim() === "") {
      continue;
    }
    if (body === null && line === begin) {
      body = [];
    } else if (body !== null && line === end) {
      blocks.push(body.join(""));
      body = null;
    } else if (body !== null && !line.startsWith("-----")) {
      body.push(line);
    } else {
      return null;
    }
  }
  return blocks.length > 0 && body === null ? blocks : null;
}

function pemBody(body: string): Buffer {
  const data = decodeBase64(body);
  if (data === null) {
    throw new KeyError("not PEM");
  }
  return data;
}

function afterPrefix(der: Buffer, prefix: Buffer, length: number): Uint8Array | null {
  if (der.length !== prefix.length + length || !der.subarray(0, prefix.length).equals(prefix)) {
    return null;
  }
  return new Uint8Array(der.subarray(prefix.length));
}

/** A hybrid private key from the two PKCS#8 PEM blocks Two-Key writes. */
export function privateKeyFromPem(text: string, what: string): HybridPrivateKey {
  if (text.trimStart().startsWith("-----BEGIN TWO-KEY ENCRYPTED PRIVATE KEY-----")) {
    throw new KeyError(`key_file_encrypted: ${what} is encrypted; the tool check needs an unencrypted tool key, `
      + "readable by the tool's account only");
  }
  const invalid = new KeyError(`key_file_invalid: ${what} is not a hybrid Ed25519 + ML-DSA-65 private key `
    + "(two PEM blocks, Ed25519 first)");
  const blocks = pemBlocks(text, "PRIVATE KEY");
  if (blocks?.length !== 2) {
    throw invalid;
  }
  try {
    const ed = createPrivateKey({ key: pemBody(blocks[0]), format: "der", type: "pkcs8" });
    const seed = afterPrefix(pemBody(blocks[1]), ML_PRIVATE_PREFIX, SEED_BYTES);
    if (seed === null) {
      throw invalid;
    }
    return new HybridPrivateKey(ed, seed);
  } catch {
    throw invalid;
  }
}

/** A hybrid public key from the two SubjectPublicKeyInfo PEM blocks Two-Key writes. */
export function publicKeyFromPem(text: string, what: string): HybridPublicKey {
  const invalid = new KeyError(`public_key_invalid: ${what} is not a hybrid Ed25519 + ML-DSA-65 public key `
    + "(two PEM blocks, Ed25519 first)");
  const blocks = pemBlocks(text, "PUBLIC KEY");
  if (blocks?.length !== 2) {
    throw invalid;
  }
  try {
    const ed = createPublicKey({ key: pemBody(blocks[0]), format: "der", type: "spki" });
    const ml = afterPrefix(pemBody(blocks[1]), ML_PUBLIC_PREFIX, ML_PUB_BYTES);
    if (ml === null) {
      throw invalid;
    }
    return new HybridPublicKey(ed, ml);
  } catch {
    throw invalid;
  }
}

/** A hybrid public key from its raw form in standard base64 (a receipt's `key`). */
export function publicKeyFromRaw(raw: string): HybridPublicKey {
  const data = decodeBase64(raw);
  if (data?.length !== ED_PUB_BYTES + ML_PUB_BYTES) {
    throw new KeyError("public_key_invalid: not a hybrid Ed25519 + ML-DSA-65 public key");
  }
  const ed = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: data.subarray(0, ED_PUB_BYTES).toString("base64url") },
    format: "jwk",
  });
  return new HybridPublicKey(ed, new Uint8Array(data.subarray(ED_PUB_BYTES)));
}

// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * The tool's side of Two-Key's tool check (docs/TOOL_CHECK.md), as `two_key.toolcheck` does it in Python: the eight
 * checks a tool runs before its own code, and the receipt it signs after. Any failure, including an error inside
 * the helper, is a refusal, never a pass.
 */

import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { readFileSync } from "node:fs";
import { canonicalHash, canonicalText } from "./canonical.ts";
import { readOwnerOnly } from "./files.ts";
import { HYBRID_ALG, HybridPrivateKey, HybridPublicKey, privateKeyFromPem, publicKeyFromPem, verifyHybrid } from "./keys.ts";
import { SeenRecord } from "./seen.ts";

export const STAMP_PREFIX = "tks1";
export const RECEIPT_PREFIX = "tkr1";
export const STAMP_LABEL = "two-key-redeem-stamp/1";
export const RECEIPT_LABEL = "two-key-tool-receipt/1";
/** The key the proxy and the tool use in MCP `_meta`, on the request and on the result. */
export const META_KEY = "io.github.insomniac-vibelabs/two-key";
/** Fixed and not configurable: how far the tool's clock may be behind or ahead of Two-Key's. */
export const CLOCK_ALLOWANCE_SECONDS = 5;
/** The longest a token may live, as Two-Key issues them. */
export const MAX_TTL_SECONDS = 300;
/** A stamp or receipt is under 10,000 characters; anything far longer is refused unread. */
export const MAX_OBJECT_CHARS = 16384;
const MAX_KEY_FILE_BYTES = 64 * 1024;
const MAX_CONFIG_BYTES = 64 * 1024;
/** What the tool refuses with, in check order. */
export const REFUSALS = ["check_missing", "stamp_invalid", "token_invalid", "stamp_mismatch", "tool_mismatch",
  "args_mismatch", "expired", "replayed", "check_failed"] as const;
export type Refusal = (typeof REFUSALS)[number];
const CONFIG_KEYS = ["tool", "capability_public_key", "capability_key_fingerprint", "stamp_public_key",
  "stamp_key_fingerprint", "tool_private_key", "seen_record"] as const;
const ASCII = /^[\x20-\x7e]*$/;

export type JsonObject = Record<string, unknown>;

/** A check that failed. `reason` is a code from `REFUSALS`. */
export class ToolCheckError extends Error {
  readonly reason: string;

  constructor(reason: string) {
    super(reason);
    this.name = "ToolCheckError";
    this.reason = reason;
  }
}

/** A call that passed the checks: what its receipt names. */
export interface CheckedCall {
  readonly jti: string;
  readonly tool: string;
  readonly stampHash: string;
}

/** `sha256:` of a token, stamp or receipt as sent (its ASCII text). */
export function textHash(text: string): string {
  return "sha256:" + createHash("sha256").update(text, "ascii").digest("hex");
}

/** `sha256:` of the canonical JSON of the arguments as the tool receives them. */
export function toolArgsHash(args: unknown): string {
  return canonicalHash(args);
}

/** `sha256:` of the canonical JSON of an MCP result in wire form, without its `_meta`. */
export function resultHash(result: JsonObject): string {
  const rest: JsonObject = {};
  for (const [key, value] of Object.entries(result)) {
    if (key !== "_meta") {
      rest[key] = value;
    }
  }
  return canonicalHash(rest);
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function message(label: string, body: string): Buffer {
  return Buffer.from(`${label}\0${body}`, "ascii");
}

function decodeBody(body: string): unknown {
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
}

/** `<prefix>.<base64url canonical body>.<base64 signature over label, 0x00, body text>`. */
export function seal(prefix: string, label: string, key: HybridPrivateKey, body: JsonObject): string {
  const text = Buffer.from(canonicalText(body), "ascii").toString("base64url");
  return `${prefix}.${text}.${key.sign(message(label, text))}`;
}

function parts(text: unknown, prefix: string, limit: number): [string, string] | null {
  if (typeof text !== "string" || text.length > limit || !ASCII.test(text) || !text.startsWith(prefix + ".")) {
    return null;
  }
  const pieces = text.split(".");
  return pieces.length === 3 ? [pieces[1], pieces[2]] : null;
}

/** The body of a stamp or receipt whose signature verifies with `key`. Throws `<what>_invalid`. */
export function openSealed(prefix: string, label: string, key: HybridPublicKey, text: unknown, what: string): JsonObject {
  const invalid = new ToolCheckError(`${what}_invalid`);
  const got = parts(text, prefix, MAX_OBJECT_CHARS);
  if (got === null) {
    throw invalid;
  }
  let body: unknown;
  try {
    body = decodeBody(got[0]);
  } catch {
    throw invalid;
  }
  if (!isObject(body) || body.v !== 1 || body.alg !== HYBRID_ALG || !verifyHybrid(key, message(label, got[0]), got[1])) {
    throw invalid;
  }
  return body;
}

/** The payload of a `tk2` (hybrid) token signed by `key`; the times are checked by the caller. */
export function tokenPayload(key: HybridPublicKey, token: unknown): JsonObject {
  const invalid = new ToolCheckError("token_invalid");
  const got = parts(token, "tk2", MAX_OBJECT_CHARS * 4);
  if (got === null || !verifyHybrid(key, Buffer.from(got[0], "ascii"), got[1])) {
    throw invalid;
  }
  let payload: unknown;
  try {
    payload = decodeBody(got[0]);
  } catch {
    throw invalid;
  }
  if (!isObject(payload) || payload.v !== 2 || payload.alg !== HYBRID_ALG) {
    throw invalid;
  }
  return payload;
}

/** Two-Key's entry in a request's `_meta`, or null. */
function mine(meta: unknown): JsonObject | null {
  const entry = isObject(meta) ? meta[META_KEY] : undefined;
  return isObject(entry) ? entry : null;
}

function isTime(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** What a checking tool needs; `ToolCheckConfig.load` reads it from the same check.json the Python helper reads. */
export interface ToolCheckConfig {
  readonly tool: string;
  readonly capabilityKey: HybridPublicKey;
  readonly stampKey: HybridPublicKey;
  readonly toolKey: HybridPrivateKey;
  readonly seenRecord: string;
}

function configPath(base: string, value: string): string {
  const expanded = value === "~" || value.startsWith("~/") ? join(homedir(), value.slice(1)) : value;
  return isAbsolute(expanded) ? expanded : resolve(base, expanded);
}

function readConfigObject(path: string): Record<(typeof CONFIG_KEYS)[number], string> {
  const text = readFileSync(path, "utf8");
  const data: unknown = text.length <= MAX_CONFIG_BYTES ? JSON.parse(text) : null;
  const keys = isObject(data) ? Object.keys(data) : [];
  if (!isObject(data) || keys.length !== CONFIG_KEYS.length
      || !CONFIG_KEYS.every((key) => typeof data[key] === "string")) {
    throw new ToolCheckError(`${path}: expected exactly the string keys ${JSON.stringify(CONFIG_KEYS)}`);
  }
  return data as Record<(typeof CONFIG_KEYS)[number], string>;
}

function pinnedPublicKey(path: string, file: string, fingerprint: string, name: string): HybridPublicKey {
  const key = publicKeyFromPem(readFileSync(file, "utf8"), `${path}: ${name}_public_key`);
  if (key.fingerprint() !== fingerprint) {
    throw new ToolCheckError(`${path}: ${name}_public_key does not have the pinned fingerprint`);
  }
  return key;
}

/** Read a check.json (docs/TOOL_CHECK.md). Each public key must have its pinned fingerprint. */
export function loadConfig(path: string): ToolCheckConfig {
  const data = readConfigObject(path);
  const base = dirname(resolve(path));
  const keyFile = configPath(base, data.tool_private_key);
  return {
    tool: data.tool,
    capabilityKey: pinnedPublicKey(path, configPath(base, data.capability_public_key), data.capability_key_fingerprint,
      "capability"),
    stampKey: pinnedPublicKey(path, configPath(base, data.stamp_public_key), data.stamp_key_fingerprint, "stamp"),
    toolKey: privateKeyFromPem(readOwnerOnly(keyFile, "key_file", MAX_KEY_FILE_BYTES), keyFile),
    seenRecord: configPath(base, data.seen_record),
  };
}

/** An MCP tool result, as the TypeScript SDK's `CallToolResult` and the wire carry it. */
export type ToolResult = JsonObject;

function errorName(error: unknown): string {
  const name = error instanceof Error ? error.constructor.name : "";
  return /^[A-Za-z_$][\w$]{0,63}$/.test(name) ? name : "Error";
}

/**
 * A result in the wire form the gateway reads and hashes: JSON-safe (what `JSON.stringify` drops is gone), with
 * `isError` and `resultType` written out. The gateway's MCP SDK fills in `false` and `"complete"` when they are left
 * out, so a result that leaves them out would hash differently on each side. Send what this returns, and sign it.
 */
export function wireResult(result: ToolResult): ToolResult {
  const wire = JSON.parse(JSON.stringify(result)) as ToolResult;
  return { ...wire, isError: wire.isError ?? false, resultType: wire.resultType ?? "complete" };
}

function textResult(text: string): ToolResult {
  return { content: [{ type: "text", text }], isError: true };
}

/** The checks a tool runs before its own code, and the receipt it signs after. */
export class ToolChecker {
  readonly config: ToolCheckConfig;
  readonly #seen: SeenRecord;
  readonly #clock: () => number;
  readonly #publicRaw: string;

  private constructor(config: ToolCheckConfig, seen: SeenRecord, clock: () => number) {
    this.config = config;
    this.#seen = seen;
    this.#clock = clock;
    this.#publicRaw = config.toolKey.publicKey.rawBase64();
  }

  /** A checker from a check.json path, or from a config already read. `clock` gives Unix seconds. */
  static async load(source: string | ToolCheckConfig, clock: () => number = () => Date.now() / 1000):
      Promise<ToolChecker> {
    const config = typeof source === "string" ? loadConfig(source) : source;
    return new ToolChecker(config, await SeenRecord.open(config.seenRecord), clock);
  }

  /** Checks 1 to 8, in order; throws `ToolCheckError` at the first that fails. Any other error is `check_failed`. */
  check(args: unknown, meta: unknown): CheckedCall {
    try {
      return this.#check(args, meta);
    } catch (e) {
      throw e instanceof ToolCheckError ? e : new ToolCheckError("check_failed");
    }
  }

  #check(args: unknown, meta: unknown): CheckedCall {
    const entry = mine(meta) ?? {};
    const token = entry.token;
    const stamp = entry.stamp;
    if (typeof token !== "string" || typeof stamp !== "string") {
      throw new ToolCheckError("check_missing");                                          // 1
    }
    const stamped = openSealed(STAMP_PREFIX, STAMP_LABEL, this.config.stampKey, stamp, "stamp");   // 2
    const payload = tokenPayload(this.config.capabilityKey, token);                       // 3
    if (stamped.token_hash !== textHash(token) || stamped.jti !== payload.jti || stamped.tool !== payload.tool) {
      throw new ToolCheckError("stamp_mismatch");                                         // 4
    }
    if (payload.tool !== this.config.tool) {
      throw new ToolCheckError("tool_mismatch");                                          // 5
    }
    this.#checkArgs(args, payload, stamped);                                              // 6
    const exp = this.#checkTimes(payload);                                                // 7
    const jti = payload.jti;
    if (typeof jti !== "string" || jti === "" || !this.#seen.add(jti, exp + CLOCK_ALLOWANCE_SECONDS, this.#clock())) {
      throw new ToolCheckError("replayed");                                               // 8
    }
    return { jti, tool: this.config.tool, stampHash: textHash(stamp) };
  }

  #checkArgs(args: unknown, payload: JsonObject, stamped: JsonObject): void {
    let received: string;
    try {
      received = toolArgsHash(args);
    } catch {
      throw new ToolCheckError("args_mismatch");
    }
    if (received !== payload.tool_args_hash || received !== stamped.tool_args_hash) {
      throw new ToolCheckError("args_mismatch");
    }
  }

  #checkTimes(payload: JsonObject): number {
    const now = this.#clock();
    const { exp, iat } = payload;
    if (!isTime(exp) || !isTime(iat) || exp - iat > MAX_TTL_SECONDS || now > exp + CLOCK_ALLOWANCE_SECONDS
        || iat > now + CLOCK_ALLOWANCE_SECONDS) {
      throw new ToolCheckError("expired");
    }
    return exp;
  }

  /** The receipt for a call that ran: over the jti, the stamp and the result (MCP wire form). */
  receipt(call: CheckedCall, result: ToolResult): string {
    return this.#sign(call.jti, call.stampHash, resultHash(result), "ran");
  }

  /** The receipt for a refused call: the tool did not run. Names the jti when the token could be read. */
  refusal(reason: string, meta: unknown): string {
    const entry = mine(meta);
    let jti: string | null = null;
    let stampHash: string | null = null;
    if (entry !== null) {
      try {
        const got = tokenPayload(this.config.capabilityKey, entry.token).jti;
        jti = typeof got === "string" ? got : null;
      } catch {
        jti = null;
      }
      const stamp = entry.stamp;
      if (typeof stamp === "string" && stamp.length <= MAX_OBJECT_CHARS && ASCII.test(stamp)) {
        stampHash = textHash(stamp);
      }
    }
    return this.#sign(jti, stampHash, null, `refused:${reason}`);
  }

  #sign(jti: string | null, stampHash: string | null, result: string | null, outcome: string): string {
    return seal(RECEIPT_PREFIX, RECEIPT_LABEL, this.config.toolKey, {
      v: 1, alg: HYBRID_ALG, key: this.#publicRaw, jti, tool: this.config.tool, stamp_hash: stampHash,
      result_hash: result, outcome, iat: Math.trunc(this.#clock()),
    });
  }

  /**
   * For an MCP server: check, then `run(args)`, and return its result with the receipt in `_meta`. A refused call
   * returns an error result with a refusal receipt, and `run` is never called. When `run` throws, the call returns
   * `tool failed: <error class>` as an error result with an ordinary receipt (never the error's message), so the
   * gateway sees a signed failure, not an unanswered call.
   */
  async mcpCall<A>(args: A, meta: unknown, run: (args: A) => ToolResult | Promise<ToolResult>): Promise<ToolResult> {
    let call: CheckedCall;
    try {
      call = this.check(args, meta);
    } catch (e) {
      const reason = e instanceof ToolCheckError ? e.reason : "check_failed";
      return { ...textResult(`two-key tool check refused this call: ${reason}`),
        _meta: { [META_KEY]: { receipt: this.refusal(reason, meta) } } };
    }
    let result: ToolResult;
    try {
      result = await run(args);
    } catch (e) {
      result = textResult(`tool failed: ${errorName(e)}`);
    }
    const wire = wireResult(result);
    const metaOut = isObject(wire._meta) ? { ...wire._meta } : {};
    metaOut[META_KEY] = { receipt: this.receipt(call, wire) };
    return { ...wire, _meta: metaOut };
  }
}

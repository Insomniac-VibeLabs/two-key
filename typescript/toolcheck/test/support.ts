// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/** Test keys from fixed seeds, and tokens and stamps made the way Two-Key makes them. */

import { createPrivateKey } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { canonicalText } from "../src/canonical.ts";
import { HYBRID_ALG, HybridPrivateKey } from "../src/keys.ts";
import { STAMP_LABEL, STAMP_PREFIX, ToolChecker, seal, textHash, toolArgsHash, type JsonObject } from "../src/toolcheck.ts";

const ED_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
export const IAT = 1_800_000_000;
export const ARGS = { amount: 12.5, vendor: "ada" };
export const RESULT = { content: [{ type: "text", text: "paid" }], isError: false };

/** The hybrid key from seeds: Ed25519 from 32 bytes of `n`, ML-DSA-65 from 32 bytes of `n + 0x10`. */
export function seeded(n: number): HybridPrivateKey {
  const ed = createPrivateKey({ key: Buffer.concat([ED_PKCS8_PREFIX, Buffer.alloc(32, n)]), format: "der", type: "pkcs8" });
  return new HybridPrivateKey(ed, new Uint8Array(32).fill(n + 0x10));
}

export const CAPABILITY = seeded(1);
export const STAMP_KEY = seeded(2);
export const TOOL_KEY = seeded(3);

export function payload(overrides: JsonObject = {}): JsonObject {
  return { v: 2, alg: HYBRID_ALG, jti: "0123456789abcdef0123456789abcdef", tool: "pay_vendor",
    iat: IAT, exp: IAT + 120, tool_args_hash: toolArgsHash(ARGS), ...overrides };
}

/** A tk2 token: the body signed with no label, by the capability key. */
export function token(body: JsonObject = payload(), key: HybridPrivateKey = CAPABILITY): string {
  const text = Buffer.from(canonicalText(body), "ascii").toString("base64url");
  return `tk2.${text}.${key.sign(Buffer.from(text, "ascii"))}`;
}

/** The payload inside a token made by `token`. */
export function payloadOf(tok: string): JsonObject {
  return JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString("utf8")) as JsonObject;
}

/** A redeem stamp for `tok`, signed by the stamp key, with `overrides` in its body. */
export function stamp(tok: string, overrides: JsonObject = {}, key: HybridPrivateKey = STAMP_KEY): string {
  const body = payloadOf(tok);
  return seal(STAMP_PREFIX, STAMP_LABEL, key, { v: 1, alg: HYBRID_ALG, jti: body.jti, tool: body.tool,
    tool_args_hash: body.tool_args_hash, token_hash: textHash(tok), seq: 8, iat: IAT + 1, ...overrides });
}

export function meta(tok: string, stmp: string): JsonObject {
  return { "io.github.insomniac-vibelabs/two-key": { token: tok, stamp: stmp } };
}

/** A temporary folder, removed by the returned function. */
export function tempDir(): [string, () => void] {
  mkdirSync(join(process.cwd(), "build", "tmp"), { recursive: true });
  const dir = mkdtempSync(join(process.cwd(), "build", "tmp", "t-"));
  return [dir, () => { rmSync(dir, { recursive: true, force: true }); }];
}

export async function checker(dir: string, now: number = IAT + 2, tool = "pay_vendor"): Promise<ToolChecker> {
  return ToolChecker.load({ tool, capabilityKey: CAPABILITY.publicKey, stampKey: STAMP_KEY.publicKey,
    toolKey: TOOL_KEY, seenRecord: join(dir, "seen.sqlite") }, () => now);
}

/** The published test vectors in docs/TOOL_CHECK.md. */
export function vectors(): JsonObject {
  // A Windows checkout may have CRLF line ends.
  const doc = readFileSync(join(process.cwd(), "..", "..", "docs", "TOOL_CHECK.md"), "utf8").replaceAll("\r\n", "\n");
  const start = doc.indexOf("<!-- vectors -->\n```json\n");
  const end = doc.indexOf("```\n<!-- /vectors -->");
  if (start < 0 || end < start) {
    throw new Error("no vectors in docs/TOOL_CHECK.md");
  }
  return JSON.parse(doc.slice(start + "<!-- vectors -->\n```json\n".length, end)) as JsonObject;
}

export function joined(signed: unknown): string {
  const parts = signed as { prefix: string; body: string; signature: string };
  return `${parts.prefix}.${parts.body}.${parts.signature}`;
}

// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/** The published test vectors (docs/TOOL_CHECK.md): the same keys, hashes and bodies as Python, byte for byte. */

import assert from "node:assert/strict";
import { test } from "node:test";
import { publicKeyFromRaw } from "../src/keys.ts";
import { RECEIPT_LABEL, RECEIPT_PREFIX, ToolChecker, openSealed, resultHash, toolArgsHash,
  type JsonObject } from "../src/toolcheck.ts";
import { CAPABILITY, STAMP_KEY, TOOL_KEY, checker, joined, meta, tempDir, vectors } from "./support.ts";

const V = vectors();

test("the keys from the fixed seeds are the published keys", () => {
  for (const [name, key] of [["capability", CAPABILITY], ["stamp", STAMP_KEY], ["tool", TOOL_KEY]] as const) {
    assert.equal(key.publicKey.rawBase64(), V[`${name}_public_key`]);
    assert.equal(key.publicKey.fingerprint(), V[`${name}_key_fingerprint`]);
    assert.equal(publicKeyFromRaw(V[`${name}_public_key`] as string).fingerprint(), V[`${name}_key_fingerprint`]);
  }
});

test("the argument and result hashes are the published ones", () => {
  assert.equal(toolArgsHash(V.arguments), V.tool_args_hash);
  assert.equal(resultHash(V.result as JsonObject), V.result_hash);
});

test("the published token and stamp pass all eight checks, and the receipt made here matches the published body",
  async () => {
    const [dir, done] = tempDir();
    try {
      const tool: ToolChecker = await checker(dir, V.checked_at as number);
      const call = tool.check(V.arguments, meta(joined(V.token), joined(V.stamp)));
      const made = tool.receipt(call, V.result as JsonObject).split(".");
      assert.equal(made[1], (V.receipt as JsonObject).body);
    } finally {
      done();
    }
  });

test("the published receipt verifies with the tool key and the receipt label only", () => {
  const body = openSealed(RECEIPT_PREFIX, RECEIPT_LABEL, TOOL_KEY.publicKey, joined(V.receipt), "receipt");
  assert.equal(body.outcome, "ran");
  assert.throws(() => openSealed(RECEIPT_PREFIX, "two-key-redeem-stamp/1", TOOL_KEY.publicKey, joined(V.receipt),
    "receipt"), { name: "ToolCheckError", message: "receipt_invalid" });
});

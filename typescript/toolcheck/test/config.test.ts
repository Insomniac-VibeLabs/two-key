// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/** check.json and the key files, as Two-Key writes them, and every way they are refused. */

import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { chmodSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { decodeBase64, HybridPublicKey, pemBlocks, privateKeyFromPem, publicKeyFromPem, publicKeyFromRaw,
  verifyHybrid } from "../src/keys.ts";
import { WINDOWS } from "../src/files.ts";
import { ToolChecker, loadConfig } from "../src/toolcheck.ts";
import { ARGS, CAPABILITY, IAT, STAMP_KEY, TOOL_KEY, meta, stamp, tempDir, token } from "./support.ts";

const ML_PRIVATE_PREFIX = "3034020100300b060960864801650304031204228020";
const ML_PUBLIC_PREFIX = "308207b2300b0609608648016503040312038207a100";

function pem(label: string, der: Buffer): string {
  const lines = der.toString("base64").match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

function publicPem(key: HybridPublicKey): string {
  const ed = key.ed.export({ format: "pem", type: "spki" }).toString();
  return ed + pem("PUBLIC KEY", Buffer.concat([Buffer.from(ML_PUBLIC_PREFIX, "hex"), key.ml]));
}

function privatePem(seed: number): string {
  const ed = TOOL_KEY.ed.export({ format: "pem", type: "pkcs8" }).toString();
  return ed + pem("PRIVATE KEY", Buffer.concat([Buffer.from(ML_PRIVATE_PREFIX, "hex"), Buffer.alloc(32, seed)]));
}

function writeConfig(dir: string, overrides: Record<string, unknown> = {}): string {
  writeFileSync(join(dir, "cap.pub.pem"), publicPem(CAPABILITY.publicKey));
  writeFileSync(join(dir, "stamp.pub.pem"), publicPem(STAMP_KEY.publicKey));
  writeFileSync(join(dir, "tool.pem"), privatePem(0x13), { mode: 0o600 });
  const config = join(dir, "check.json");
  writeFileSync(config, JSON.stringify({
    tool: "pay_vendor", capability_public_key: "cap.pub.pem",
    capability_key_fingerprint: CAPABILITY.publicKey.fingerprint(), stamp_public_key: join(dir, "stamp.pub.pem"),
    stamp_key_fingerprint: STAMP_KEY.publicKey.fingerprint(), tool_private_key: "tool.pem", seen_record: "seen.sqlite",
    ...overrides,
  }));
  return config;
}

async function inDir(work: (dir: string) => Promise<void> | void): Promise<void> {
  const [dir, done] = tempDir();
  try {
    await work(dir);
  } finally {
    done();
  }
}

test("a check.json as the Python helper reads it loads, and its checker passes a call", async () => {
  await inDir(async (dir) => {
    const config = loadConfig(writeConfig(dir));
    assert.equal(config.toolKey.publicKey.fingerprint(), TOOL_KEY.publicKey.fingerprint());
    assert.equal(config.seenRecord, join(dir, "seen.sqlite"));
    const checker = await ToolChecker.load(join(dir, "check.json"), () => IAT + 2);
    const tok = token();
    assert.equal(checker.check(ARGS, meta(tok, stamp(tok))).tool, "pay_vendor");
  });
});

test("a check.json with a missing, extra or non-string key is refused", async () => {
  await inDir((dir) => {
    for (const overrides of [{ extra: "x" }, { tool: 1 }, { seen_record: undefined }]) {
      assert.throws(() => loadConfig(writeConfig(dir, overrides)), /expected exactly the string keys/);
    }
  });
});

test("a public key that is not the pinned one is refused", async () => {
  await inDir((dir) => {
    const path = writeConfig(dir, { stamp_key_fingerprint: CAPABILITY.publicKey.fingerprint() });
    assert.throws(() => loadConfig(path), /stamp_public_key does not have the pinned fingerprint/);
  });
});

test("a tool key others can read, a linked one, an encrypted one, or a big one is refused", { skip: WINDOWS },
  async () => {
    await inDir((dir) => {
      const path = writeConfig(dir);
      chmodSync(join(dir, "tool.pem"), 0o644);
      assert.throws(() => loadConfig(path), /key_file_insecure: .* mode 0644/);
      chmodSync(join(dir, "tool.pem"), 0o600);
      symlinkSync(join(dir, "tool.pem"), join(dir, "link.pem"));
      assert.throws(() => loadConfig(writeConfig(dir, { tool_private_key: "link.pem" })), /key_file_unreadable/);
      writeFileSync(join(dir, "enc.pem"), "-----BEGIN TWO-KEY ENCRYPTED PRIVATE KEY-----\nAAAA\n", { mode: 0o600 });
      assert.throws(() => loadConfig(writeConfig(dir, { tool_private_key: "enc.pem" })), /key_file_encrypted/);
      writeFileSync(join(dir, "big.pem"), "x".repeat(70000), { mode: 0o600 });
      assert.throws(() => loadConfig(writeConfig(dir, { tool_private_key: "big.pem" })), /key_file_invalid: .* over/);
      assert.throws(() => loadConfig(writeConfig(dir, { tool_private_key: "none.pem" })), /key_file_unreadable/);
    });
  });

test("a seen record others can read is refused", { skip: WINDOWS }, async () => {
  await inDir(async (dir) => {
    writeFileSync(join(dir, "seen.sqlite"), "", { mode: 0o644 });
    chmodSync(join(dir, "seen.sqlite"), 0o644);
    await assert.rejects(ToolChecker.load(writeConfig(dir)), /seen record .* readable by group or others/);
  });
});

test("only two PEM blocks of the right kinds, Ed25519 first, make a key", () => {
  const good = publicPem(CAPABILITY.publicKey);
  assert.equal(publicKeyFromPem(good, "k").fingerprint(), CAPABILITY.publicKey.fingerprint());
  const edOnly = CAPABILITY.ed.export({ format: "pem", type: "pkcs8" }).toString();
  const edPublic = createPublicKey(CAPABILITY.ed).export({ format: "pem", type: "spki" }).toString();
  for (const bad of [edPublic, `${good}${edPublic}`, `junk\n${good}`, `${good}junk`, good.replace("PUBLIC", "PRIVATE"),
    edPublic + edPublic, good.replace(/\n-----END PUBLIC KEY-----\n$/, "!\n-----END PUBLIC KEY-----\n")]) {
    assert.throws(() => publicKeyFromPem(bad, "k"), /public_key_invalid/);
  }
  assert.equal(privateKeyFromPem(privatePem(0x13), "k").publicKey.fingerprint(), TOOL_KEY.publicKey.fingerprint());
  for (const bad of [edOnly, edOnly + edOnly, privatePem(0x13).replace("MDQCAQAwCwYJYIZIAWUDBAMS", "MDQCAQAwCwYJYIZIAWUDBAMR")]) {
    assert.throws(() => privateKeyFromPem(bad, "k"), /key_file_invalid/);
  }
  assert.equal(pemBlocks("", "PUBLIC KEY"), null);
});

test("raw keys and base64 are read strictly", () => {
  assert.equal(publicKeyFromRaw(CAPABILITY.publicKey.rawBase64()).fingerprint(), CAPABILITY.publicKey.fingerprint());
  for (const bad of ["AAAA", `${CAPABILITY.publicKey.rawBase64()}AAAA`, "not base64"]) {
    assert.throws(() => publicKeyFromRaw(bad), /public_key_invalid/);
  }
  assert.equal(decodeBase64("AAA"), null);
  assert.equal(decodeBase64("A=AA"), null);
  assert.deepEqual(decodeBase64("AAE="), Buffer.from([0, 1]));
  assert.throws(() => new HybridPublicKey(CAPABILITY.ed, new Uint8Array(3)), /public_key_invalid/);
});

test("a signature is good only with both halves, over the same message, by the same key", () => {
  const message = Buffer.from("m");
  const signature = CAPABILITY.sign(message);
  assert.ok(verifyHybrid(CAPABILITY.publicKey, message, signature));
  assert.ok(!verifyHybrid(STAMP_KEY.publicKey, message, signature));
  assert.ok(!verifyHybrid(CAPABILITY.publicKey, Buffer.from("n"), signature));
  assert.ok(!verifyHybrid(CAPABILITY.publicKey, message, 7));
  const data = Buffer.from(signature, "base64");
  assert.ok(!verifyHybrid(CAPABILITY.publicKey, message, data.subarray(0, 64).toString("base64")));
  data[100] ^= 1;
  assert.ok(!verifyHybrid(CAPABILITY.publicKey, message, data.toString("base64")));
});

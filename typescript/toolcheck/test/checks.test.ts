// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/** The eight checks in order, the receipts, and `mcpCall`. */

import assert from "node:assert/strict";
import { test } from "node:test";
import { RECEIPT_LABEL, RECEIPT_PREFIX, META_KEY, ToolCheckError, openSealed, resultHash,
  type JsonObject, type ToolChecker, type ToolResult, wireResult } from "../src/toolcheck.ts";
import { ARGS, CAPABILITY, IAT, RESULT, STAMP_KEY, TOOL_KEY, checker, meta, payload, seeded, stamp, tempDir,
  token } from "./support.ts";

async function withChecker(work: (tool: ToolChecker, dir: string) => Promise<void> | void,
  now: number = IAT + 2, name = "pay_vendor"): Promise<void> {
  const [dir, done] = tempDir();
  try {
    await work(await checker(dir, now, name), dir);
  } finally {
    done();
  }
}

function refusedWith(tool: ToolChecker, args: unknown, requestMeta: unknown, reason: string): void {
  assert.throws(() => tool.check(args, requestMeta), (e: unknown) => e instanceof ToolCheckError && e.reason === reason);
}

function receiptBody(result: ToolResult): JsonObject {
  const entry = (result._meta as JsonObject)[META_KEY] as JsonObject;
  return openSealed(RECEIPT_PREFIX, RECEIPT_LABEL, TOOL_KEY.publicKey, entry.receipt, "receipt");
}

const TOKEN = token();
const STAMP = stamp(TOKEN);

test("a good call passes, and its receipt covers the jti, the stamp and the result", async () => {
  await withChecker((tool) => {
    const call = tool.check(ARGS, meta(TOKEN, STAMP));
    const body = openSealed(RECEIPT_PREFIX, RECEIPT_LABEL, TOOL_KEY.publicKey, tool.receipt(call, RESULT), "receipt");
    assert.equal(body.jti, payload().jti);
    assert.equal(body.outcome, "ran");
    assert.equal(body.result_hash, resultHash(RESULT));
    assert.equal(body.key, TOOL_KEY.publicKey.rawBase64());
  });
});

test("1: no token or stamp is check_missing", async () => {
  await withChecker((tool) => {
    for (const bad of [undefined, null, {}, { [META_KEY]: "x" }, { [META_KEY]: { token: TOKEN } }]) {
      refusedWith(tool, ARGS, bad, "check_missing");
    }
  });
});

test("2: a stamp signed by another key, with another label, or malformed is stamp_invalid", async () => {
  await withChecker((tool) => {
    const others = [stamp(TOKEN, {}, CAPABILITY), "tks1.e30.AAAA", STAMP.replace("tks1.", "tkr1."),
      `${STAMP}.x`, STAMP.slice(0, -4), "tks1.!!!!.sig", "x".repeat(20000)];
    for (const bad of others) {
      refusedWith(tool, ARGS, meta(TOKEN, bad), "stamp_invalid");
    }
  });
});

test("3: a token signed by another key, or not a hybrid tk2 payload, is token_invalid", async () => {
  await withChecker((tool) => {
    const forged = token(payload(), STAMP_KEY);
    refusedWith(tool, ARGS, meta(forged, stamp(forged)), "token_invalid");
    const old = token(payload({ v: 1 }));
    refusedWith(tool, ARGS, meta(old, stamp(old)), "token_invalid");
    const tk1 = TOKEN.replace("tk2.", "tk1.");
    refusedWith(tool, ARGS, meta(tk1, stamp(tk1)), "token_invalid");
  });
});

test("4: a stamp for another token, jti or tool is stamp_mismatch", async () => {
  await withChecker((tool) => {
    for (const overrides of [{ token_hash: "sha256:" + "0".repeat(64) }, { jti: "other" }, { tool: "read_report" }]) {
      refusedWith(tool, ARGS, meta(TOKEN, stamp(TOKEN, overrides)), "stamp_mismatch");
    }
  });
});

test("5: a token for another tool is tool_mismatch", async () => {
  await withChecker((tool) => { refusedWith(tool, ARGS, meta(TOKEN, STAMP), "tool_mismatch"); }, IAT + 2, "read_report");
});

test("6: changed arguments, or a stamp with another arguments hash, is args_mismatch", async () => {
  await withChecker((tool) => {
    refusedWith(tool, { ...ARGS, amount: 13 }, meta(TOKEN, STAMP), "args_mismatch");
    refusedWith(tool, { ...ARGS, extra: undefined }, meta(TOKEN, STAMP), "args_mismatch");
    refusedWith(tool, ARGS, meta(TOKEN, stamp(TOKEN, { tool_args_hash: "sha256:x" })), "args_mismatch");
  });
});

test("7: an expired token, one from the future, or one that lives too long is expired", async () => {
  await withChecker((tool) => { refusedWith(tool, ARGS, meta(TOKEN, STAMP), "expired"); }, IAT + 126);
  await withChecker((tool) => { refusedWith(tool, ARGS, meta(TOKEN, STAMP), "expired"); }, IAT - 6);
  for (const times of [{ exp: IAT + 301 }, { exp: "soon" }, { iat: null }]) {
    const tok = token(payload(times));
    await withChecker((tool) => { refusedWith(tool, ARGS, meta(tok, stamp(tok)), "expired"); });
  }
  await withChecker((tool) => { assert.equal(tool.check(ARGS, meta(TOKEN, STAMP)).jti, payload().jti); }, IAT + 125);
});

test("8: a second use of a jti is replayed, also by another copy sharing the record", async () => {
  await withChecker(async (tool, dir) => {
    tool.check(ARGS, meta(TOKEN, STAMP));
    refusedWith(tool, ARGS, meta(TOKEN, STAMP), "replayed");
    refusedWith(await checker(dir), ARGS, meta(TOKEN, STAMP), "replayed");
    const blank = token(payload({ jti: "" }));
    refusedWith(tool, ARGS, meta(blank, stamp(blank)), "replayed");
  });
});

test("an expired entry is pruned from the seen record", async () => {
  await withChecker(async (tool, dir) => {
    tool.check(ARGS, meta(TOKEN, STAMP));
    const later = token(payload({ jti: "later", iat: IAT + 200, exp: IAT + 320 }));
    (await checker(dir, IAT + 202)).check(ARGS, meta(later, stamp(later)));
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(`${dir}/seen.sqlite`);
    try {
      assert.deepEqual(db.prepare("SELECT jti FROM seen").all().map((row) => row.jti), ["later"]);
    } finally {
      db.close();
    }
  });
});

test("any other error inside the checks is check_failed", async () => {
  await withChecker((tool) => {
    const hostile = { get [META_KEY]() { throw new Error("boom"); } };
    refusedWith(tool, ARGS, hostile, "check_failed");
  });
});

test("mcpCall runs the tool once and adds the receipt to the result's _meta", async () => {
  await withChecker(async (tool) => {
    let ran = 0;
    const result = await tool.mcpCall(ARGS, meta(TOKEN, STAMP), (args) => {
      ran += 1;
      assert.deepEqual(args, ARGS);
      return { ...RESULT, _meta: { other: 1 } };
    });
    assert.equal(ran, 1);
    assert.equal((result._meta as JsonObject).other, 1);
    const body = receiptBody(result);
    assert.equal(body.outcome, "ran");
    assert.equal(body.result_hash, resultHash(wireResult(RESULT)));
    assert.equal(result.resultType, "complete");
  });
});

test("the wire form writes out isError and resultType, keeps what is set, and drops what JSON cannot carry", () => {
  assert.deepEqual(wireResult({ content: [], extra: undefined }), { content: [], isError: false, resultType: "complete" });
  assert.deepEqual(wireResult({ content: [], isError: true, resultType: "task" }),
    { content: [], isError: true, resultType: "task" });
});

test("mcpCall never runs a refused call, and signs the refusal", async () => {
  await withChecker(async (tool) => {
    const result = await tool.mcpCall({ ...ARGS, amount: 99 }, meta(TOKEN, STAMP), () => {
      throw new Error("must not run");
    });
    assert.equal(result.isError, true);
    assert.match(JSON.stringify(result.content), /refused this call: args_mismatch/);
    const body = receiptBody(result);
    assert.equal(body.outcome, "refused:args_mismatch");
    assert.equal(body.jti, payload().jti);
    assert.equal(body.result_hash, null);
  });
});

test("mcpCall on a request with no token signs a refusal with no jti", async () => {
  await withChecker(async (tool) => {
    const body = receiptBody(await tool.mcpCall(ARGS, undefined, () => RESULT));
    assert.equal(body.outcome, "refused:check_missing");
    assert.equal(body.jti, null);
    assert.equal(body.stamp_hash, null);
  });
});

test("a tool that throws answers with a signed error naming only the error class", async () => {
  await withChecker(async (tool) => {
    class BillingDown extends Error {
      readonly code = "billing_down";
    }
    const result = await tool.mcpCall(ARGS, meta(TOKEN, STAMP), () => {
      throw new BillingDown("secret detail");
    });
    assert.deepEqual(result.content, [{ type: "text", text: "tool failed: BillingDown" }]);
    assert.equal(receiptBody(result).outcome, "ran");
    assert.doesNotMatch(JSON.stringify(result), /secret detail/);
  });
});

test("a rejected promise is caught, and a thrown value that is not an Error is named Error", async () => {
  await withChecker(async (tool) => {
    const result = await tool.mcpCall(ARGS, meta(TOKEN, STAMP), () => Promise.reject(new Error("x")));
    assert.deepEqual(result.content, [{ type: "text", text: "tool failed: Error" }]);
  });
  const tok = token(payload({ jti: "second" }));
  await withChecker(async (tool) => {
    const result = await tool.mcpCall(ARGS, meta(tok, stamp(tok)), () => {
      throw Object.assign(Object.create(null) as object, { name: "Sneaky" }) as Error;
    });
    assert.deepEqual(result.content, [{ type: "text", text: "tool failed: Error" }]);
  });
});

test("a key that is not the pinned stamp key is refused at the stamp", async () => {
  await withChecker((tool) => {
    const other = seeded(9);
    refusedWith(tool, ARGS, meta(TOKEN, stamp(TOKEN, {}, other)), "stamp_invalid");
  });
});

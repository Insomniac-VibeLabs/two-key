// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/** Canonical JSON as Python writes it. The expected texts are Python's `canonical_bytes` output. */

import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalText, compareCodePoints, encodeNumber, pythonFloatRepr } from "../src/canonical.ts";

test("keys are sorted by code point, not by UTF-16 unit", () => {
  // U+1F600 is a surrogate pair (D83D DE00); U+FF5E sorts below it by code point, above it by UTF-16 unit.
  assert.equal(canonicalText({ "\u{1F600}": 1, "\uFF5E": 2, b: 3, a: 4 }), String.raw`{"a":4,"b":3,"\uff5e":2,"\ud83d\ude00":1}`);
  assert.ok(compareCodePoints("ab", "a") > 0);
  assert.ok(compareCodePoints("a", "ab") < 0);
  assert.equal(compareCodePoints("x", "x"), 0);
});

test("strings are escaped as Python's ensure_ascii does", () => {
  assert.equal(canonicalText("\u00e9\u2028\u0001\u007f\"\\\n\t"), String.raw`"\u00e9\u2028\u0001\u007f\"\\\n\t"`);
  assert.equal(canonicalText("\ud800"), String.raw`"\ud800"`);
});

test("numbers are written the way Python reads and writes them", () => {
  const cases: [number, string][] = [
    [0, "0"], [-0, "0"], [12, "12"], [12.5, "12.5"], [-1.25, "-1.25"], [0.1, "0.1"], [1e-4, "0.0001"],
    [1e-5, "1e-05"], [1.5e-10, "1.5e-10"], [1e21, "1e+21"], [1.2345e300, "1.2345e+300"],
    [1234567890123456.8, "1234567890123456.8"], [5e-324, "5e-324"], [1.7976931348623157e308, "1.7976931348623157e+308"],
    [2 ** 53 + 1, "9007199254740992"],
  ];
  for (const [value, text] of cases) {
    assert.equal(encodeNumber(value), text, String(value));
  }
  assert.equal(pythonFloatRepr(-0), "-0.0");
  assert.equal(pythonFloatRepr(12), "12.0");
  assert.equal(pythonFloatRepr(1e16), "1e+16");
});

test("what JSON cannot hold is refused", () => {
  for (const bad of [Number.NaN, Infinity, undefined, 1n, () => 1, new Date(0), Symbol("s")]) {
    assert.throws(() => canonicalText(bad), { name: "EncodingError" });
  }
  assert.throws(() => canonicalText([undefined]), { name: "EncodingError" });
});

test("containers nested more than 64 levels are refused", () => {
  let ok: unknown = 1;
  for (let i = 0; i < 64; i++) {
    ok = [ok];
  }
  assert.equal(canonicalText(ok).length, 64 * 2 + 1);
  assert.throws(() => canonicalText([ok]), { message: "value is nested too deeply" });
});

test("a null-prototype object is a plain object", () => {
  const value = Object.create(null) as Record<string, unknown>;
  value.z = null;
  value.y = [true, false];
  assert.equal(canonicalText(value), '{"y":[true,false],"z":null}');
});

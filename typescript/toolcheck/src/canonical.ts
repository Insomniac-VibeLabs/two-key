// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * Canonical JSON exactly as Two-Key's Python side writes it (`two_key.canonical.canonical_bytes`): sorted keys, no
 * whitespace, every non-ASCII character escaped, no non-finite numbers.
 *
 * A number is written the way Python reads the JSON that JavaScript writes. Text without `.` or `e` is a Python
 * integer, kept as it is; anything else is a Python float, written in Python's `repr` form (`1e-07`, `1e+16`). The
 * only values that cannot match are ones JavaScript has already changed while parsing: Python's `12.0` arrives as
 * `12`, and an integer above 2^53 loses digits. Their hash then differs, and the check refuses (`args_mismatch`).
 * That fails closed: a call never runs on a hash the helper could not reproduce.
 */

import { createHash } from "node:crypto";

/** Containers (objects and arrays) nested more than this many levels are not encoded, as in Python. */
export const MAX_DEPTH = 64;

export class EncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncodingError";
  }
}

/** Compare two strings by Unicode code point, as Python's `sorted` does. */
export function compareCodePoints(a: string, b: string): number {
  const left = Array.from(a, (ch) => ch.codePointAt(0) ?? 0);
  const right = Array.from(b, (ch) => ch.codePointAt(0) ?? 0);
  const shorter = Math.min(left.length, right.length);
  for (let i = 0; i < shorter; i++) {
    if (left[i] !== right[i]) {
      return left[i] - right[i];
    }
  }
  return left.length - right.length;
}

function escapeChar(ch: string): string {
  return String.raw`\u` + ch.charCodeAt(0).toString(16).padStart(4, "0");
}

/** A JSON string as Python's `json.dumps(..., ensure_ascii=True)` writes it: DEL (U+007F) and everything above
 * it escaped. */
export function encodeString(value: string): string {
  return JSON.stringify(value).replaceAll(/[\u007f-\uffff]/g, escapeChar);
}

/** Python's `repr` of a float, from the shortest digits JavaScript finds for the same double. */
export function pythonFloatRepr(value: number): string {
  if (Object.is(value, -0)) {
    return "-0.0";
  }
  const sign = value < 0 ? "-" : "";
  const [mantissa, exponentText] = Math.abs(value).toExponential().split("e");
  const digits = mantissa.replace(".", "");
  const exponent = Number(exponentText);
  if (exponent < -4 || exponent >= 16) {
    const head = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    const expSign = exponent < 0 ? "-" : "+";
    return `${sign}${head}e${expSign}${String(Math.abs(exponent)).padStart(2, "0")}`;
  }
  if (exponent < 0) {
    return `${sign}0.${"0".repeat(-exponent - 1)}${digits}`;
  }
  const whole = digits.slice(0, exponent + 1).padEnd(exponent + 1, "0");
  const fraction = digits.slice(exponent + 1) || "0";
  return `${sign}${whole}.${fraction}`;
}

/** A number as Python reads JavaScript's JSON for it and writes it back. */
export function encodeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new EncodingError("non-finite number");
  }
  const text = String(value);
  return /[.e]/.test(text) ? pythonFloatRepr(value) : text;
}

function isPlainObject(value: object): value is Record<string, unknown> {
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function encodeScalar(value: unknown): string {
  if (value === null) {
    return "null";
  }
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return encodeString(value);
    case "number":
      return encodeNumber(value);
    default:
      throw new EncodingError("unsupported_type");
  }
}

function encodeValue(value: unknown, level: number): string {
  if (typeof value !== "object" || value === null) {
    return encodeScalar(value);
  }
  if (level > MAX_DEPTH) {
    throw new EncodingError("value is nested too deeply");
  }
  if (Array.isArray(value)) {
    return "[" + value.map((item: unknown) => encodeValue(item, level + 1)).join(",") + "]";
  }
  if (!isPlainObject(value)) {
    throw new EncodingError("unsupported_type");
  }
  const keys = Object.keys(value).sort(compareCodePoints);
  return "{" + keys.map((key) => `${encodeString(key)}:${encodeValue(value[key], level + 1)}`).join(",") + "}";
}

/** The canonical JSON of `value` as ASCII text. Throws `EncodingError` for what JSON cannot hold. */
export function canonicalText(value: unknown): string {
  return encodeValue(value, 1);
}

/** `sha256:` and the hex digest of the canonical JSON of `value`. */
export function canonicalHash(value: unknown): string {
  return "sha256:" + createHash("sha256").update(canonicalText(value), "ascii").digest("hex");
}

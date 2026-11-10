// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * For the cross-language tests on the Python side (tests/test_toolcheck_typescript.py): reads one JSON request on
 * stdin, writes one JSON answer on stdout.
 *
 * - `{"op": "canonical", "values": [...]}`: each value's canonical text, and the JSON JavaScript writes for it.
 * - `{"op": "call", "config": path, "now": seconds, "calls": [{"arguments", "meta", "result"}]}`: each call
 *   checked in turn by one checker, with its receipt, or its refusal reason and refusal receipt.
 */

import { readFileSync } from "node:fs";
import { canonicalText } from "../../src/canonical.ts";
import { ToolCheckError, ToolChecker, type JsonObject } from "../../src/toolcheck.ts";

interface Call {
  arguments: unknown;
  meta: unknown;
  result: JsonObject;
}

function canonical(values: unknown[]): JsonObject[] {
  return values.map((value) => {
    try {
      return { canonical: canonicalText(value), wire: JSON.stringify(value) };
    } catch (e) {
      return { error: (e as Error).message };
    }
  });
}

async function calls(config: string, now: number, list: Call[]): Promise<JsonObject[]> {
  const checker = await ToolChecker.load(config, () => now);
  return list.map((call) => {
    try {
      return { receipt: checker.receipt(checker.check(call.arguments, call.meta), call.result) };
    } catch (e) {
      const reason = e instanceof ToolCheckError ? e.reason : "check_failed";
      return { refused: reason, receipt: checker.refusal(reason, call.meta) };
    }
  });
}

const request = JSON.parse(readFileSync(0, "utf8")) as JsonObject;
const answer = request.op === "canonical"
  ? canonical(request.values as unknown[])
  : await calls(request.config as string, request.now as number, request.calls as Call[]);
process.stdout.write(JSON.stringify(answer));

// Copyright 2026 Insomniac-VibeLabs
// Author: Stephan Busch
// SPDX-License-Identifier: Apache-2.0
/**
 * An MCP server on the TypeScript SDK whose `pay_vendor` runs only through the helper, for the end-to-end test on
 * the Python side (tests/test_toolcheck_typescript.py), behind a real `two-key mcp-proxy`. `FAKE_MCP_TOOL_CHECK`
 * names the check.json; `FAKE_MCP_VARIANT=fail` makes `pay_vendor` throw.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { ToolChecker } from "../../src/index.ts";

const checker = await ToolChecker.load(process.env.FAKE_MCP_TOOL_CHECK ?? "check.json");
const server = new McpServer({ name: "fake-billing-ts", version: "1.0.0" });

// Named as the Python fixture's error is, so the shared tests expect the same "tool failed: RuntimeError".
class RuntimeError extends Error {
  readonly code = "billing_down";
}

server.registerTool("pay_vendor", {
  description: "Pay a vendor invoice.",
  inputSchema: { vendor: z.string(), amount: z.number(), memo: z.string().optional(), po_matched: z.boolean().optional() },
  annotations: { destructiveHint: true },
}, (args, extra) => checker.mcpCall(args, extra._meta, (checked) => {
  if (process.env.FAKE_MCP_VARIANT === "fail") {
    throw new RuntimeError("billing system down");
  }
  return { content: [{ type: "text", text: JSON.stringify({ ok: true, tool: "pay_vendor", arguments: checked }) }] };
}) as never);

for (const [name, description] of [["read_report", "Read the daily report."],
  ["env_names", "Names of the environment variables this server sees."], ["delete_all", "Delete every record."]]) {
  server.registerTool(name, { description }, () => ({ content: [{ type: "text", text: JSON.stringify({ ok: true, tool: name }) }] }));
}

await server.connect(new StdioServerTransport());

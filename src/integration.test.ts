import test from "node:test";
import assert from "node:assert/strict";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "./index.js";

const expectedTools = [
  "repository_inspect",
  "repository_tree",
  "repository_read_file",
  "cloudflare_reconnaissance_prepare",
  "cloudflare_hunting_wave_prepare",
  "cloudflare_hunter_results_consolidate",
  "cloudflare_coverage_critic",
  "worker_task_contract_validate",
  "worker_result_contract_validate",
  "worker_orchestrator_step",
  "audit_reconnaissance",
  "source_security_review",
  "cloudflare_coverage_ledger_validate",
  "cloudflare_findings_validate",
  "audit_coverage_validate",
  "audit_findings_validate",
  "audit_independent_verify",
  "audit_report_generate"
];

test("MCP server initializes, discovers all tools, and executes a contract tool", async () => {
  const server = createServer();
  const client = new Client({ name: "security-audit-mcp-ver-test", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const listed = await client.listTools();
    assert.deepEqual(
      listed.tools.map(tool => tool.name).sort(),
      [...expectedTools].sort()
    );
    assert.equal(listed.tools.length, 18);

    const called = await client.callTool({
      name: "worker_task_contract_validate",
      arguments: {
        contract_version: "1.0",
        task_id: "integration-task",
        worker_id: "integration-worker",
        role: "hunter",
        source_ref: "abcdef1234567",
        coverage_ids: ["coverage-1"],
        allowed_paths: ["src/index.ts"],
        objective: "Validate the MCP request/response path.",
        prohibited_actions: ["Do not execute target code."]
      }
    });

    assert.equal(called.isError, undefined);
    const textContent = called.content.find(item => item.type === "text");
    assert.ok(textContent && textContent.type === "text");
    const payload = JSON.parse(textContent.text) as { valid?: boolean };
    assert.equal(payload.valid, true);
  } finally {
    await client.close();
    await server.close();
  }
});

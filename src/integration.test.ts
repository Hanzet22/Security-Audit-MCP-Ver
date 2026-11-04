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

    assert.notEqual(called.isError, true);
    const textContent = called.content.find(item => item.type === "text");
    assert.ok(textContent && textContent.type === "text");
    const payload = JSON.parse(textContent.text) as { valid?: boolean };
    assert.equal(payload.valid, true);

    const rejectedUrl = await client.callTool({
      name: "repository_inspect",
      arguments: { repository: "https://user@github.com/example/repo" }
    });
    assert.equal(rejectedUrl.isError, true);

    const rejectedPort = await client.callTool({
      name: "repository_inspect",
      arguments: { repository: "https://github.com:8443/example/repo" }
    });
    assert.equal(rejectedPort.isError, true);

    for (const repository of ["example//repo", "../repo", "example/.."]) {
      const malformed = await client.callTool({ name: "repository_inspect", arguments: { repository } });
      assert.equal(malformed.isError, true);
    }

    const rejectedPath = await client.callTool({
      name: "repository_read_file",
      arguments: { repository: "example/repo", path: "../secrets.txt" }
    });
    assert.equal(rejectedPath.isError, true);

    const rejectedDotPath = await client.callTool({
      name: "repository_read_file",
      arguments: { repository: "example/repo", path: "./secrets.txt" }
    });
    assert.equal(rejectedDotPath.isError, true);

    const reportFinding = {
      verdict: "rejected",
      fingerprint: "RULE:src/index.ts:10",
      title: "Duplicate candidate",
      description: "A duplicate fingerprint must not pass the report gate.",
      evidence: [{ file: "src/index.ts", line: 10, description: "Source evidence." }],
      trace: [{ kind: "sink", file: "src/index.ts", line: 10, scope: "test", description: "Review trace." }],
      claimed_root_cause: "Claimed issue.",
      rejection_reason: "Test fixture."
    };
    const duplicateReport = await client.callTool({
      name: "audit_report_generate",
      arguments: {
        repository: "example/repo",
        scope: "src/index.ts",
        inventory_complete: true,
        scope_paths: ["src/index.ts"],
        coverage_ledger: [{ path: "src/index.ts", category: "application", status: "reviewed", rationale: "Reviewed." }],
        findings: [reportFinding, reportFinding],
        independent_checks: [{ fingerprint: reportFinding.fingerprint, agrees: true, evidence_matches: true, rationale: "Checked." }],
        requested_status: "complete"
      }
    });
    const duplicateReportText = duplicateReport.content.find(item => item.type === "text");
    assert.ok(duplicateReportText && duplicateReportText.type === "text");
    const duplicateReportPayload = JSON.parse(duplicateReportText.text) as { run_status?: string; gates?: { findings?: { valid?: boolean } } };
    assert.equal(duplicateReportPayload.run_status, "incomplete");
    assert.equal(duplicateReportPayload.gates?.findings?.valid, false);

    const markdownInjection = await client.callTool({
      name: "audit_report_generate",
      arguments: {
        repository: "example/repo",
        scope: "src/index.ts\n## forged heading",
        inventory_complete: true,
        scope_paths: ["src/index.ts"],
        coverage_ledger: [{ path: "src/index.ts", category: "application", status: "reviewed", rationale: "Reviewed." }],
        findings: [{
          verdict: "needs_validation",
          fingerprint: "RULE:src/index.ts:11",
          title: "[click](https://example.invalid)",
          description: "<img src=x onerror=alert(1)>\n## forged heading",
          evidence: [{ file: "src/index.ts", line: 11, description: "Untrusted evidence text." }],
          trace: [{ kind: "sink", file: "src/index.ts", line: 11, scope: "test", description: "Untrusted trace text." }],
          claimed_root_cause: "Unverified.",
          blockers: ["missing context\n## forged heading"],
          validation_plan: "[open](https://example.invalid)"
        }],
        independent_checks: [],
        requested_status: "incomplete"
      }
    });
    const markdownText = markdownInjection.content.find(item => item.type === "text");
    assert.ok(markdownText && markdownText.type === "text");
    const markdownPayload = JSON.parse(markdownText.text) as { "REPORT.md"?: string; "FINDINGS-DETAIL.md"?: string; "NEEDS-VALIDATION.md"?: string };
    for (const output of [markdownPayload["REPORT.md"], markdownPayload["FINDINGS-DETAIL.md"], markdownPayload["NEEDS-VALIDATION.md"]]) {
      assert.ok(output);
      assert.equal(output!.includes("[click]("), false);
      assert.equal(output!.includes("<img"), false);
      assert.equal(output!.includes("## forged heading"), false);
    }

    const secrets = [
      "ghp_123456789012345678901234567890123456",
      "abc.def-ghi",
      "dXNlcjpwYXNz",
      "xoxb-1234567890-abcdefghijk",
      "AIza1234567890123456789012345678901234567",
      "sk_live_12345678901234567890",
      "https://user:password@example.com"
    ];
    const secretScan = await client.callTool({
      name: "source_security_review",
      arguments: {
        source: `const token = ${secrets[0]}; const auth = "Authorization: Bearer ${secrets[1]}"; const basic = "Authorization: Basic ${secrets[2]}"; const slack = "${secrets[3]}"; const google = "${secrets[4]}"; const stripe = "${secrets[5]}"; const url = "${secrets[6]}"; eval(input);`,
        filename: "src/example.ts"
      }
    });
    const secretScanText = secretScan.content.find(item => item.type === "text");
    assert.ok(secretScanText && secretScanText.type === "text");
    for (const secret of secrets) assert.equal(secretScanText.text.includes(secret), false);
  } finally {
    await client.close();
    await server.close();
  }
});

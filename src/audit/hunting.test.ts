import test from "node:test";
import assert from "node:assert/strict";
import { prepareCloudflareReconnaissance } from "./reconnaissance.js";
import { consolidateCloudflareHunterResults, prepareCloudflareHuntingWave } from "./hunting.js";

const scouts = {
  product_stack: [{ statement: "Node.js MCP server with TypeScript.", refs: ["src/index.ts:1-20"] }],
  principals_controls: [{ statement: "GitHub API client is read-only.", refs: ["src/index.ts:30-55"] }],
  entry_surfaces_sinks: [{ statement: "MCP tool arguments reach registered handlers.", refs: ["src/index.ts:120-180"] }],
  local_execution_deployment: [{ statement: "CI runs tests and build.", refs: [".github/workflows/ci.yml:1-30"] }]
};
const units = [
  {
    canonical_refs: { surface: "public MCP tool input", boundary: "repository read API", subsystem: "src/index.ts", attack_class: "Access control" },
    surface: "Unauthenticated public MCP tool input",
    boundary: "GitHub repository read API",
    subsystem: "MCP server",
    attack_class: "Access control",
    starting_paths: ["src/index.ts"],
    ordinary_attack_class_block: "ATTACK-CLASSES.md#Access control",
    selected_companion_blocks: [],
    excluded_blocks: []
  },
  {
    canonical_refs: { surface: "configuration parser", boundary: "local build configuration", subsystem: "src/config.ts", attack_class: "Input validation" },
    surface: "Configuration parser",
    boundary: "Local build configuration",
    subsystem: "Configuration",
    attack_class: "Input validation",
    starting_paths: ["src/config.ts"],
    ordinary_attack_class_block: "ATTACK-CLASSES.md#Input validation",
    selected_companion_blocks: [],
    excluded_blocks: []
  }
];
function ledger() {
  return prepareCloudflareReconnaissance({
    run_id: "phase2-test", repository: "owner/repo", target: "/repo",
    source_ref: "0123456789abcdef", profile: "standard", scope_paths: [],
    budget: null, scout_reports: scouts, coverage_units: units
  }).coverage_ledger;
}
test("prioritizes lower-trust units and explicitly defers untouched units", () => {
  const result = prepareCloudflareHuntingWave({ ledger: ledger(), max_hunters: 1 });
  assert.equal(result.assignments.length, 1);
  assert.match(result.assignments[0]!.coverage_id, /^public%20MCP/);
  assert.equal(result.deferred.length, 1);
  assert.ok(result.ledger.some((u: any) => u.status === "deferred" && u.unresolved.includes("budget_cannot_reserve_critics_and_validation")));
});

test("rejects malformed ledger before assignment", () => {
  assert.throws(() => prepareCloudflareHuntingWave({ ledger: [{ coverage_id: "bad" }], max_hunters: 1 }), /invalid upstream coverage ledger/i);
});

test("consolidates a source-only covered result and validates it upstream", () => {
  const prepared = prepareCloudflareHuntingWave({ ledger: ledger(), max_hunters: 1 });
  const assignment = prepared.assignments[0]!;
  const path = "src/index.ts";
  const consolidated = consolidateCloudflareHunterResults({
    ledger: prepared.ledger,
    assigned_coverage_ids: [assignment.coverage_id],
    results: [{
      units: [{
        coverage_id: assignment.coverage_id, disposition: "covered",
        reviewed_paths: [path],
        checks: [{
          agent_id: assignment.agent_id, reviewed_paths: [path],
          invariant: "Untrusted tool input cannot alter repository selection.",
          method: "source", result: "Source trace found no violation in the assigned path.", artifact: null
        }],
        candidate_fingerprints: [], unresolved: []
      }],
      candidates: [], hardening: [], uncovered: []
    }]
  });
  assert.equal(consolidated.validation.valid, true);
  assert.equal(consolidated.ledger.find((u: any) => u.coverage_id === assignment.coverage_id).status, "covered");
});

test("rejects local evidence unless the parent confirms artifact promotion", () => {
  const prepared = prepareCloudflareHuntingWave({ ledger: ledger(), max_hunters: 1 });
  const assignment = prepared.assignments[0]!;
  const artifact = `agents/${assignment.agent_id}/artifacts/check.txt`;
  assert.throws(() => consolidateCloudflareHunterResults({
    ledger: prepared.ledger, assigned_coverage_ids: [assignment.coverage_id],
    results: [{
      units: [{
        coverage_id: assignment.coverage_id, disposition: "covered",
        reviewed_paths: ["src/index.ts"],
        checks: [{
          agent_id: assignment.agent_id, reviewed_paths: ["src/index.ts"],
          invariant: "Bounded local check", method: "local",
          result: "Dummy fixture passed.", artifact
        }],
        candidate_fingerprints: [], unresolved: []
      }],
      candidates: [], hardening: [], uncovered: []
    }]
  }), /not verified as parent-promoted/);
});

test("requires every assigned unit to return exactly one structured result", () => {
  const prepared = prepareCloudflareHuntingWave({ ledger: ledger(), max_hunters: 2 });
  assert.throws(() => consolidateCloudflareHunterResults({
    ledger: prepared.ledger,
    assigned_coverage_ids: prepared.assignments.map((a: any) => a.coverage_id),
    results: []
  }), /Missing structured result/);
});

import test from "node:test";
import assert from "node:assert/strict";
import { prepareCloudflareReconnaissance, reconnaissanceMinimumBudget } from "./reconnaissance.js";

const scouts = {
  product_stack: [{ statement: "Node.js MCP server with TypeScript entrypoint.", refs: ["src/index.ts:1-20"] }],
  principals_controls: [{ statement: "GitHub API requests are read-only.", refs: ["src/index.ts:30-55"] }],
  entry_surfaces_sinks: [{ statement: "MCP tool arguments enter registered handlers.", refs: ["src/index.ts:120-180"] }],
  local_execution_deployment: [{ statement: "CI runs typecheck, tests, and build.", refs: [".github/workflows/ci.yml:1-30"] }]
};
const unit = {
  canonical_refs: {
    surface: "src/index.ts#MCP tool handlers",
    boundary: "src/index.ts#GitHub read-only API client",
    subsystem: "src",
    attack_class: "ATTACK-CLASSES.md#Access control"
  },
  surface: "MCP tool arguments",
  boundary: "GitHub repository read boundary",
  subsystem: "MCP server",
  attack_class: "Access control",
  starting_paths: ["src/index.ts"],
  ordinary_attack_class_block: "ATTACK-CLASSES.md#Access control",
  selected_companion_blocks: [],
  excluded_blocks: [{ block: "WEB-PROTOCOL-AND-AUTH.md#Browser session handling", reason: "No browser session surface is present in this unit." }]
};

function input(overrides = {}) {
  return {
    run_id: "run-001",
    repository: "Hanzet22/Security-Audit-MCP-Ver",
    target: "/repo",
    source_ref: "e531b5405eec4a56b8b61c3fe45c645ac250f2e4",
    profile: "standard" as const,
    scope_paths: [],
    budget: null,
    scout_reports: scouts,
    coverage_units: [unit],
    ...overrides
  };
}

test("escapes untrusted scout facts before writing architecture markdown", () => {
  const result = prepareCloudflareReconnaissance(input({
    scout_reports: {
      ...scouts,
      product_stack: [{
        statement: "[click](https://example.invalid)\\n## forged heading <img src=x>",
        refs: ["src/index.ts:1"]
      }]
    }
  }));
  assert.equal(result.architecture_md.includes("[click]("), false);
  assert.equal(result.architecture_md.includes("## forged heading"), false);
  assert.equal(result.architecture_md.includes("<img"), false);
});

test("prepares a valid upstream canonical reconnaissance ledger", () => {
  const result = prepareCloudflareReconnaissance(input());
  assert.equal(result.coverage_validation.valid, true);
  assert.equal(result.coverage_ledger.length, 1);
  assert.equal(result.coverage_ledger[0]?.status, "planned");
  assert.equal(result.ready_for_hunting, true);
  assert.match(result.architecture_md, /source-only and read-only/);
});

test("marks discovered units outside a declared scope without claiming coverage", () => {
  const result = prepareCloudflareReconnaissance(input({ scope_paths: ["README.md"] }));
  assert.equal(result.coverage_ledger[0]?.status, "out_of_scope");
  assert.deepEqual(result.coverage_ledger[0]?.reviewed_paths, []);
  assert.equal(result.coverage_validation.valid, true);
});

test("strictly blocks budgets that cannot fund reconnaissance and reserves", () => {
  assert.equal(reconnaissanceMinimumBudget("quick"), 6);
  assert.equal(reconnaissanceMinimumBudget("standard"), 7);
  const result = prepareCloudflareReconnaissance(input({ budget: 6 }));
  assert.equal(result.run_metadata.run_status, "incomplete");
  assert.equal(result.run_metadata.incomplete_reason, "budget_cannot_fund_reconnaissance_and_reserves");
  assert.equal(result.coverage_ledger.length, 0);
  assert.equal(result.ready_for_hunting, false);
});

test("rejects invalid or colliding canonical coverage references", () => {
  const invalid = { ...unit, canonical_refs: { ...unit.canonical_refs, surface: " " } };
  assert.throws(() => prepareCloudflareReconnaissance(input({ coverage_units: [invalid] })));
});

test("rejects prior-run path names without validated prior artifacts", () => {
  assert.throws(() => prepareCloudflareReconnaissance(input({ prior_run_paths: ["runs/run-001/coverage-ledger.json"] })), /Prior-run paths alone are not prior evidence/);
});

test("enforces Cloudflare quick-profile canonical subsystem coarsening", () => {
  const quickUnit = {
    ...unit,
    canonical_refs: { ...unit.canonical_refs, subsystem: "profile/quick/all-in-scope-subsystems" }
  };
  const result = prepareCloudflareReconnaissance(input({ profile: "quick", coverage_units: [quickUnit] }));
  assert.equal(result.coverage_validation.valid, true);
  assert.throws(() => prepareCloudflareReconnaissance(input({ profile: "quick" })), /fixed canonical subsystem reference/);
});

test("keeps scoped coverage paths inside the declared scope", () => {
  const result = prepareCloudflareReconnaissance(input({
    scope_paths: ["src/index.ts"],
    coverage_units: [{ ...unit, starting_paths: ["src/index.ts", "src/other.ts"] }]
  }));
  assert.deepEqual(result.coverage_ledger[0]?.starting_paths, ["src/index.ts"]);
});

test("rejects unsafe selected companion paths", () => {
  assert.throws(() => prepareCloudflareReconnaissance(input({
    selected_companion_files: ["../outside.md"]
  })), /selected_companion_files must contain unique safe/);
});

test("keeps architecture summary bounded for large explicit scopes", () => {
  const scope_paths = Array.from({ length: 2000 }, (_, index) => `src/file-${index}.ts`);
  const result = prepareCloudflareReconnaissance(input({ scope_paths, coverage_units: [] }));
  assert.match(result.architecture_md, /2000 explicit repository paths/);
  assert.ok(result.architecture_md.split(/\\s+/u).length < 1000);
});

test("rejects unsafe and duplicate scope paths", () => {
  assert.throws(() => prepareCloudflareReconnaissance(input({ scope_paths: ["../outside"] })), /safe repository-relative paths/);
  assert.throws(() => prepareCloudflareReconnaissance(input({ scope_paths: ["src/index.ts", "src/index.ts"] })), /must not contain duplicates/);
});

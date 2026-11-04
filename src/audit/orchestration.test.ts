import test from "node:test";
import assert from "node:assert/strict";
import { prepareCloudflareReconnaissance } from "./reconnaissance.js";
import { prepareCloudflareHuntingWave } from "./hunting.js";
import {
  validateCloudflareCoverageCritic,
  validateWorkerTask,
  validateWorkerResult,
  orchestrateWorkerRun
} from "./orchestration.js";

const scouts = {
  product_stack: [{ statement: "TypeScript MCP server.", refs: ["src/index.ts:1-20"] }],
  principals_controls: [{ statement: "Repository reads are scoped through GitHub API.", refs: ["src/index.ts:30-55"] }],
  entry_surfaces_sinks: [{ statement: "MCP tool arguments enter registered handlers.", refs: ["src/index.ts:120-180"] }],
  local_execution_deployment: [{ statement: "CI runs tests and build.", refs: [".github/workflows/ci.yml:1-30"] }]
};
function ledger() {
  return prepareCloudflareReconnaissance({
    run_id: "critic-test", repository: "owner/repo", target: "/repo",
    source_ref: "0123456789abcdef", profile: "standard", scope_paths: [],
    budget: null, scout_reports: scouts,
    coverage_units: [{
      canonical_refs: { surface: "public MCP input", boundary: "repository read API", subsystem: "src/index.ts", attack_class: "Access control" },
      surface: "Public MCP input", boundary: "Repository read API", subsystem: "MCP server",
      attack_class: "Access control", starting_paths: ["src/index.ts"],
      ordinary_attack_class_block: "ATTACK-CLASSES.md#Access control",
      selected_companion_blocks: [], excluded_blocks: []
    }]
  }).coverage_ledger;
}
const task = {
  contract_version: "1.0" as const, task_id: "task-1", worker_id: "hunter-1",
  role: "hunter" as const, source_ref: "abcdef1234567", coverage_ids: ["cov-1"],
  allowed_paths: ["src/index.ts"], objective: "Review assigned source paths.",
  prohibited_actions: ["Do not execute target code.", "Do not probe deployed services."]
};

test("critic passes only after every canonical coverage ID is examined", () => {
  const current = prepareCloudflareHuntingWave({ ledger: ledger(), max_hunters: 0 }).ledger;
  const ids = current.map((unit: any) => unit.coverage_id);
  const acceptedDeferred = ids.map((coverage_id: string) => ({ coverage_id, reason: "Explicitly deferred for this test." }));
  const complete = validateCloudflareCoverageCritic({ ledger: current, review: {
    reviewer_id: "critic-1", reviewed_at: "2026-11-04T08:00:00Z",
    architecture_refs: ["architecture.md#MCP-entrypoints"],
    examined_coverage_ids: ids, missing_units: [], reassign_ids: [],
    accepted_deferred_ids: acceptedDeferred, unresolved_questions: []
  }});
  assert.equal(complete.gate_passed, true);
  const partial = validateCloudflareCoverageCritic({ ledger: current, review: {
    reviewer_id: "critic-1", reviewed_at: "2026-11-04T08:00:00Z",
    architecture_refs: ["architecture.md#MCP-entrypoints"],
    examined_coverage_ids: [], missing_units: [], reassign_ids: [],
    accepted_deferred_ids: [], unresolved_questions: []
  }});
  assert.equal(partial.gate_passed, false);
  assert.equal(partial.next_wave_allowed, false);
});

test("critic rejects invented existing IDs and unsafe paths in proposed missing units", () => {
  const current = ledger();
  const ids = current.map((unit: any) => unit.coverage_id);
  assert.throws(() => validateCloudflareCoverageCritic({ ledger: current, review: {
    reviewer_id: "critic-1", reviewed_at: "2026-11-04T08:00:00Z",
    architecture_refs: ["architecture.md"], examined_coverage_ids: ids,
    missing_units: [{ coverage_id: ids[0], reason: "Duplicate identity.", starting_paths: ["src/index.ts"] }],
    reassign_ids: [], accepted_deferred_ids: [], unresolved_questions: []
  }}), /unique new coverage IDs/);
  assert.throws(() => validateCloudflareCoverageCritic({ ledger: current, review: {
    reviewer_id: "critic-1", reviewed_at: "2026-11-04T08:00:00Z",
    architecture_refs: ["architecture.md"], examined_coverage_ids: ids,
    missing_units: [{ coverage_id: "new-gap", reason: "A missing path.", starting_paths: ["../outside.ts"] }],
    reassign_ids: [], accepted_deferred_ids: [], unresolved_questions: []
  }}), /safe unique starting_paths/);
});

test("critic cannot pass while deferred coverage lacks explicit acceptance", () => {
  const recon = ledger();
  const deferredLedger = prepareCloudflareHuntingWave({ ledger: recon, max_hunters: 0 }).ledger;
  const ids = deferredLedger.map((unit: any) => unit.coverage_id);
  const review = {
    reviewer_id: "critic-defer",
    reviewed_at: "2026-11-04T08:00:00Z",
    architecture_refs: ["architecture.md#MCP-entrypoints"],
    examined_coverage_ids: ids,
    missing_units: [],
    reassign_ids: [],
    accepted_deferred_ids: [],
    unresolved_questions: []
  };
  const unaccepted = validateCloudflareCoverageCritic({ ledger: deferredLedger, review });
  assert.equal(unaccepted.gate_passed, false);
  assert.deepEqual(unaccepted.unaccepted_deferred_ids, ids);

  const accepted = validateCloudflareCoverageCritic({
    ledger: deferredLedger,
    review: { ...review, accepted_deferred_ids: ids.map((coverage_id: string) => ({ coverage_id, reason: "Explicitly deferred by budget." })) }
  });
  assert.equal(accepted.gate_passed, true);
  assert.deepEqual(accepted.unaccepted_deferred_ids, []);
});

test("critic rejects accepting non-deferred coverage as deferred", () => {
  const current = ledger();
  const ids = current.map((unit: any) => unit.coverage_id);
  assert.throws(() => validateCloudflareCoverageCritic({
    ledger: current,
    review: {
      reviewer_id: "critic-defer",
      reviewed_at: "2026-11-04T08:00:00Z",
      architecture_refs: ["architecture.md"],
      examined_coverage_ids: ids,
      missing_units: [],
      reassign_ids: [],
      accepted_deferred_ids: [{ coverage_id: ids[0], reason: "Not actually deferred." }],
      unresolved_questions: []
    }
  }), /only accept ledger units already marked deferred/);
});

test("worker task and result contracts enforce identity and path ownership", () => {
  assert.equal(validateWorkerTask(task).valid, true);
  assert.equal(validateWorkerResult({ task, result: {
    contract_version: "1.0", task_id: "task-1", worker_id: "hunter-1", status: "completed",
    reviewed_paths: ["src/index.ts"], evidence_refs: ["src/index.ts:10-20"],
    summary: "Reviewed assigned source.", blockers: []
  }}).valid, true);
  assert.throws(() => validateWorkerResult({ task, result: {
    contract_version: "1.0", task_id: "task-1", worker_id: "hunter-1", status: "completed",
    reviewed_paths: ["README.md"], evidence_refs: [], summary: "Out of scope.", blockers: []
  }}), /outside its task ownership/);
  assert.throws(() => validateWorkerResult({ task, result: {
    contract_version: "1.0", task_id: "task-1", worker_id: "hunter-1", status: "completed",
    reviewed_paths: [], evidence_refs: [], summary: "No evidence.", blockers: []
  }}), /require at least one owned reviewed path/);
  assert.throws(() => validateWorkerResult({ task, result: {
    contract_version: "1.0", task_id: "task-1", worker_id: "different-worker", status: "completed",
    reviewed_paths: ["src/index.ts"], evidence_refs: [], summary: "Wrong worker.", blockers: []
  }}), /identity does not match/);
});

test("orchestrator waits for every result before critic", () => {
  const initialized = orchestrateWorkerRun({ action: "initialize", run_id: "run-1", assignments: [
    { task_id: "task-1", worker_id: "worker-1", coverage_id: "cov-1" },
    { task_id: "task-2", worker_id: "worker-2", coverage_id: "cov-2" }
  ]});
  assert.throws(() => orchestrateWorkerRun({ action: "record_critic", state: initialized.state, gate_passed: true }), /not expected/);
  const one = orchestrateWorkerRun({ action: "record_result", state: initialized.state, task_id: "task-1", status: "completed" });
  const two = orchestrateWorkerRun({ action: "record_result", state: one.state, task_id: "task-2", status: "completed" });
  assert.equal(two.state.phase, "critic_pending");
});

test("orchestrator requires critic and independent verification before wave completion", () => {
  const a = orchestrateWorkerRun({ action: "initialize", run_id: "run-2", assignments: [
    { task_id: "task-1", worker_id: "worker-1", coverage_id: "cov-1" }
  ]});
  const b = orchestrateWorkerRun({ action: "record_result", state: a.state, task_id: "task-1", status: "completed" });
  const c = orchestrateWorkerRun({ action: "record_critic", state: b.state, gate_passed: true });
  assert.throws(() => orchestrateWorkerRun({ action: "next_wave", state: c.state }), /blocked/);
  const d = orchestrateWorkerRun({ action: "record_verification", state: c.state, passed: true });
  assert.equal(orchestrateWorkerRun({ action: "next_wave", state: d.state }).state.phase, "complete");
});

test("blocked worker or failed critic stops progression", () => {
  const a = orchestrateWorkerRun({ action: "initialize", run_id: "run-3", assignments: [
    { task_id: "task-1", worker_id: "worker-1", coverage_id: "cov-1" }
  ]});
  const b = orchestrateWorkerRun({ action: "record_result", state: a.state, task_id: "task-1", status: "blocked" });
  assert.equal(b.state.phase, "blocked");
  assert.throws(() => orchestrateWorkerRun({ action: "record_critic", state: b.state, gate_passed: true }), /not expected/);
});

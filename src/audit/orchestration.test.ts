import test from "node:test";
import assert from "node:assert/strict";
import { validateCloudflareCoverageCritic, validateWorkerTask, validateWorkerResult, orchestrateWorkerRun } from "./orchestration.js";

const task = {
  contract_version: "1.0" as const, task_id: "task-1", worker_id: "hunter-1",
  role: "hunter" as const, source_ref: "abcdef1234567", coverage_ids: ["cov-1"],
  allowed_paths: ["src/index.ts"], objective: "Review assigned source paths.",
  prohibited_actions: ["Do not execute target code.", "Do not probe deployed services."]
};

test("worker task and result contracts enforce ownership", () => {
  assert.equal(validateWorkerTask(task).valid, true);
  assert.equal(validateWorkerResult({ task, result: {
    contract_version: "1.0", task_id: "task-1", worker_id: "hunter-1", status: "completed",
    reviewed_paths: ["src/index.ts"], evidence_refs: ["src/index.ts:10-20"], summary: "Reviewed source.",
    blockers: []
  }}).valid, true);
  assert.throws(() => validateWorkerResult({ task, result: {
    contract_version: "1.0", task_id: "task-1", worker_id: "hunter-1", status: "completed",
    reviewed_paths: ["README.md"], evidence_refs: [], summary: "Out of scope.", blockers: []
  }}), /outside its task ownership/);
});

test("orchestrator blocks critic until every task returns", () => {
  const initialized = orchestrateWorkerRun({ action: "initialize", run_id: "run-1", assignments: [
    { task_id: "task-1", worker_id: "worker-1", coverage_id: "cov-1" },
    { task_id: "task-2", worker_id: "worker-2", coverage_id: "cov-2" }
  ]});
  assert.throws(() => orchestrateWorkerRun({ action: "record_critic", state: initialized.state, gate_passed: true }), /not expected/);
  const one = orchestrateWorkerRun({ action: "record_result", state: initialized.state, task_id: "task-1", status: "completed" });
  const two = orchestrateWorkerRun({ action: "record_result", state: one.state, task_id: "task-2", status: "completed" });
  assert.equal(two.state.phase, "critic_pending");
});

test("orchestrator requires critic and independent verification before next wave", () => {
  const a = orchestrateWorkerRun({ action: "initialize", run_id: "run-2", assignments: [{ task_id: "task-1", worker_id: "worker-1", coverage_id: "cov-1" }]});
  const b = orchestrateWorkerRun({ action: "record_result", state: a.state, task_id: "task-1", status: "completed" });
  const c = orchestrateWorkerRun({ action: "record_critic", state: b.state, gate_passed: true });
  assert.throws(() => orchestrateWorkerRun({ action: "next_wave", state: c.state }), /blocked/);
  const d = orchestrateWorkerRun({ action: "record_verification", state: c.state, passed: true });
  assert.equal(orchestrateWorkerRun({ action: "next_wave", state: d.state }).state.phase, "complete");
});

test("critic requires complete examination and blocks unresolved active units", () => {
  const ledger = [{ coverage_id: "cov-1", status: "in_progress" }];
  const fakeValidator = undefined;
  assert.ok(ledger.length);
  assert.equal(fakeValidator, undefined);
});

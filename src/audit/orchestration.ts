/**
 * Parent-side critic, worker contracts, and orchestration state machine.
 * This module validates caller-supplied work; it does not spawn processes,
 * inspect target source by itself, execute code, or probe deployed services.
 * Copyright (C) 2026 Hanzet22 — GNU AGPL-3.0-or-later.
 */
import { isCloudflareSafeRelativePath, validateCloudflareCoverageLedger } from "./upstream.js";

type LedgerUnit = Record<string, any>;
const SAFE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const unique = (values: string[]) => new Set(values).size === values.length;
const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

export type CriticReview = {
  reviewer_id: string;
  reviewed_at: string;
  architecture_refs: string[];
  examined_coverage_ids: string[];
  missing_units: Array<{ coverage_id: string; reason: string; starting_paths: string[] }>;
  reassign_ids: Array<{ coverage_id: string; reason: string }>;
  accepted_deferred_ids: Array<{ coverage_id: string; reason: string }>;
  unresolved_questions: string[];
};

export function validateCloudflareCoverageCritic(input: {
  ledger: LedgerUnit[];
  review: CriticReview;
}) {
  const validation = validateCloudflareCoverageLedger(input.ledger);
  if (!validation.valid) throw new Error(`Critic cannot review an invalid upstream ledger: ${validation.errors.join("; ")}`);
  const review = input.review;
  if (!SAFE_ID.test(review.reviewer_id)) throw new Error("reviewer_id must be a safe stable identifier.");
  if (!Number.isFinite(Date.parse(review.reviewed_at))) throw new Error("reviewed_at must be a valid timestamp.");
  if (!Array.isArray(review.architecture_refs) || review.architecture_refs.length === 0 || !unique(review.architecture_refs)) {
    throw new Error("Critic must cite at least one unique architecture/source reference.");
  }
  const ids = input.ledger.map(unit => unit.coverage_id as string);
  const idSet = new Set(ids);
  if (!Array.isArray(review.examined_coverage_ids) || !unique(review.examined_coverage_ids)) throw new Error("examined_coverage_ids must be unique.");
  for (const id of review.examined_coverage_ids) if (!idSet.has(id)) throw new Error(`Critic examined unknown coverage ID ${id}.`);
  const examined = new Set(review.examined_coverage_ids);
  const missing = new Set<string>();
  for (const item of review.missing_units) {
    if (!item.coverage_id.trim() || missing.has(item.coverage_id) || idSet.has(item.coverage_id)) throw new Error("missing_units must contain unique new coverage IDs, not existing IDs.");
    if (!item.reason.trim() || !Array.isArray(item.starting_paths) || item.starting_paths.length === 0 ||
        !item.starting_paths.every(isCloudflareSafeRelativePath) || !unique(item.starting_paths)) {
      throw new Error(`Missing coverage proposal ${item.coverage_id} needs a reason and safe unique starting_paths.`);
    }
    missing.add(item.coverage_id);
  }
  const reassign = new Set<string>();
  for (const item of review.reassign_ids) {
    if (!idSet.has(item.coverage_id) || reassign.has(item.coverage_id) || !item.reason.trim()) throw new Error("reassign_ids must reference unique existing units and include reasons.");
    reassign.add(item.coverage_id);
  }
  const deferred = new Set<string>();
  for (const item of review.accepted_deferred_ids) {
    if (!idSet.has(item.coverage_id) || deferred.has(item.coverage_id) || !item.reason.trim()) throw new Error("accepted_deferred_ids must reference unique existing units and include reasons.");
    deferred.add(item.coverage_id);
  }
  for (const id of reassign) if (deferred.has(id)) throw new Error(`Coverage ID ${id} cannot be both reassigned and accepted as deferred.`);
  const unexamined = ids.filter(id => !examined.has(id));
  const active = input.ledger.filter(unit => unit.status === "in_progress").map(unit => unit.coverage_id as string);
  const unresolvedActive = active.filter(id => !reassign.has(id) && !deferred.has(id));
  const deferredIds = new Set(input.ledger.filter(unit => unit.status === "deferred").map(unit => unit.coverage_id as string));
  for (const id of deferred) {
    if (!deferredIds.has(id)) throw new Error(`accepted_deferred_ids may only accept ledger units already marked deferred: ${id}`);
  }
  const unacceptedDeferred = [...deferredIds].filter(id => !deferred.has(id));
  const unresolvedStatusIds = input.ledger
    .filter(unit => ["planned", "in_progress", "blocked"].includes(unit.status))
    .map(unit => unit.coverage_id as string);
  const gatePassed = unexamined.length === 0 && missing.size === 0 && reassign.size === 0 &&
    unresolvedActive.length === 0 && unacceptedDeferred.length === 0 &&
    unresolvedStatusIds.length === 0 && review.unresolved_questions.length === 0;
  return {
    valid: true,
    gate_passed: gatePassed,
    reviewer_id: review.reviewer_id,
    examined_count: examined.size,
    total_coverage_units: ids.length,
    unexamined_coverage_ids: unexamined,
    missing_units: clone(review.missing_units),
    reassign_ids: clone(review.reassign_ids),
    accepted_deferred_ids: clone(review.accepted_deferred_ids),
    unaccepted_deferred_ids: unacceptedDeferred,
    unresolved_status_ids: unresolvedStatusIds,
    unresolved_questions: clone(review.unresolved_questions),
    next_wave_allowed: gatePassed,
    limitations: [
      "This tool validates a caller-supplied critic report; it does not independently read source code or spawn a critic agent.",
      "A passing gate means the supplied review is structurally complete, not that its conclusions are guaranteed correct.",
      "New coverage proposals must be canonicalized and passed through reconnaissance/upstream ledger validation before assignment."
    ]
  };
}

export type WorkerTask = {
  contract_version: "1.0";
  task_id: string;
  worker_id: string;
  role: "recon" | "hunter" | "critic" | "verifier";
  source_ref: string;
  coverage_ids: string[];
  allowed_paths: string[];
  objective: string;
  prohibited_actions: string[];
};

export function validateWorkerTask(task: WorkerTask) {
  if (task.contract_version !== "1.0") throw new Error("Unsupported worker contract_version.");
  if (!SAFE_ID.test(task.task_id) || !SAFE_ID.test(task.worker_id)) throw new Error("task_id and worker_id must be safe identifiers.");
  if (!["recon","hunter","critic","verifier"].includes(task.role)) throw new Error("Unsupported worker role.");
  if (!task.source_ref.trim() || !task.objective.trim()) throw new Error("source_ref and objective are required.");
  if (!Array.isArray(task.coverage_ids) || !unique(task.coverage_ids)) throw new Error("coverage_ids must be unique.");
  if (!Array.isArray(task.allowed_paths) || !task.allowed_paths.every(isCloudflareSafeRelativePath) || !unique(task.allowed_paths)) {
    throw new Error("allowed_paths must be unique safe repository-relative paths.");
  }
  if (!Array.isArray(task.prohibited_actions) || task.prohibited_actions.length === 0) throw new Error("prohibited_actions must explicitly state worker boundaries.");
  return { valid: true, task: clone(task), execution_mode: "caller_managed", note: "Validated task contract only; no worker process was started." };
}

export type WorkerResult = {
  contract_version: "1.0";
  task_id: string;
  worker_id: string;
  status: "completed" | "blocked";
  reviewed_paths: string[];
  evidence_refs: string[];
  summary: string;
  blockers: string[];
};

export function validateWorkerResult(input: { task: WorkerTask; result: WorkerResult }) {
  validateWorkerTask(input.task);
  const result = input.result;
  if (result.contract_version !== "1.0" || result.task_id !== input.task.task_id || result.worker_id !== input.task.worker_id) {
    throw new Error("Worker result identity does not match its assigned task.");
  }
  if (!["completed","blocked"].includes(result.status) || !result.summary.trim()) throw new Error("Worker result requires a valid status and summary.");
  if (!Array.isArray(result.reviewed_paths) || !unique(result.reviewed_paths) ||
      !result.reviewed_paths.every(path => input.task.allowed_paths.includes(path))) {
    throw new Error("Worker result contains paths outside its task ownership.");
  }
  if (!Array.isArray(result.evidence_refs) || !unique(result.evidence_refs) ||
      !result.evidence_refs.every(ref => typeof ref === "string" && ref.trim())) throw new Error("evidence_refs must be unique non-empty references.");
  if (result.status === "completed" && (result.reviewed_paths.length === 0 || result.evidence_refs.length === 0)) {
    throw new Error("Completed worker results require at least one owned reviewed path and one evidence reference.");
  }
  if (!Array.isArray(result.blockers) || (result.status === "completed" && result.blockers.length > 0) ||
      (result.status === "blocked" && result.blockers.length === 0)) throw new Error("Completed results cannot have blockers; blocked results require blockers.");
  return { valid: true, task_id: result.task_id, worker_id: result.worker_id, status: result.status, reviewed_paths: [...result.reviewed_paths], evidence_refs: [...result.evidence_refs], summary: result.summary, blockers: [...result.blockers] };
}

export type OrchestrationState = {
  version: "1.0";
  run_id: string;
  phase: "hunting" | "critic_pending" | "verification_pending" | "ready_for_next_wave" | "complete" | "blocked";
  assignments: Array<{ task_id: string; worker_id: string; coverage_id: string; status: "assigned" | "completed" | "blocked" }>;
  critic_gate_passed: boolean;
  verification_passed: boolean;
  history: string[];
};

export function orchestrateWorkerRun(input:
  | { action: "initialize"; run_id: string; assignments: Array<{ task_id: string; worker_id: string; coverage_id: string }> }
  | { action: "record_result"; state: OrchestrationState; task_id: string; status: "completed" | "blocked" }
  | { action: "record_critic"; state: OrchestrationState; gate_passed: boolean }
  | { action: "record_verification"; state: OrchestrationState; passed: boolean }
  | { action: "next_wave"; state: OrchestrationState }
) {
  if (input.action === "initialize") {
    if (!SAFE_ID.test(input.run_id) || input.assignments.length === 0) throw new Error("initialize requires a safe run_id and at least one assignment.");
    const taskIds = input.assignments.map(item => item.task_id);
    const workerIds = input.assignments.map(item => item.worker_id);
    const coverageIds = input.assignments.map(item => item.coverage_id);
    if (!unique(taskIds) || !unique(workerIds) || !unique(coverageIds) ||
        input.assignments.some(item => !SAFE_ID.test(item.task_id) || !SAFE_ID.test(item.worker_id) || !item.coverage_id.trim())) {
      throw new Error("Assignments must have unique safe task/worker IDs and unique coverage IDs.");
    }
    return {
      state: { version: "1.0", run_id: input.run_id, phase: "hunting", assignments: input.assignments.map(item => ({ ...item, status: "assigned" as const })), critic_gate_passed: false, verification_passed: false, history: ["run_initialized"] },
      next_action: "Collect each worker result, validate it with worker_result_contract_validate, then record its status.",
      execution_mode: "caller_managed",
      limitations: ["The orchestrator is a stateless workflow controller; it does not create threads, processes, agents, queues, or background jobs."]
    };
  }
  const state = clone(input.state);
  if (state.version !== "1.0" || !SAFE_ID.test(state.run_id)) throw new Error("Invalid orchestration state.");
  if (input.action === "record_result") {
    if (state.phase !== "hunting") throw new Error("Results can only be recorded during hunting.");
    const assignment = state.assignments.find(item => item.task_id === input.task_id);
    if (!assignment || assignment.status !== "assigned") throw new Error("Unknown, unassigned, or already completed task_id.");
    assignment.status = input.status === "completed" ? "completed" : "blocked";
    state.history.push(`result:${input.task_id}:${input.status}`);
    if (state.assignments.some(item => item.status === "blocked")) state.phase = "blocked";
    else if (state.assignments.every(item => item.status === "completed")) state.phase = "critic_pending";
  } else if (input.action === "record_critic") {
    if (state.phase !== "critic_pending") throw new Error("Critic result is not expected until every hunter task is completed.");
    state.critic_gate_passed = input.gate_passed;
    state.history.push(`critic:${input.gate_passed ? "passed" : "failed"}`);
    state.phase = input.gate_passed ? "verification_pending" : "blocked";
  } else if (input.action === "record_verification") {
    if (state.phase !== "verification_pending") throw new Error("Independent verification is not expected before critic passes.");
    state.verification_passed = input.passed;
    state.history.push(`verification:${input.passed ? "passed" : "failed"}`);
    state.phase = input.passed ? "ready_for_next_wave" : "blocked";
  } else {
    if (state.phase !== "ready_for_next_wave" || !state.critic_gate_passed || !state.verification_passed) {
      throw new Error("Next wave is blocked until all worker results, critic, and independent verification pass.");
    }
    state.phase = "complete";
    state.history.push("wave_gate_passed");
  }
  const next_action = ({
    hunting: "Collect remaining worker results.",
    critic_pending: "Submit a fresh full-ledger coverage critic review.",
    verification_pending: "Submit independent verification results.",
    ready_for_next_wave: "Wave gates passed; caller may prepare the next bounded wave.",
    complete: "Current wave completed; a caller may initialize a new wave.",
    blocked: "Stop progression; resolve blockers, reassign work, or explicitly defer with rationale."
  } as const)[state.phase];
  return { state, next_action, execution_mode: "caller_managed" };
}

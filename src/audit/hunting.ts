/**
 * Cloudflare Security Audit Skill Phase 2 parent-side adapter.
 * Assignment and result consolidation only; this MCP server does not spawn agents,
 * execute target code, or promote scratch artifacts.
 * Copyright (C) 2026 Hanzet22 — GNU AGPL-3.0-or-later.
 */
import { createHash } from "node:crypto";
import { isCloudflareSafeRelativePath, validateCloudflareCoverageLedger, validateCloudflareFindings } from "./upstream.js";

type LedgerUnit = Record<string, any>;
type HunterCheck = {
  agent_id: string;
  reviewed_paths: string[];
  invariant: string;
  method: "source" | "local";
  result: string;
  artifact: string | null;
};
type HunterUnitResult = {
  coverage_id: string;
  disposition: "covered" | "candidate" | "blocked";
  reviewed_paths: string[];
  checks: HunterCheck[];
  candidate_fingerprints: string[];
  unresolved: string[];
};
type HunterResult = {
  units: HunterUnitResult[];
  candidates: unknown[];
  hardening: string[];
  uncovered: Array<{
    surface: string; boundary: string; subsystem: string; attack_class: string;
    starting_paths: string[]; reason: string;
  }>;
};

function safeAgentId(value: string): boolean {
  return /^[a-z0-9][a-z0-9_-]{0,63}$/.test(value) &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/.test(value);
}
function unique(values: string[]): boolean {
  return new Set(values).size === values.length;
}
function priority(unit: LedgerUnit, changedPaths: Set<string>, priorGapIds: Set<string>): number {
  const text = [unit.surface, unit.boundary, unit.attack_class].join(" ").toLowerCase();
  let score = 0;
  if (/unauth|public|anonymous|unauthenticated|untrusted|external|pre-auth/.test(text)) score += 1000;
  if (/credential|secret|tenant|cross.?tenant|execution|release|signing|privilege|authorization/.test(text)) score += 500;
  if (priorGapIds.has(unit.coverage_id)) score += 300;
  if (Array.isArray(unit.starting_paths) && unit.starting_paths.some((p: string) => changedPaths.has(p))) score += 200;
  return score;
}
function agentFor(coverageId: string, wave: number): string {
  return `hunter-${wave}-${createHash("sha256").update(coverageId).digest("hex").slice(0, 12)}`;
}
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function prepareCloudflareHuntingWave(input: {
  ledger: LedgerUnit[];
  max_hunters: number;
  changed_paths?: string[];
  prior_gap_ids?: string[];
}) {
  const initial = validateCloudflareCoverageLedger(input.ledger);
  if (!initial.valid) throw new Error(`Cannot assign from invalid upstream coverage ledger: ${initial.errors.join("; ")}`);
  if (!Number.isInteger(input.max_hunters) || input.max_hunters < 0 || input.max_hunters > 100) {
    throw new Error("max_hunters must be an integer from 0 to 100.");
  }
  const changed = new Set(input.changed_paths ?? []);
  const gaps = new Set(input.prior_gap_ids ?? []);
  for (const path of changed) if (!isCloudflareSafeRelativePath(path)) throw new Error("changed_paths must be safe repository-relative paths.");
  const planned = input.ledger.filter(unit => unit.status === "planned");
  const ranked = [...planned].sort((a,b) =>
    priority(b, changed, gaps) - priority(a, changed, gaps) ||
    a.coverage_id.localeCompare(b.coverage_id)
  );
  const chosen = new Set(ranked.slice(0, input.max_hunters).map(unit => unit.coverage_id));
  const rationale = ranked.map((unit,index) => ({
    coverage_id: unit.coverage_id,
    priority_rank: index + 1,
    priority_score: priority(unit, changed, gaps),
    rationale: [
      /unauth|public|anonymous|untrusted|external|pre-auth/i.test([unit.surface,unit.boundary].join(" ")) ? "lower-trust or unauthenticated entry surface" : null,
      /credential|secret|tenant|execution|release|signing|privilege|authorization/i.test([unit.surface,unit.boundary,unit.attack_class].join(" ")) ? "high-value security boundary" : null,
      gaps.has(unit.coverage_id) ? "prior-run coverage gap" : null,
      unit.starting_paths.some((p: string) => changed.has(p)) ? "changed source path" : null
    ].filter(Boolean)
  }));
  const next = clone(input.ledger);
  const assignments: Array<{ coverage_id: string; agent_id: string; wave: number }> = [];
  const deferred: string[] = [];
  for (const unit of next) {
    if (unit.status !== "planned") continue;
    if (chosen.has(unit.coverage_id)) {
      const agent_id = agentFor(unit.coverage_id, unit.wave);
      unit.status = "in_progress";
      unit.agent_id = agent_id;
      assignments.push({ coverage_id: unit.coverage_id, agent_id, wave: unit.wave });
    } else {
      unit.status = "deferred";
      unit.agent_id = null;
      unit.unresolved = ["budget_cannot_reserve_critics_and_validation"];
      deferred.push(unit.coverage_id);
    }
  }
  const validation = validateCloudflareCoverageLedger(next);
  if (!validation.valid) throw new Error(`Prepared hunting ledger failed upstream validation: ${validation.errors.join("; ")}`);
  return {
    upstream: "cloudflare/security-audit-skill",
    phase: 2,
    ledger: next,
    assignments,
    deferred,
    priority_order: rationale,
    critic_reservation: { required: true, invocation_count: 1, runs_after_hunter_wave: true },
    limitations: [
      "Assignments are planning records only; this MCP tool does not spawn agents or execute tasks.",
      "Each assigned unit requires a separate fresh hunter and one structured result.",
      "Untouched units are explicitly deferred rather than silently omitted.",
      "A coverage critic must review the full ledger after the wave before another wave is prepared."
    ]
  };
}

export function consolidateCloudflareHunterResults(input: {
  ledger: LedgerUnit[];
  assigned_coverage_ids: string[];
  results: HunterResult[];
  promoted_artifacts?: string[];
}) {
  const before = validateCloudflareCoverageLedger(input.ledger);
  if (!before.valid) throw new Error(`Cannot consolidate into invalid ledger: ${before.errors.join("; ")}`);
  if (!unique(input.assigned_coverage_ids)) throw new Error("assigned_coverage_ids contains duplicates.");
  const promoted = new Set(input.promoted_artifacts ?? []);
  for (const path of promoted) if (!isCloudflareSafeRelativePath(path)) throw new Error("promoted_artifacts contains an unsafe path.");
  const resultById = new Map<string, HunterUnitResult>();
  const candidateRecords: unknown[] = [];
  const candidateFingerprints = new Set<string>();
  const hardening: string[] = [];
  const uncovered: HunterResult["uncovered"] = [];
  for (const result of input.results) {
    if (!Array.isArray(result.units) || !Array.isArray(result.candidates) || !Array.isArray(result.hardening) || !Array.isArray(result.uncovered)) {
      throw new Error("Hunter result does not match the structured result contract.");
    }
    for (const unit of result.units) {
      if (resultById.has(unit.coverage_id)) throw new Error(`Duplicate hunter result for ${unit.coverage_id}.`);
      resultById.set(unit.coverage_id, unit);
    }
    for (const candidate of result.candidates) {
      if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
        throw new Error("Hunter candidate must be an object.");
      }
      const record = candidate as Record<string, unknown>;
      if (record.proposed_verdict !== "confirmed" && record.proposed_verdict !== "needs_validation") {
        throw new Error("Hunter candidate proposed_verdict must be confirmed or needs_validation.");
      }
      if (typeof record.fingerprint !== "string" || candidateFingerprints.has(record.fingerprint)) {
        throw new Error("Hunter candidate fingerprints must be unique across the wave.");
      }
      candidateFingerprints.add(record.fingerprint);
      const proposedVerdict = record.proposed_verdict;
      const fields = { ...record };
      delete fields.proposed_verdict;
      candidateRecords.push({ ...fields, verdict: proposedVerdict });
    }
    hardening.push(...result.hardening);
    uncovered.push(...result.uncovered);
  }
  const candidateValidation = validateCloudflareFindings(candidateRecords);
  if (!candidateValidation.valid) {
    throw new Error("Hunter candidate records failed the upstream Cloudflare report schema: " + candidateValidation.errors.join("; "));
  }
  const assigned = new Set(input.assigned_coverage_ids);
  for (const id of resultById.keys()) if (!assigned.has(id)) throw new Error(`Hunter returned unassigned coverage ID ${id}.`);
  for (const id of assigned) if (!resultById.has(id)) throw new Error(`Missing structured result for assigned coverage ID ${id}; leave it in_progress for reassignment.`);

  const next = clone(input.ledger);
  const unitMap = new Map(next.map(unit => [unit.coverage_id, unit]));
  const seenFingerprints = new Set<string>();
  for (const item of next) for (const fp of item.result_fingerprints ?? []) seenFingerprints.add(fp);
  for (const [id, result] of resultById) {
    const unit = unitMap.get(id);
    if (!unit || unit.status !== "in_progress") throw new Error(`Coverage unit ${id} is not currently in_progress.`);
    if (!["covered","candidate","blocked"].includes(result.disposition)) throw new Error(`Invalid disposition for ${id}.`);
    if (!Array.isArray(result.reviewed_paths) || !result.reviewed_paths.every(isCloudflareSafeRelativePath) || !unique(result.reviewed_paths)) throw new Error(`Unsafe or duplicate reviewed_paths for ${id}.`);
    if (!Array.isArray(result.checks) || result.checks.length === 0) throw new Error(`Unit ${id} requires owned checks.`);
    const checkOwners = new Set<string>();
    const ownedPaths = new Set<string>();
    for (const check of result.checks) {
      if (!safeAgentId(check.agent_id)) throw new Error(`Unsafe check agent_id for ${id}.`);
      checkOwners.add(check.agent_id);
      if (!Array.isArray(check.reviewed_paths) || check.reviewed_paths.length === 0 || !check.reviewed_paths.every(isCloudflareSafeRelativePath)) throw new Error(`Check paths are invalid for ${id}.`);
      for (const path of check.reviewed_paths) ownedPaths.add(path);
      if (typeof check.invariant !== "string" || !check.invariant.trim() || typeof check.result !== "string" || !check.result.trim()) throw new Error(`Check invariant/result missing for ${id}.`);
      if (check.method === "source" && check.artifact !== null) throw new Error(`Source check cannot reference an artifact for ${id}.`);
      if (check.method === "local") {
        if (typeof check.artifact !== "string" || !check.artifact.startsWith(`agents/${check.agent_id}/artifacts/`) || !promoted.has(check.artifact)) {
          throw new Error(`Local check artifact was not verified as parent-promoted for ${id}.`);
        }
      } else if (check.method !== "source") throw new Error(`Unknown check method for ${id}.`);
    }
    if (ownedPaths.size !== result.reviewed_paths.length || result.reviewed_paths.some(path => !ownedPaths.has(path))) throw new Error(`Reviewed path ownership mismatch for ${id}.`);
    if (checkOwners.has(unit.agent_id) === false) throw new Error(`Assigned hunter ownership missing from checks for ${id}.`);
    if (!Array.isArray(result.unresolved) || !unique(result.unresolved)) throw new Error(`Invalid unresolved list for ${id}.`);
    if (result.disposition === "covered" && (result.unresolved.length || result.candidate_fingerprints.length)) throw new Error(`Covered unit ${id} cannot have unresolved facts or candidates.`);
    if (result.disposition === "candidate" && (!result.candidate_fingerprints.length || result.unresolved.length)) throw new Error(`Candidate unit ${id} needs fingerprints and no unresolved facts.`);
    if (result.disposition === "blocked" && !result.unresolved.length) throw new Error(`Blocked unit ${id} requires unresolved facts.`);
    if (!Array.isArray(result.candidate_fingerprints) || !unique(result.candidate_fingerprints)) throw new Error(`Invalid candidate fingerprints for ${id}.`);
    for (const fp of result.candidate_fingerprints) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(fp)) throw new Error(`Invalid fingerprint ${fp}.`);
      if (seenFingerprints.has(fp)) throw new Error(`Duplicate candidate fingerprint ${fp}; consolidate at parent before ledger update.`);
      seenFingerprints.add(fp);
    }
    unit.status = result.disposition;
    unit.reviewed_paths = [...result.reviewed_paths].sort();
    unit.local_checks = clone(result.checks);
    unit.result_fingerprints = [...result.candidate_fingerprints].sort();
    unit.unresolved = [...result.unresolved];
  }
  const validation = validateCloudflareCoverageLedger(next);
  if (!validation.valid) throw new Error(`Consolidated ledger failed upstream validation: ${validation.errors.join("; ")}`);
  return {
    ledger: next,
    candidate_records: candidateRecords,
    hardening_notes: hardening,
    uncovered_proposals: uncovered,
    validation,
    next_step: "Run one fresh source-reading coverage critic against the full ledger; accept no further wave until its missing_units and reassign_ids are resolved or explicitly deferred."
  };
}

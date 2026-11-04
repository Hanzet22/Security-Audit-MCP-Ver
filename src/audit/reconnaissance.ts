/**
 * Cloudflare Security Audit Skill Phase 1 adapter.
 * Produces deterministic run metadata, architecture summary, and canonical ledger.
 * This module does not spawn agents, execute target code, or contact deployed systems.
 * Copyright (C) 2026 Hanzet22 — GNU AGPL-3.0-or-later.
 */
import { canonicalCloudflareCoverageId, isCloudflareSafeRelativePath, validateCloudflareCoverageLedger } from "./upstream.js";

export type ReconFact = { statement: string; refs: string[] };
export type ScoutReports = {
  product_stack: ReconFact[];
  principals_controls: ReconFact[];
  entry_surfaces_sinks: ReconFact[];
  local_execution_deployment: ReconFact[];
};
export type ReconCoverageUnit = {
  canonical_refs: { surface: string; boundary: string; subsystem: string; attack_class: string; lifecycle?: string | undefined };
  surface: string;
  boundary: string;
  subsystem: string;
  attack_class: string;
  lifecycle?: string | undefined;
  starting_paths: string[];
  ordinary_attack_class_block: string | null;
  selected_companion_blocks: string[];
  excluded_blocks: Array<{ block: string; reason: string }>;
};

const REQUIRED_SCOUTS = [
  "product_stack",
  "principals_controls",
  "entry_surfaces_sinks",
  "local_execution_deployment"
] as const;

function escapeMarkdown(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/([\x60*_{}\[\]()#+\-.!|>])/g, "\\$1")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function words(value: string): number {
  return value.trim() ? value.trim().split(/\s+/u).length : 0;
}

function factLines(name: string, facts: ReconFact[]): string[] {
  return [
    `### ${name}`,
    ...(facts.length ? facts.map(f => `- ${escapeMarkdown(f.statement)} (source: ${f.refs.map(escapeMarkdown).join(", ")})`) : ["- Not supplied; this area remains unmapped."])
  ];
}

export function prepareCloudflareReconnaissance(input: {
  run_id: string;
  repository: string;
  target: string;
  source_ref: string;
  profile: "quick" | "standard" | "deep";
  scope_paths: string[];
  budget: number | null;
  scout_reports: ScoutReports;
  coverage_units: ReconCoverageUnit[];
  prior_run_paths?: string[] | undefined;
  selected_companion_files?: string[] | undefined;
}) {
  const minimum = 4 + (input.profile === "quick" ? 1 : 2) + 1;
  if (input.scope_paths.some(path => !isCloudflareSafeRelativePath(path))) {
    throw new Error("scope_paths must contain safe repository-relative paths.");
  }
  if (new Set(input.scope_paths).size !== input.scope_paths.length) {
    throw new Error("scope_paths must not contain duplicates.");
  }
  const companionFiles = input.selected_companion_files ?? [];
  if (!companionFiles.every(isCloudflareSafeRelativePath) || new Set(companionFiles).size !== companionFiles.length) {
    throw new Error("selected_companion_files must contain unique safe repository-relative paths.");
  }
  const scopeSet = new Set(input.scope_paths);
  if (input.profile === "quick" && input.coverage_units.some(unit =>
    unit.canonical_refs.subsystem !== "profile/quick/all-in-scope-subsystems" || unit.canonical_refs.lifecycle !== undefined
  )) {
    throw new Error("The quick profile requires the fixed canonical subsystem reference and must not split units by lifecycle.");
  }
  const budgetBlocked = input.budget !== null && input.budget < minimum;
  if ((input.prior_run_paths ?? []).length > 0) {
    throw new Error("Prior-run paths alone are not prior evidence. Load and validate the actual prior run-metadata.json, coverage-ledger.json, and findings.json before supplying carry-forward data.");
  }
  const metadata = {
    run_id: input.run_id,
    repo: input.repository,
    target: input.target,
    source_ref: input.source_ref,
    profile: input.profile,
    scope_paths: input.scope_paths,
    budget: input.budget,
    execution_policy: "sandboxed-source-and-local-only",
    selected_companion_files: input.selected_companion_files ?? [],
    prior_run_paths: input.prior_run_paths ?? [],
    shared_file_owners: {
      "run-metadata.json": "parent",
      "architecture.md": "parent",
      "coverage-ledger.json": "parent",
      "findings.json": "parent"
    },
    run_status: budgetBlocked ? "incomplete" : "in_progress",
    ...(budgetBlocked ? { incomplete_reason: "budget_cannot_fund_reconnaissance_and_reserves" } : {}),
    budget_gate: {
      minimum_agent_invocations: minimum,
      baseline_reconnaissance_invocations: 4,
      reserved_critic_invocations: input.profile === "quick" ? 1 : 2,
      reserved_verifier_invocations: 1,
      passed: !budgetBlocked
    },
    prior_run_handling: "No compatible prior-run ledger or findings were supplied; no prior coverage is assumed."
  };

  const allFacts = [
    ...factLines("Product, stack, and local operation", input.scout_reports.product_stack),
    ...factLines("Principals, authority, and controls", input.scout_reports.principals_controls),
    ...factLines("Entry surfaces, copies, and sinks", input.scout_reports.entry_surfaces_sinks),
    ...factLines("Local execution and deployment visibility", input.scout_reports.local_execution_deployment)
  ];
  const architecture = [
    "# Architecture Summary",
    "",
    `- Repository: ${escapeMarkdown(input.repository)}`,
    `- Source ref: ${escapeMarkdown(input.source_ref)}`,
    `- Profile: ${input.profile}`,
    `- Scope: ${input.scope_paths.length ? `${input.scope_paths.length} explicit repository paths` : "all discovered paths"}`,
    `- Prior-run input: ${metadata.prior_run_handling}`,
    "",
    ...allFacts,
    "",
    "## Method and limitations",
    "- Reconnaissance is source-only and read-only.",
    "- No target code, build, test, browser, emulator, or fixture was executed.",
    "- No deployed endpoint, identity provider, registry, broker, cloud API, or shared service was contacted.",
    "- Facts without repository-relative file:line references must be treated as unverified.",
    "- Coverage is represented by the ledger, not by this narrative summary.",
    "- This MCP adapter does not spawn research agents; the four scout reports are supplied by the caller."
  ].join("\n");
  if (words(architecture) > 1000) {
    throw new Error("architecture.md exceeds the upstream ~1,000-word cap.");
  }

  const ledger = budgetBlocked ? [] : input.coverage_units.map(unit => {
    const startingPaths = input.scope_paths.length === 0
      ? unit.starting_paths
      : unit.starting_paths.filter(path => scopeSet.has(path));
    const inScope = startingPaths.length > 0;
    const refs = unit.canonical_refs;
    const priorStatus = "none";
    const lifecycleFields = refs.lifecycle === undefined ? {} : { lifecycle: unit.lifecycle ?? refs.lifecycle };
    return {
      coverage_id: canonicalCloudflareCoverageId(refs),
      canonical_refs: refs,
      surface: unit.surface,
      boundary: unit.boundary,
      subsystem: unit.subsystem,
      attack_class: unit.attack_class,
      ...lifecycleFields,
      starting_paths: inScope ? startingPaths : unit.starting_paths,
      ordinary_attack_class_block: unit.ordinary_attack_class_block,
      selected_companion_blocks: unit.selected_companion_blocks,
      excluded_blocks: unit.excluded_blocks,
      prior_status: priorStatus,
      attempts: [],
      wave: 1,
      status: inScope ? "planned" : "out_of_scope",
      agent_id: null,
      reviewed_paths: [],
      local_checks: [],
      result_fingerprints: [],
      unresolved: inScope ? [] : ["This discovered surface is outside the declared scope."]
    };
  }).sort((a,b) => a.coverage_id.localeCompare(b.coverage_id));

  const validation = budgetBlocked
    ? { valid: true, errors: [], unit_count: 0 }
    : validateCloudflareCoverageLedger(ledger);
  return {
    run_metadata: metadata,
    architecture_md: architecture,
    coverage_ledger: ledger,
    coverage_validation: validation,
    ready_for_hunting: !budgetBlocked && validation.valid && ledger.length > 0,
    limitations: [
      "The four scout reports and coverage-unit candidates are caller-supplied; this server does not create sub-agents.",
      "A planned unit is not reviewed or covered. It must receive owned source checks before its state can advance.",
      "Prior-run paths are not prior evidence. Carry-forward requires loading and validating the actual prior ledger and findings, then comparing current source.",
      "A scoped run is partial; out-of-scope units remain visible and are never counted as covered."
    ]
  };
}

export function reconnaissanceMinimumBudget(profile: "quick" | "standard" | "deep"): number {
  return 4 + (profile === "quick" ? 1 : 2) + 1;
}

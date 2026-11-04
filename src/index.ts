/**
 * Security-Audit-MCP-Ver
 * Copyright (C) 2026 Hanzet22
 * Licensed under GNU AGPL v3.0 or later. See LICENSE.
 *
 * Read-only source audit workflow. It never executes target code or probes
 * deployed services. Independent review is supplied as a separate input;
 * this MCP process does not claim to spawn independent agents.
 */
import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import {
  CoverageEntrySchema,
  FindingSchema,
  validateCoverage,
  validateFindings,
  verifyIndependentReview
} from "./audit/contracts.js";
import {
  validateCloudflareCoverageLedger,
  validateCloudflareFindings
} from "./audit/upstream.js";
import { prepareCloudflareReconnaissance } from "./audit/reconnaissance.js";
import { consolidateCloudflareHunterResults, prepareCloudflareHuntingWave } from "./audit/hunting.js";
import { orchestrateWorkerRun, validateCloudflareCoverageCritic, validateWorkerResult, validateWorkerTask } from "./audit/orchestration.js";

const API_ROOT = "https://api.github.com";
const MAX_FILE_BYTES = 300_000;
const MAX_API_RESPONSE_BYTES = 5_000_000;
const MAX_TREE_ITEMS = 500;
const MAX_SOURCE_CHARS = 100_000;
const token = process.env.GITHUB_TOKEN;

type RepoRef = { owner: string; repo: string; ref?: string };

function parseRepo(input: string, ref?: string): RepoRef {
  const raw = input.trim();
  let parts: string[];

  if (/^https?:\/\//i.test(raw)) {
    const url = new URL(raw);
    if (url.protocol !== "https:" ||
        !["github.com", "www.github.com"].includes(url.hostname.toLowerCase()) ||
        url.username || url.password || (url.port && url.port !== "443")) {
      throw new Error("Only standard HTTPS GitHub repository URLs without credentials or custom ports are accepted.");
    }
    if (url.search || url.hash) throw new Error("Repository URLs must not include query strings or fragments.");
    const pathname = url.pathname.replace(/\/$/, "");
    parts = pathname.slice(1).split("/");
    if (parts.at(-1)?.endsWith(".git")) parts[parts.length - 1] = parts.at(-1)!.slice(0, -4);
  } else {
    parts = raw.replace(/\.git$/, "").split("/");
  }

  if (parts.length !== 2 || parts.some(part => !part || part === "." || part === "..") ||
      !/^[A-Za-z0-9_.-]+$/.test(parts[0] ?? "") || !/^[A-Za-z0-9_.-]+$/.test(parts[1] ?? "")) {
    throw new Error("Repository must be owner/name or a GitHub repository URL.");
  }
  if (ref !== undefined && (!ref.trim() || ref.length > 200 || /[\u0000-\u001f\u007f]/.test(ref))) {
    throw new Error("Git reference must be non-empty, at most 200 characters, and contain no control characters.");
  }
  return { owner: parts[0]!, repo: parts[1]!, ...(ref ? { ref } : {}) };
}

async function github(path: string): Promise<any> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "Security-Audit-MCP-Ver"
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${API_ROOT}${path}`, {
    headers,
    signal: AbortSignal.timeout(15_000)
  });
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error(`GitHub API returned HTTP ${response.status}.`);
  }

  const contentType = response.headers.get("content-type") ?? "";
  if (!/application\/(?:json|vnd\.github\+json)/i.test(contentType)) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("GitHub API returned an unexpected content type.");
  }

  const declaredLength = Number(response.headers.get("content-length") ?? 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_API_RESPONSE_BYTES) {
    await response.body?.cancel().catch(() => undefined);
    throw new Error("GitHub API response exceeds the configured size limit.");
  }

  if (!response.body) throw new Error("GitHub API returned an empty response body.");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_API_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("GitHub API response exceeds the configured size limit.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error("GitHub API returned invalid JSON.");
  }
}

function result(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

function failure(error: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify({
      error: error instanceof Error ? error.message : String(error)
    }) }],
    isError: true
  };
}

async function inspectRepo(repository: string, ref?: string) {
  const parsed = parseRepo(repository, ref);
  const base = `/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`;
  const metadata = await github(base);
  const branch = parsed.ref ?? metadata.default_branch;
  const tree = await github(`${base}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  if (!tree || !Array.isArray(tree.tree)) throw new Error("GitHub API returned an invalid repository tree.");
  const entries: Array<{ path: string; type: string; size: number | null }> = tree.tree.slice(0, MAX_TREE_ITEMS).map((item: { path: string; type: string; size?: number | null }) => ({
    path: item.path as string,
    type: item.type as string,
    size: item.size ?? null
  }));
  return {
    repository: metadata.full_name,
    default_branch: metadata.default_branch,
    ref: branch,
    visibility: metadata.visibility,
    license: metadata.license?.spdx_id ?? null,
    archived: Boolean(metadata.archived),
    truncated: Boolean(tree.truncated) || (tree.tree?.length ?? 0) > MAX_TREE_ITEMS,
    entries
  };
}

function categorize(path: string): "application" | "configuration" | "dependency" | "test" | "documentation" | "generated" | "unknown" {
  if (/(^|\/)(dist|build|coverage)(\/|$)/i.test(path)) return "generated";
  if (/(^|\/)vendor(\/|$)/i.test(path) ||
      /(^|\/)(package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|Cargo\.lock|go\.sum)$/i.test(path) ||
      /(requirements.*\.txt)$/i.test(path)) return "dependency";
  if (/(^|\/)(test|tests|__tests__|spec)(\/|$)|\.(test|spec)\.[^.]+$/i.test(path)) return "test";
  if (/\.(md|mdx|rst|txt)$/i.test(path)) return "documentation";
  if (/\.(json|ya?ml|toml|ini|conf|config)$/i.test(path) || /(^|\/)(\.github|\.npmrc|\.nvmrc)(\/|$)/i.test(path)) return "configuration";
  if (/\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|kt|php|rb|cs|swift|c|cc|cpp|h|hpp|sql)$/i.test(path)) return "application";
  return "unknown";
}

function redactEvidence(line: string): string {
  return line
    .replace(/((?:api[_-]?key|secret|password|token|authorization|access[_-]?key|client[_-]?secret)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:(?:Bearer|Basic)\s+)?[^\s,;]+)/gi, "$1[REDACTED]")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [REDACTED]")
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, "[REDACTED]")
    .replace(/\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b/gi, "[REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, "[REDACTED]")
    .replace(/\bhttps?:\/\/[^\s/@:]+:[^\s/@]+@/gi, "https://[REDACTED]@")
    .slice(0, 220);
}

function escapeMarkdown(value: string): string {
  return value
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/([\x60*_{}\[\]()#+\-.!|>])/g, "\\$1")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function generateReport(
  repository: string,
  scope: string,
  findings: Array<z.infer<typeof FindingSchema>>,
  coverageComplete: boolean,
  verificationPassed: boolean,
  requestedStatus: "complete" | "incomplete"
) {
  const runComplete = requestedStatus === "complete" && coverageComplete && verificationPassed;
  const status = runComplete ? "complete" : "incomplete";
  const confirmed = findings.filter(item => item.verdict === "confirmed");
  const pending = findings.filter(item => item.verdict === "needs_validation");
  const rejected = findings.filter(item => item.verdict === "rejected");

  const report = [
    "# Security Audit Report",
    "",
    `- Repository: ${escapeMarkdown(repository)}`,
    `- Scope: ${escapeMarkdown(scope)}`,
    `- Run status: ${status}`,
    `- Confirmed: ${confirmed.length}`,
    `- Needs validation: ${pending.length}`,
    `- Rejected: ${rejected.length}`,
    "",
    status === "complete"
      ? "Coverage and independent-record verification gates were reported as passed by the caller."
      : "This run is incomplete. Do not interpret the current findings as a complete audit.",
    "",
    "## Confirmed findings",
    confirmed.length ? confirmed.map(item => `- **${escapeMarkdown(item.title)}** (${item.severity}, ${item.confidence}) — ${escapeMarkdown(item.description)}`).join("\n") : "No confirmed findings recorded.",
    "",
    "## Needs validation",
    pending.length ? pending.map(item => `- **${escapeMarkdown(item.title)}** — ${escapeMarkdown(item.description)} Blockers: ${item.blockers.map(escapeMarkdown).join("; ")}`).join("\n") : "No pending candidates.",
    "",
    "## Rejected candidates",
    rejected.length ? rejected.map(item => `- **${escapeMarkdown(item.title)}** — ${escapeMarkdown(item.rejection_reason)}`).join("\n") : "No rejected candidates.",
    "",
    "## Method and limitations",
    "- Source inspection only; target code was not executed.",
    "- No production or third-party endpoints were probed.",
    "- A pattern match is not proof of exploitability.",
    "- Independent verification is an explicit input gate, not an agent spawned by this server.",
    "- Any missing phase or unavailable validation environment must remain disclosed as incomplete."
  ].join("\n");

  const detail = [
    "# Findings Detail",
    "",
    ...findings.map(item => [
      `## ${escapeMarkdown(item.title)}`,
      `- Verdict: ${item.verdict}`,
      `- Fingerprint: ${escapeMarkdown(item.fingerprint)}`,
      `- Description: ${escapeMarkdown(item.description)}`,
      ...item.evidence.map(ev => `- Evidence: ${escapeMarkdown(ev.file)}:${ev.line} — ${escapeMarkdown(ev.description)}`),
      ...item.trace.map(step => `- Trace (${escapeMarkdown(step.kind)}): ${escapeMarkdown(step.file)}:${step.line} — ${escapeMarkdown(step.description)}`),
      item.verdict === "confirmed" ? `- Root cause: ${escapeMarkdown(item.root_cause)}` : `- Claimed root cause: ${escapeMarkdown(item.claimed_root_cause)}`,
      item.verdict === "confirmed" ? `- Affected boundary: ${escapeMarkdown(item.affected_boundary)}` : "",
      item.verdict === "confirmed" ? `- Impact: ${escapeMarkdown(item.impact)}` : "",
      item.verdict === "confirmed" ? `- Severity: ${item.severity}; confidence: ${item.confidence}` : "",
      item.verdict === "confirmed" ? `- Remediation: ${escapeMarkdown(item.remediation)}` : "",
      item.verdict === "rejected" ? `- Rejection reason: ${escapeMarkdown(item.rejection_reason)}` : "",
      item.verdict === "needs_validation" ? `- Blockers: ${item.blockers.map(escapeMarkdown).join("; ")}` : "",
      ""
    ].filter(Boolean).join("\n"))
  ].join("\n");

  const needsValidation = [
    "# Needs Validation",
    "",
    ...pending.map(item => `## ${escapeMarkdown(item.title)}\n\n${escapeMarkdown(item.description)}\n\nBlockers:\n${item.blockers.map(b => `- ${escapeMarkdown(b)}`).join("\n")}\n\nValidation plan: ${escapeMarkdown(item.validation_plan)}\n`)
  ].join("\n");

  return {
    run_status: status,
    "findings.json": JSON.stringify(findings, null, 2),
    "REPORT.md": report,
    "FINDINGS-DETAIL.md": detail,
    "NEEDS-VALIDATION.md": needsValidation
  };
}

const WorkerTaskSchema = z.strictObject({
  contract_version: z.literal("1.0"),
  task_id: z.string().min(1).max(64),
  worker_id: z.string().min(1).max(64),
  role: z.enum(["recon", "hunter", "critic", "verifier"]),
  source_ref: z.string().min(1).max(200),
  coverage_ids: z.array(z.string().min(1).max(65536)).min(1).max(10000),
  allowed_paths: z.array(z.string().min(1).max(500)).min(1).max(5000),
  objective: z.string().min(1).max(3000),
  prohibited_actions: z.array(z.string().min(1).max(1000)).min(1).max(100)
});

const OrchestrationStateSchema = z.strictObject({
  version: z.literal("1.0"),
  run_id: z.string().min(1).max(64),
  phase: z.enum(["hunting", "critic_pending", "verification_pending", "ready_for_next_wave", "complete", "blocked"]),
  assignments: z.array(z.strictObject({
    task_id: z.string().min(1).max(64),
    worker_id: z.string().min(1).max(64),
    coverage_id: z.string().min(1).max(65536),
    status: z.enum(["assigned", "completed", "blocked"])
  })).min(1).max(100),
  critic_gate_passed: z.boolean(),
  verification_passed: z.boolean(),
  history: z.array(z.string().min(1).max(500)).max(1000)
});

const HunterResultSchema = z.strictObject({
  units: z.array(z.strictObject({
    coverage_id: z.string().min(1).max(65536),
    disposition: z.enum(["covered", "candidate", "blocked"]),
    reviewed_paths: z.array(z.string().min(1).max(500)).max(5000),
    checks: z.array(z.strictObject({
      agent_id: z.string().min(1).max(64),
      reviewed_paths: z.array(z.string().min(1).max(500)).min(1).max(5000),
      invariant: z.string().min(1).max(5000),
      method: z.enum(["source", "local"]),
      result: z.string().min(1).max(5000),
      artifact: z.string().max(1000).nullable()
    })).min(1).max(1000),
    candidate_fingerprints: z.array(z.string().min(1).max(500)).max(1000),
    unresolved: z.array(z.string().min(1).max(1000)).max(1000)
  })).min(1).max(10000),
  candidates: z.array(z.record(z.string(), z.unknown())).max(1000),
  hardening: z.array(z.string().min(1).max(2000)).max(1000),
  uncovered: z.array(z.strictObject({
    surface: z.string().min(1).max(2000),
    boundary: z.string().min(1).max(2000),
    subsystem: z.string().min(1).max(2000),
    attack_class: z.string().min(1).max(2000),
    starting_paths: z.array(z.string().min(1).max(500)).min(1).max(100),
    reason: z.string().min(1).max(3000)
  })).max(1000)
});

export function createServer(): McpServer {
  const server = new McpServer({
    name: "security-audit-mcp-ver",
    version: "0.3.0"
  });

  server.registerTool("repository_inspect", {
    description: "Read GitHub repository metadata. Read-only; no code is executed.",
    inputSchema: z.object({ repository: z.string().min(3).max(300) })
  }, async ({ repository }) => {
    try {
      const parsed = parseRepo(repository);
      const data = await github(`/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`);
      return result({
        repository: data.full_name,
        description: data.description,
        visibility: data.visibility,
        default_branch: data.default_branch,
        archived: data.archived,
        license: data.license?.spdx_id ?? null,
        html_url: data.html_url,
        security_note: "Metadata only; no code was executed or tested."
      });
    } catch (error) { return failure(error); }
  });

  server.registerTool("repository_tree", {
    description: "List bounded repository paths from GitHub's Git tree API.",
    inputSchema: z.object({
      repository: z.string().min(3).max(300),
      ref: z.string().max(200).optional()
    })
  }, async ({ repository, ref }) => {
    try {
      const data = await inspectRepo(repository, ref);
      return result({
        repository: data.repository,
        ref: data.ref,
        truncated: data.truncated,
        returned_entries: data.entries.length,
        entries: data.entries
      });
    } catch (error) { return failure(error); }
  });

  server.registerTool("repository_read_file", {
    description: "Read one bounded text file from a GitHub repository. No code is executed.",
    inputSchema: z.object({
      repository: z.string().min(3).max(300),
      path: z.string().min(1).max(500),
      ref: z.string().max(200).optional()
    })
  }, async ({ repository, path, ref }) => {
    try {
      if (path.startsWith("/") || path.includes("\\") ||
          /[\u0000-\u001f\u007f]/.test(path) ||
          path.split("/").some(part => part === "." || part === ".." || part === "")) {
        throw new Error("Absolute paths, backslashes, control characters, dot segments and empty path segments are not allowed.");
      }
      const parsed = parseRepo(repository, ref);
      const suffix = parsed.ref ? `?ref=${encodeURIComponent(parsed.ref)}` : "";
      const apiPath = path.split("/").map(encodeURIComponent).join("/");
      const data = await github(`/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/contents/${apiPath}${suffix}`);
      if (Array.isArray(data) || data.type !== "file") throw new Error("The requested path is not a single file.");
      if ((data.size ?? 0) > MAX_FILE_BYTES) throw new Error("File exceeds the 300 KB read limit.");
      if (data.encoding !== "base64" || typeof data.content !== "string") throw new Error("GitHub did not return a supported text file.");
      const base64 = data.content.replace(/\s/g, "");
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
        throw new Error("GitHub returned invalid base64 file content.");
      }
      const bytes = Buffer.from(base64, "base64");
      const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      if (content.includes("\u0000")) throw new Error("Binary-looking content is not supported.");
      return result({ repository: `${parsed.owner}/${parsed.repo}`, path, size_bytes: data.size, content });
    } catch (error) { return failure(error); }
  });

  server.registerTool("cloudflare_reconnaissance_prepare", {
    description: "Cloudflare Skill Phase 1 adapter: synthesize four caller-supplied read-only scout reports into run-metadata.json, architecture.md, and a canonical coverage-ledger.json validated by the upstream validator. Does not spawn agents or execute target code.",
    inputSchema: z.object({
      run_id: z.string().min(1).max(100),
      repository: z.string().min(3).max(300),
      target: z.string().min(1).max(1000),
      source_ref: z.string().min(7).max(100),
      profile: z.enum(["quick", "standard", "deep"]).default("standard"),
      scope_paths: z.array(z.string().min(1).max(500)).max(5000).default([]),
      budget: z.number().int().nonnegative().nullable().default(null),
      prior_run_paths: z.array(z.string().min(1).max(1000)).max(100).optional(),
      selected_companion_files: z.array(z.string().min(1).max(300)).max(100).optional(),
      scout_reports: z.strictObject({
        product_stack: z.array(z.strictObject({ statement: z.string().min(1).max(2000), refs: z.array(z.string().min(1).max(500)).min(1).max(30) })).max(100),
        principals_controls: z.array(z.strictObject({ statement: z.string().min(1).max(2000), refs: z.array(z.string().min(1).max(500)).min(1).max(30) })).max(100),
        entry_surfaces_sinks: z.array(z.strictObject({ statement: z.string().min(1).max(2000), refs: z.array(z.string().min(1).max(500)).min(1).max(30) })).max(100),
        local_execution_deployment: z.array(z.strictObject({ statement: z.string().min(1).max(2000), refs: z.array(z.string().min(1).max(500)).min(1).max(30) })).max(100)
      }),
      coverage_units: z.array(z.strictObject({
        canonical_refs: z.strictObject({
          surface: z.string().min(1).max(4096),
          boundary: z.string().min(1).max(4096),
          subsystem: z.string().min(1).max(4096),
          attack_class: z.string().min(1).max(4096),
          lifecycle: z.string().min(1).max(4096).optional()
        }),
        surface: z.string().min(1).max(4096),
        boundary: z.string().min(1).max(4096),
        subsystem: z.string().min(1).max(4096),
        attack_class: z.string().min(1).max(4096),
        lifecycle: z.string().min(1).max(4096).optional(),
        starting_paths: z.array(z.string().min(1).max(500)).min(1).max(100),
        ordinary_attack_class_block: z.string().min(1).max(300).nullable(),
        selected_companion_blocks: z.array(z.string().min(1).max(300)).max(100),
        excluded_blocks: z.array(z.strictObject({ block: z.string().min(1).max(300), reason: z.string().min(1).max(2000) })).max(100)
      })).max(5000)
    })
  }, async input => {
    try {
      return result({
        upstream: "cloudflare/security-audit-skill",
        upstream_commit: "c1c8a8c1471069fb0e188eeaff69b8e8db6564a8",
        phase: 1,
        ...prepareCloudflareReconnaissance(input)
      });
    } catch (error) { return failure(error); }
  });

  server.registerTool("cloudflare_hunting_wave_prepare", {
    description: "Cloudflare Skill Phase 2 parent-side planner: validate a canonical ledger, rank planned units deterministically, assign a bounded wave, and explicitly defer untouched units. Does not spawn hunters.",
    inputSchema: z.object({
      ledger: z.array(z.unknown()).max(10000),
      max_hunters: z.number().int().min(0).max(100),
      changed_paths: z.array(z.string().min(1).max(500)).max(5000).optional(),
      prior_gap_ids: z.array(z.string().min(1).max(65536)).max(10000).optional()
    })
  }, async input => {
    try {
      return result(prepareCloudflareHuntingWave(input as Parameters<typeof prepareCloudflareHuntingWave>[0]));
    } catch (error) { return failure(error); }
  });

  server.registerTool("cloudflare_hunter_results_consolidate", {
    description: "Cloudflare Skill Phase 2 parent-side consolidator: validate structured hunter unit results, ownership, source/local checks and parent-promoted artifact paths, then update only assigned ledger units. Does not execute targets or promote artifacts.",
    inputSchema: z.object({
      ledger: z.array(z.unknown()).max(10000),
      assigned_coverage_ids: z.array(z.string().min(1).max(65536)).min(1).max(10000),
      results: z.array(HunterResultSchema).max(100),
      promoted_artifacts: z.array(z.string().min(1).max(1000)).max(10000).optional()
    })
  }, async input => {
    try {
      return result(consolidateCloudflareHunterResults(input as Parameters<typeof consolidateCloudflareHunterResults>[0]));
    } catch (error) { return failure(error); }
  });


  server.registerTool("cloudflare_coverage_critic", {
    description: "Validate a caller-supplied full-ledger critic review, identify unexamined or newly proposed coverage, and gate the next wave. Does not spawn an independent critic or inspect source files itself.",
    inputSchema: z.strictObject({
      ledger: z.array(z.unknown()).max(10000),
      review: z.strictObject({
        reviewer_id: z.string().min(1).max(64),
        reviewed_at: z.string().min(1).max(100),
        architecture_refs: z.array(z.string().min(1).max(1000)).min(1).max(500),
        examined_coverage_ids: z.array(z.string().min(1).max(65536)).max(10000),
        missing_units: z.array(z.strictObject({
          coverage_id: z.string().min(1).max(65536),
          reason: z.string().min(1).max(3000),
          starting_paths: z.array(z.string().min(1).max(500)).min(1).max(100)
        })).max(1000),
        reassign_ids: z.array(z.strictObject({
          coverage_id: z.string().min(1).max(65536),
          reason: z.string().min(1).max(3000)
        })).max(10000),
        accepted_deferred_ids: z.array(z.strictObject({
          coverage_id: z.string().min(1).max(65536),
          reason: z.string().min(1).max(3000)
        })).max(10000),
        unresolved_questions: z.array(z.string().min(1).max(3000)).max(1000)
      })
    })
  }, async input => {
    try { return result(validateCloudflareCoverageCritic(input as Parameters<typeof validateCloudflareCoverageCritic>[0])); }
    catch (error) { return failure(error); }
  });

  server.registerTool("worker_task_contract_validate", {
    description: "Validate a versioned worker task contract, role, source ref, assigned coverage IDs, safe owned paths, objective and explicit prohibited actions. Does not start a worker.",
    inputSchema: WorkerTaskSchema

  }, async task => {
    try { return result(validateWorkerTask(task)); }
    catch (error) { return failure(error); }
  });

  server.registerTool("worker_result_contract_validate", {
    description: "Validate a worker result against its assigned task identity and path ownership. Evidence references are caller-supplied and are not independently authenticated by this contract.",
    inputSchema: z.strictObject({
      task: WorkerTaskSchema,
      worker_result: z.strictObject({
        contract_version: z.literal("1.0"),
        task_id: z.string().min(1).max(64),
        worker_id: z.string().min(1).max(64),
        status: z.enum(["completed", "blocked"]),
        reviewed_paths: z.array(z.string().min(1).max(500)).max(5000),
        evidence_refs: z.array(z.string().min(1).max(2000)).max(10000),
        summary: z.string().min(1).max(10000),
        blockers: z.array(z.string().min(1).max(3000)).max(1000)
      })
    })
  }, async input => {
    try { return result(validateWorkerResult({ task: input.task as Parameters<typeof validateWorkerResult>[0]["task"], result: input.worker_result })); }
    catch (error) { return failure(error); }
  });

  server.registerTool("worker_orchestrator_step", {
    description: "Advance a stateless parent-side workflow through hunting, critic, independent-verification and next-wave gates. Validate each worker payload with worker_result_contract_validate before recording its status. State is caller-held unsigned JSON and is not an authorization or attestation boundary. Caller supplies all results; no agents, processes, queues or background jobs are spawned.",
    inputSchema: z.discriminatedUnion("action", [
      z.strictObject({
        action: z.literal("initialize"),
        run_id: z.string().min(1).max(64),
        assignments: z.array(z.strictObject({
          task_id: z.string().min(1).max(64),
          worker_id: z.string().min(1).max(64),
          coverage_id: z.string().min(1).max(65536)
        })).min(1).max(100)
      }),
      z.strictObject({ action: z.literal("record_result"), state: OrchestrationStateSchema, task_id: z.string().min(1).max(64), status: z.enum(["completed", "blocked"]) }),
      z.strictObject({ action: z.literal("record_critic"), state: OrchestrationStateSchema, gate_passed: z.boolean() }),
      z.strictObject({ action: z.literal("record_verification"), state: OrchestrationStateSchema, passed: z.boolean() }),
      z.strictObject({ action: z.literal("next_wave"), state: OrchestrationStateSchema })
    ])
  }, async input => {
    try { return result(orchestrateWorkerRun(input as Parameters<typeof orchestrateWorkerRun>[0])); }
    catch (error) { return failure(error); }
  });

  server.registerTool("audit_reconnaissance", {
    description: "Phase 1: map repository metadata and paths, classify files, and create an initial not-yet-reviewed inventory.",
    inputSchema: z.object({
      repository: z.string().min(3).max(300),
      ref: z.string().max(200).optional()
    })
  }, async ({ repository, ref }) => {
    try {
      const data = await inspectRepo(repository, ref);
      const inventory = data.entries.filter(entry => entry.type === "blob").map(entry => ({
        path: entry.path,
        size: entry.size,
        category: categorize(entry.path),
        status: "not_reviewed",
        rationale: "Inventoried during reconnaissance; source review has not yet been completed."
      }));
      return result({
        phase: 1,
        repository: data.repository,
        ref: data.ref,
        visibility: data.visibility,
        truncated: data.truncated,
        scope_note: "This is an inventory, not a completed security review.",
        inventory
      });
    } catch (error) { return failure(error); }
  });

  server.registerTool("source_security_review", {
    description: "Phase 2/3: generate heuristic source-review candidates. Results are leads only and never confirmed automatically.",
    inputSchema: z.object({
      source: z.string().min(1).max(MAX_SOURCE_CHARS),
      filename: z.string().max(500).optional()
    })
  }, async ({ source, filename }) => {
    if (Buffer.byteLength(source, "utf8") > 100_000) {
      return failure(new Error("Source input exceeds the 100 KB UTF-8 byte limit."));
    }
    const rules: Array<{ id: string; title: string; regex: RegExp; rationale: string }> = [
      { id: "JS_DYNAMIC_EVAL", title: "Dynamic code evaluation", regex: /\beval\s*\(|new\s+Function\s*\(/g, rationale: "Trace whether untrusted data can reach dynamic evaluation." },
      { id: "JS_WEAK_RANDOM", title: "Potentially non-cryptographic randomness", regex: /\bMath\.random\s*\(/g, rationale: "Check whether the value is used for a security-sensitive token or secret." },
      { id: "NODE_PROCESS_EXEC", title: "Process execution API", regex: /\b(exec|execSync|spawn|spawnSync)\s*\(/g, rationale: "Review trust boundaries, argument construction and shell options." },
      { id: "SQL_DYNAMIC", title: "Potential dynamic SQL construction", regex: /(?:query|execute)\s*\(\s*(?:`[^\n]*\$\{|['"][^'"]*\s\+)/gi, rationale: "Verify the database API and whether values are parameterized." },
      { id: "TLS_VERIFY_DISABLED", title: "TLS verification disabled", regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=['"]?0/g, rationale: "Check whether this setting is active outside isolated tests." },
      { id: "HTML_UNSAFE_SINK", title: "Potential unsafe HTML sink", regex: /\.innerHTML\s*=|dangerouslySetInnerHTML\s*=/g, rationale: "Trace whether untrusted content reaches the HTML sink and whether it is safely encoded." }
    ];
    const lines = source.split("\n");
    const candidates: Array<Record<string, unknown>> = [];
    for (const rule of rules) {
      rule.regex.lastIndex = 0;
      for (const match of source.matchAll(rule.regex)) {
        const line = source.slice(0, match.index ?? 0).split("\n").length;
        candidates.push({
          fingerprint: `${rule.id}:${filename ?? "unknown"}:${line}`,
          rule_id: rule.id,
          title: rule.title,
          file: filename ?? null,
          line,
          evidence: redactEvidence(lines[line - 1] ?? ""),
          rationale: rule.rationale,
          verdict: "needs_validation"
        });
        if (candidates.length >= 100) break;
      }
      if (candidates.length >= 100) break;
    }
    return result({
      phase: 3,
      review_type: "heuristic_candidate_generation",
      candidate_count: candidates.length,
      candidates,
      limitations: [
        "Pattern matches are leads, not proof of vulnerabilities.",
        "No severity is assigned.",
        "No code is executed and no deployed endpoint is contacted.",
        "A human or separate reviewer must validate source context and trust-boundary impact."
      ]
    });
  });

  server.registerTool("cloudflare_coverage_ledger_validate", {
    description: "Validate a canonical coverage-ledger.json document with Cloudflare Security Audit Skill's upstream validator.",
    inputSchema: z.object({
      ledger: z.array(z.unknown()).max(10_000)
    })
  }, async ({ ledger }) => result({
    upstream: "cloudflare/security-audit-skill",
    upstream_validator: "validate-coverage-ledger.cjs",
    phase: 1,
    ...validateCloudflareCoverageLedger(ledger)
  }));

  server.registerTool("cloudflare_findings_validate", {
    description: "Validate findings.json against Cloudflare Security Audit Skill's upstream report-schema.json and semantic checks.",
    inputSchema: z.object({
      findings: z.array(z.unknown()).max(1000)
    })
  }, async ({ findings }) => result({
    upstream: "cloudflare/security-audit-skill",
    upstream_validator: "validate-findings.cjs",
    phase: 4,
    ...validateCloudflareFindings(findings)
  }));

  server.registerTool("audit_coverage_validate", {
    description: "Phase 2: validate that every in-scope path has exactly one coverage-ledger entry.",
    inputSchema: z.object({
      scope_paths: z.array(z.string().min(1)).max(5000),
      ledger: z.array(CoverageEntrySchema).max(5000)
    })
  }, async ({ scope_paths, ledger }) => result({
    phase: 2,
    ...validateCoverage(scope_paths, ledger)
  }));

  server.registerTool("audit_findings_validate", {
    description: "Phase 4: validate finding structure, evidence fields and unique fingerprints. Needs-validation records cannot carry severity.",
    inputSchema: z.object({
      findings: z.array(z.unknown()).max(1000)
    })
  }, async ({ findings }) => {
    const checked = validateFindings(findings);
    return result({
      phase: 4,
      valid: checked.valid,
      errors: checked.errors,
      findings_count: checked.findings.length
    });
  });

  server.registerTool("audit_independent_verify", {
    description: "Phase 5: compare findings against separately supplied reviewer checks. This tool does not spawn reviewers or claim independence by itself.",
    inputSchema: z.object({
      findings: z.array(FindingSchema).max(1000),
      checks: z.array(z.strictObject({
        fingerprint: z.string().min(1),
        agrees: z.boolean(),
        evidence_matches: z.boolean(),
        rationale: z.string().min(1).max(3000)
      })).max(1000)
    })
  }, async ({ findings, checks }) => {
    const findingsValidation = validateFindings(findings);
    const verification = findingsValidation.valid
      ? verifyIndependentReview(findings, checks)
      : { passed: false, missing_reviews: [], disagreements: [], duplicate_review_records: [], duplicate_finding_records: [], unknown_review_records: [] };
    return result({
      phase: 5,
      findings_validation: { valid: findingsValidation.valid, errors: findingsValidation.errors },
      ...verification
    });
  });

  server.registerTool("audit_report_generate", {
    description: "Phase 6: validate coverage and separate reviewer checks, then generate target-neutral Markdown reports.",
    inputSchema: z.object({
      repository: z.string().min(1).max(300),
      scope: z.string().min(1).max(2000),
      inventory_complete: z.boolean(),
      scope_paths: z.array(z.string().min(1)).min(1).max(5000),
      coverage_ledger: z.array(CoverageEntrySchema).max(5000),
      findings: z.array(FindingSchema).max(1000),
      independent_checks: z.array(z.strictObject({
        fingerprint: z.string().min(1),
        agrees: z.boolean(),
        evidence_matches: z.boolean(),
        rationale: z.string().min(1).max(3000)
      })).max(1000),
      requested_status: z.enum(["complete", "incomplete"])
    })
  }, async ({ repository, scope, inventory_complete, scope_paths, coverage_ledger, findings, independent_checks, requested_status }) => {
    const coverage = validateCoverage(scope_paths, coverage_ledger);
    const findingsValidation = validateFindings(findings);
    const verification = findingsValidation.valid
      ? verifyIndependentReview(findings, independent_checks)
      : { passed: false, missing_reviews: [], disagreements: [], duplicate_review_records: [], duplicate_finding_records: [], unknown_review_records: [] };
    const coverageGate = coverage.valid && inventory_complete;
    return result({
      ...generateReport(repository, scope, findings, coverageGate, findingsValidation.valid && verification.passed, requested_status),
      gates: {
        inventory_complete,
        coverage,
        findings: { valid: findingsValidation.valid, errors: findingsValidation.errors },
        independent_verification: verification
      }
    });
  });

  return server;
}


#!/usr/bin/env node
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
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";
import {
  CoverageEntrySchema,
  FindingSchema,
  validateCoverage,
  validateFindings,
  verifyIndependentReview
} from "./audit/contracts.js";

const API_ROOT = "https://api.github.com";
const MAX_FILE_BYTES = 300_000;
const MAX_TREE_ITEMS = 500;
const MAX_SOURCE_CHARS = 100_000;
const token = process.env.GITHUB_TOKEN;

type RepoRef = { owner: string; repo: string; ref?: string };

function parseRepo(input: string, ref?: string): RepoRef {
  const raw = input.trim();
  let parts: string[];

  if (/^https?:\/\//i.test(raw)) {
    const url = new URL(raw);
    if (url.protocol !== "https:" || !["github.com", "www.github.com"].includes(url.hostname.toLowerCase())) {
      throw new Error("Only https://github.com repository URLs are accepted.");
    }
    if (url.search || url.hash) throw new Error("Repository URLs must not include query strings or fragments.");
    parts = url.pathname.split("/").filter(Boolean);
    if (parts.at(-1)?.endsWith(".git")) parts[parts.length - 1] = parts.at(-1)!.slice(0, -4);
  } else {
    parts = raw.replace(/\.git$/, "").split("/").filter(Boolean);
  }

  if (parts.length !== 2 || !/^[A-Za-z0-9_.-]+$/.test(parts[0] ?? "") || !/^[A-Za-z0-9_.-]+$/.test(parts[1] ?? "")) {
    throw new Error("Repository must be owner/name or a GitHub repository URL.");
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
    const detail = await response.text().catch(() => "");
    throw new Error(`GitHub API returned ${response.status}: ${detail.slice(0, 300)}`);
  }
  return response.json();
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
  const entries: Array<{ path: string; type: string; size: number | null }> = (tree.tree ?? []).slice(0, MAX_TREE_ITEMS).map((item: { path: string; type: string; size?: number | null }) => ({
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
  if (/(^|\/)(dist|build|coverage|vendor)(\/|$)/i.test(path)) return "generated";
  if (/(^|\/)(test|tests|__tests__|spec)(\/|$)|\.(test|spec)\.[^.]+$/i.test(path)) return "test";
  if (/\.(md|mdx|rst|txt)$/i.test(path)) return "documentation";
  if (/(package-lock|pnpm-lock|yarn\.lock|Cargo\.lock|go\.sum|requirements.*\.txt)/i.test(path)) return "dependency";
  if (/\.(json|ya?ml|toml|ini|conf|config)$/i.test(path) || /(^|\/)(\.github|\.npmrc|\.nvmrc)(\/|$)/i.test(path)) return "configuration";
  if (/\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|kt|php|rb|cs|swift|c|cc|cpp|h|hpp|sql)$/i.test(path)) return "application";
  return "unknown";
}

function redactEvidence(line: string): string {
  return line
    .replace(/((?:api[_-]?key|secret|password|token)\s*[:=]\s*)(['"])[^'"]+\2/gi, "$1$2[REDACTED]$2")
    .slice(0, 220);
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
    `- Repository: ${repository}`,
    `- Scope: ${scope}`,
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
    confirmed.length ? confirmed.map(item => `- **${item.title}** (${item.severity}, ${item.confidence}) — ${item.description}`).join("\n") : "No confirmed findings recorded.",
    "",
    "## Needs validation",
    pending.length ? pending.map(item => `- **${item.title}** — ${item.description} Blockers: ${item.blockers.join("; ")}`).join("\n") : "No pending candidates.",
    "",
    "## Rejected candidates",
    rejected.length ? rejected.map(item => `- **${item.title}** — ${item.rejection_reason}`).join("\n") : "No rejected candidates.",
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
      `## ${item.title}`,
      `- Verdict: ${item.verdict}`,
      `- Fingerprint: ${item.fingerprint}`,
      `- Description: ${item.description}`,
      ...item.evidence.map(ev => `- Evidence: ${ev.file}:${ev.line} — ${ev.description}`),
      ...item.trace.map(step => `- Trace (${step.kind}): ${step.file}:${step.line} — ${step.description}`),
      item.verdict === "confirmed" ? `- Root cause: ${item.root_cause}` : `- Claimed root cause: ${item.claimed_root_cause}`,
      item.verdict === "confirmed" ? `- Affected boundary: ${item.affected_boundary}` : "",
      item.verdict === "confirmed" ? `- Impact: ${item.impact}` : "",
      item.verdict === "confirmed" ? `- Severity: ${item.severity}; confidence: ${item.confidence}` : "",
      item.verdict === "confirmed" ? `- Remediation: ${item.remediation}` : "",
      item.verdict === "rejected" ? `- Rejection reason: ${item.rejection_reason}` : "",
      item.verdict === "needs_validation" ? `- Blockers: ${item.blockers.join("; ")}` : "",
      ""
    ].filter(Boolean).join("\n"))
  ].join("\n");

  const needsValidation = [
    "# Needs Validation",
    "",
    ...pending.map(item => `## ${item.title}\n\n${item.description}\n\nBlockers:\n${item.blockers.map(b => `- ${b}`).join("\n")}\n\nValidation plan: ${item.validation_plan}\n`)
  ].join("\n");

  return {
    run_status: status,
    "findings.json": JSON.stringify(findings, null, 2),
    "REPORT.md": report,
    "FINDINGS-DETAIL.md": detail,
    "NEEDS-VALIDATION.md": needsValidation
  };
}

function createServer(): McpServer {
  const server = new McpServer({
    name: "security-audit-mcp-ver",
    version: "0.2.0"
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
      if (path.startsWith("/") || path.split("/").some(part => part === ".." || part === "")) {
        throw new Error("Absolute paths, empty path segments and parent-directory segments are not allowed.");
      }
      const parsed = parseRepo(repository, ref);
      const suffix = parsed.ref ? `?ref=${encodeURIComponent(parsed.ref)}` : "";
      const apiPath = path.split("/").map(encodeURIComponent).join("/");
      const data = await github(`/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/contents/${apiPath}${suffix}`);
      if (Array.isArray(data) || data.type !== "file") throw new Error("The requested path is not a single file.");
      if ((data.size ?? 0) > MAX_FILE_BYTES) throw new Error("File exceeds the 300 KB read limit.");
      if (data.encoding !== "base64" || typeof data.content !== "string") throw new Error("GitHub did not return a supported text file.");
      const content = Buffer.from(data.content.replace(/\n/g, ""), "base64").toString("utf8");
      if (content.includes("\u0000")) throw new Error("Binary-looking content is not supported.");
      return result({ repository: `${parsed.owner}/${parsed.repo}`, path, size_bytes: data.size, content });
    } catch (error) { return failure(error); }
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
  }, async ({ findings, checks }) => result({
    phase: 5,
    ...verifyIndependentReview(findings, checks)
  }));

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
    const verification = verifyIndependentReview(findings, independent_checks);
    const coverageGate = coverage.valid && inventory_complete;
    return result({
      ...generateReport(repository, scope, findings, coverageGate, verification.passed, requested_status),
      gates: { inventory_complete, coverage, independent_verification: verification }
    });
  });

  return server;
}

await serveStdio(createServer);

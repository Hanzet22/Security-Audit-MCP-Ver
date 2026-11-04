#!/usr/bin/env node
/**
 * Security-Audit-MCP-Ver
 * Copyright (C) 2026 Hanzet22
 * Licensed under GNU AGPL v3.0 or later. See LICENSE.
 *
 * This initial server performs read-only source inspection. It does not
 * execute repository code, probe deployed systems, or attempt exploitation.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const API_ROOT = "https://api.github.com";
const MAX_FILE_BYTES = 300_000;
const MAX_TREE_ITEMS = 500;
const token = process.env.GITHUB_TOKEN;

const server = new McpServer({
  name: "security-audit-mcp-ver",
  version: "0.1.0"
});

type RepoRef = { owner: string; repo: string; ref?: string };

function parseRepo(input: string, ref?: string): RepoRef {
  const cleaned = input.trim().replace(/^https?:\/\/(www\.)?github\.com\//, "").replace(/\.git$/, "");
  const parts = cleaned.split("/");
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
  const response = await fetch(`${API_ROOT}${path}`, { headers, signal: AbortSignal.timeout(15_000) });
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(`GitHub API returned ${response.status}: ${detail.slice(0, 300)}`);
  }
  return response.json();
}

function jsonResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

server.tool(
  "repository_inspect",
  "Read GitHub repository metadata and its default branch. This is a read-only operation.",
  { repository: z.string().describe("GitHub owner/name or repository URL") },
  async ({ repository }) => {
    try {
      const ref = parseRepo(repository);
      const data = await github(`/repos/${encodeURIComponent(ref.owner)}/${encodeURIComponent(ref.repo)}`);
      return jsonResult({
        repository: data.full_name,
        description: data.description,
        visibility: data.visibility,
        default_branch: data.default_branch,
        archived: data.archived,
        license: data.license?.spdx_id ?? null,
        html_url: data.html_url,
        security_note: "Metadata only; no code was executed or tested."
      });
    } catch (error) {
      return jsonResult({ error: error instanceof Error ? error.message : String(error) });
    }
  }
);

server.tool(
  "repository_tree",
  "List repository paths from GitHub's Git tree API. Read-only; output is capped at 500 entries.",
  {
    repository: z.string(),
    ref: z.string().optional().describe("Branch, tag, or commit; defaults to the repository default branch")
  },
  async ({ repository, ref }) => {
    try {
      const parsed = parseRepo(repository, ref);
      const repoData = await github(`/repos/${parsed.owner}/${parsed.repo}`);
      const branch = parsed.ref ?? repoData.default_branch;
      const tree = await github(`/repos/${parsed.owner}/${parsed.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
      const entries = (tree.tree ?? []).slice(0, MAX_TREE_ITEMS).map((item: any) => ({
        path: item.path,
        type: item.type,
        size: item.size ?? null
      }));
      return jsonResult({
        repository: repoData.full_name,
        ref: branch,
        truncated: Boolean(tree.truncated) || (tree.tree?.length ?? 0) > MAX_TREE_ITEMS,
        returned_entries: entries.length,
        entries
      });
    } catch (error) {
      return jsonResult({ error: error instanceof Error ? error.message : String(error) });
    }
  }
);

server.tool(
  "repository_read_file",
  "Read a text file from a GitHub repository. Files larger than 300 KB are refused. No code is executed.",
  {
    repository: z.string(),
    path: z.string().min(1),
    ref: z.string().optional()
  },
  async ({ repository, path, ref }) => {
    try {
      if (path.startsWith("/") || path.split("/").some(part => part === "..")) {
        throw new Error("Absolute paths and parent-directory segments are not allowed.");
      }
      const parsed = parseRepo(repository, ref);
      const suffix = parsed.ref ? `?ref=${encodeURIComponent(parsed.ref)}` : "";
      const data = await github(`/repos/${parsed.owner}/${parsed.repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}${suffix}`);
      if (Array.isArray(data) || data.type !== "file") throw new Error("The requested path is not a single file.");
      if ((data.size ?? 0) > MAX_FILE_BYTES) throw new Error("File exceeds the 300 KB read limit.");
      if (data.encoding !== "base64" || typeof data.content !== "string") throw new Error("GitHub did not return a supported text file.");
      const content = Buffer.from(data.content.replace(/\n/g, ""), "base64").toString("utf8");
      if (content.includes("\u0000")) throw new Error("Binary-looking content is not supported.");
      return jsonResult({
        repository: `${parsed.owner}/${parsed.repo}`,
        path,
        size_bytes: data.size,
        content
      });
    } catch (error) {
      return jsonResult({ error: error instanceof Error ? error.message : String(error) });
    }
  }
);

server.tool(
  "source_security_review",
  "Run a lightweight heuristic review on source text supplied by the caller. Reports leads only; it cannot confirm exploitability and does not execute code.",
  {
    source: z.string().min(1).max(100_000).describe("Source code text, up to 100 KB"),
    filename: z.string().optional().describe("Optional filename for context")
  },
  async ({ source, filename }) => {
    const rules: Array<{ id: string; label: string; regex: RegExp; rationale: string }> = [
      { id: "JS_EVAL", label: "Dynamic code evaluation", regex: /\beval\s*\(|new\s+Function\s*\(/g, rationale: "Dynamic evaluation can turn untrusted input into executable code. Trace the data flow and intended use." },
      { id: "JS_INSECURE_RANDOM", label: "Potentially non-cryptographic randomness", regex: /\bMath\.random\s*\(/g, rationale: "Math.random is not suitable for security-sensitive tokens or secrets." },
      { id: "NODE_CHILD_PROCESS", label: "Process execution API", regex: /\b(exec|execSync|spawn|spawnSync)\s*\(/g, rationale: "Review whether arguments contain untrusted input and whether shell execution is enabled." },
      { id: "SQL_DYNAMIC", label: "Potentially dynamic SQL construction", regex: /(?:query|execute)\s*\(\s*(?:`[^\n]*\$\{|['"][^'"]*\s\+|\w+\s*\+)/gi, rationale: "Prefer parameterized queries; verify the query API and data flow before classifying." },
      { id: "SECRET_LITERAL", label: "Possible hard-coded credential", regex: /(?:api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"]{8,}['"]/gi, rationale: "Could be a placeholder or test value. Verify against repository context; do not publish discovered secrets." },
      { id: "TLS_VERIFY_DISABLED", label: "TLS certificate verification disabled", regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=['"]?0/g, rationale: "Disabling certificate verification weakens TLS protection." }
    ];
    const findings: Array<{ rule_id: string; title: string; line: number; evidence: string; rationale: string; status: string }> = [];
    for (const rule of rules) {
      rule.regex.lastIndex = 0;
      for (const match of source.matchAll(rule.regex)) {
        const index = match.index ?? 0;
        const line = source.slice(0, index).split("\n").length;
        const lineText = source.split("\n")[line - 1]?.trim().slice(0, 220) ?? "";
        findings.push({
          rule_id: rule.id,
          title: rule.label,
          line,
          evidence: lineText,
          rationale: rule.rationale,
          status: "needs_validation"
        });
        if (findings.length >= 100) break;
      }
      if (findings.length >= 100) break;
    }
    return jsonResult({
      filename: filename ?? null,
      review_type: "heuristic_source_review",
      findings_count: findings.length,
      findings,
      limitations: [
        "Pattern matches are leads, not confirmed vulnerabilities.",
        "No severity is assigned by this heuristic reviewer.",
        "No repository code is executed and no live endpoint is contacted.",
        "Manual context review and independent validation are required."
      ]
    });
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);

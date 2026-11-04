# Security-Audit-MCP-Ver

Read-only, evidence-led source-code security audit tools exposed through the Model Context Protocol (MCP).

This is an independent implementation inspired by the workflow in [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill). It is not affiliated with or endorsed by Cloudflare.

## Current status

**v0.3.0 — release preparation; no formal GitHub Release has been published.**

The server currently exposes **18 MCP tools**:

| Tool | Workflow phase | Purpose |
|---|---:|---|
| `repository_inspect` | Recon | Read GitHub repository metadata |
| `repository_tree` | Recon | List bounded repository paths |
| `repository_read_file` | Recon | Read one bounded text file |
| `cloudflare_reconnaissance_prepare` | 1 | Build run metadata, architecture summary, and canonical coverage ledger from four caller-supplied scout reports |
| `cloudflare_hunting_wave_prepare` | 2 | Validate, rank, assign, and explicitly defer canonical coverage units for a bounded hunting wave |
| `cloudflare_hunter_results_consolidate` | 2 | Validate ownership and structured hunter results, then consolidate only assigned ledger units |
| `cloudflare_coverage_critic` | 2.5 | Validate a caller-supplied full-ledger critic review and gate the next wave |
| `worker_task_contract_validate` | 2.5 | Validate worker task identity, role, source ref, scope, and constraints |
| `worker_result_contract_validate` | 2.5 | Validate worker result identity, path ownership, evidence-reference shape, and blockers |
| `worker_orchestrator_step` | 2.5 | Advance the stateless parent-side workflow through result, critic, verification, and next-wave gates |
| `audit_reconnaissance` | 1 | Inventory and classify repository files |
| `source_security_review` | 3 | Generate heuristic candidate leads |
| `cloudflare_coverage_ledger_validate` | 1–2 | Validate canonical coverage ledgers with Cloudflare's upstream validator |
| `cloudflare_findings_validate` | 4–5 | Validate findings against Cloudflare's upstream report schema and semantic rules |
| `audit_coverage_validate` | 2 | Validate that every in-scope path has exactly one coverage-ledger entry |
| `audit_findings_validate` | 4 | Validate finding structure, evidence fields, and unique fingerprints |
| `audit_independent_verify` | 5 | Compare findings with separately supplied reviewer checks |
| `audit_report_generate` | 6 | Validate final gates and generate JSON/Markdown reports |

The Phase 1 adapter follows the upstream reconnaissance contract: four distinct scout-report categories, a pre-recon budget gate, architecture summary, scope-aware canonical coverage units, and explicit prior-run limitations. Phase 2 adds deterministic priority ranking, bounded assignments, explicit deferred states, structured result consolidation, ownership checks, and parent-confirmed artifact promotion checks. Neither phase spawns agents; scout and hunter results are caller-supplied. The `cloudflare_*_validate` tools run upstream validators and schema preserved under `vendor/cloudflare-security-audit-skill/`. Upstream methodology, companion guidance, validator tests, and notices are also preserved there under MIT.

The workflow is intentionally explicit: reconnaissance inventory is not a completed review; heuristic matches are not confirmed vulnerabilities; a separate reviewer must provide verification checks; and incomplete coverage or verification keeps the run marked incomplete.

## Requirements

- Node.js 22 or newer; production deployments should use a currently supported LTS release (currently 22, 24, or 26).
- An MCP-compatible host
- Optional GitHub fine-grained token for higher API limits or private repositories

## Install and build

```bash
npm ci
npm run typecheck
npm test
npm run build
npm start
```

`npm test` runs the unit, integration, upstream-validator, and fast-check property tests. Use `npm install` when intentionally changing dependencies; review and commit the resulting lockfile.

For local development:

```bash
npm run dev
```

The production stdio entry point is `dist/stdio.js`. The exported `createServer()` factory in `src/index.ts` is also used by the in-process MCP integration smoke test; importing it does not start a stdio process.

> Dependency installation is locked by the committed npm-generated `package-lock.json`; CI uses `npm ci`. Regenerate and review the lockfile whenever dependency manifests change.

## MCP host configuration

Example for a host that launches a local Node process:

```json
{
  "mcpServers": {
    "security-audit-mcp-ver": {
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"],
      "env": {
        "GITHUB_TOKEN": "OPTIONAL_READ_ONLY_TOKEN"
      }
    }
  }
}
```

Use a fine-grained GitHub token with read-only repository Contents and Metadata permissions. Do not use a token with write permissions for this read-only server.

## Safety model

- GitHub access uses read APIs only.
- The server never clones or executes target repository code.
- No deployed endpoint, production service, or third-party infrastructure is probed.
- Repository URL parsing accepts GitHub HTTPS URLs only.
- Repository URL parsing rejects embedded credentials and non-standard ports; GitHub API responses are content-type checked and capped at 5 MB, with bounded timeouts and sanitized error messages.
- Source pattern matches are candidate leads, not proof of exploitability.
- Potential credential evidence is redacted before candidate output.
- Only confirmed records may contain severity; `needs_validation` records cannot.
- The server does not spawn independent sub-agents. The upstream validation tools validate record structure and semantics; they do not independently re-read repository source or establish a vulnerability by themselves. Phase 5 requires separately supplied reviewer checks.
- Reports are marked `incomplete` unless coverage and independent-verification gates pass.
- Do not submit secrets or private source code unless you are authorized to share them.

A future sandboxed runner would require OS-enforced isolation, no external network access, restricted environment variables, resource limits, and scratch-only writes. This project does not implement such a runner.


## Runtime behavior and limits

### Transport

The current server supports **local stdio transport only** through `src/stdio.ts`.
It does not expose an HTTP endpoint, remote MCP URL, OAuth flow, or hosted service.
A compatible host must launch the local Node.js process. Remote transport and
deployment are separate future work and are not implied by this repository's
current capabilities.

### GitHub access

- Public repositories can be read without a token, subject to GitHub's unauthenticated API rate limits.
- Set `GITHUB_TOKEN` in the host process environment when access to private repositories or a higher API rate limit is required.
- Use a fine-grained token restricted to the repositories needed, with **Contents: read-only** and **Metadata: read-only** permissions.
- The token is used only for GitHub API requests. Do not paste it into tool arguments, source files, issue reports, or committed configuration.
- The server does not write to GitHub. A read-only token is recommended as defense in depth.

### Resource bounds

The GitHub API boundary applies the following fixed limits:

| Resource | Limit |
|---|---:|
| GitHub API request timeout | 15 seconds |
| GitHub API response body | 5 MB |
| Repository tree entries returned | 500 |
| Individual file content | 300 KB |
| Source text processed by review tools | 100,000 characters |

A truncated repository tree is reported as truncated; it must not be treated as a complete inventory.
Files or responses beyond the configured limits are rejected rather than silently treated as fully reviewed.

### Evidence and trust boundaries

Tool output is evidence for a human-led review, not a certification or proof that a repository is secure.
Repository refs, line ranges, scout reports, worker results, critic reviews, and orchestration
state are supplied by callers and are not cryptographically attested by this server.
A passing workflow gate means that the supplied records satisfy the implemented consistency
checks; it does not prove that a separate person or agent performed the claimed work.
Always verify important evidence against the referenced source revision before making a decision.

## Workflow model

1. **Reconnaissance:** use `cloudflare_reconnaissance_prepare` with four source-cited scout reports and coverage-unit candidates; it emits `run-metadata.json`, `architecture.md`, and a canonical `coverage-ledger.json` validated by Cloudflare's upstream validator. It does not spawn agents.
2. **Coverage-led hunting:** prepare a bounded wave with `cloudflare_hunting_wave_prepare`; return one structured result per assigned coverage ID; consolidate with `cloudflare_hunter_results_consolidate`; then run a fresh source-reading coverage critic before another wave. The planner does not spawn hunters. Local checks are accepted only when the parent explicitly supplies paths already promoted through a trusted sandbox procedure.
3. **Candidate generation:** inspect source and produce heuristic leads with file/line evidence.
4. **Structured findings:** validate records, verdicts, evidence and unique fingerprints.
5. **Independent verification:** compare findings against a separate reviewer’s checks.
6. **Reporting:** generate `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`; disclose incomplete runs.

The current implementation provides workflow primitives, not an autonomous six-phase audit agent. It does not claim that a complete audit has occurred merely because tools were called.

## Security

See [SECURITY.md](./SECURITY.md) for supported versions, reporting guidance, and project scope.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for the development history and release status.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](./LICENSE).

Upstream inspiration and attribution details: [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

## Parent-side critic and worker orchestration

The MCP exposes `cloudflare_coverage_critic`, `worker_task_contract_validate`,
`worker_result_contract_validate`, and `worker_orchestrator_step`.

These tools validate caller-supplied review and worker records and enforce the
sequence: assigned work → complete worker results → full-ledger critic →
independent verification → next-wave gate. Orchestration state is caller-held,
unsigned JSON and can be altered or replayed; the gates check workflow
consistency, not authorization or proof of independent work. They are stateless
workflow controls, not an autonomous agent runtime: this server does not spawn workers,
create background jobs, persist queues, or independently authenticate evidence.
A host application or external orchestrator must execute workers and supply
their structured results. Source inspection remains read-only; target code is
not executed and deployed endpoints are not probed.

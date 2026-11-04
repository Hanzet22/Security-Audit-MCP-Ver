# Security-Audit-MCP-Ver

Read-only, evidence-led source-code security audit tools exposed through the Model Context Protocol (MCP).

This is an independent implementation inspired by the workflow in [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill). It is not affiliated with or endorsed by Cloudflare.

## Current status

**v0.3.0-dev — MCP SDK v2, structured workflow primitives, and upstream Cloudflare validators.**

The server currently exposes:

| Tool | Workflow phase | Purpose |
|---|---:|---|
| `repository_inspect` | Recon | Read GitHub repository metadata |
| `repository_tree` | Recon | List bounded repository paths |
| `repository_read_file` | Recon | Read one bounded text file |
| `audit_reconnaissance` | 1 | Inventory and classify repository files |
| `source_security_review` | 3 | Generate heuristic candidate leads |
| `audit_coverage_validate` | 2 | Validate the coverage ledger |
| `audit_findings_validate` | 4 | Validate structured finding records |
| `audit_independent_verify` | 5 | Compare findings with separately supplied reviewer checks |
| `audit_report_generate` | 6 | Validate final gates and generate JSON/Markdown reports |
| `cloudflare_reconnaissance_prepare` | 1 | Build run metadata, architecture summary, and canonical coverage ledger from four caller-supplied scout reports |\n| `cloudflare_coverage_ledger_validate` | 1–2 | Validate canonical coverage ledgers with Cloudflare's upstream validator |
| `cloudflare_findings_validate` | 4–5 | Validate findings against Cloudflare's upstream report schema and semantic rules |

The Phase 1 adapter follows the upstream reconnaissance contract: four distinct scout-report categories, a pre-recon budget gate, architecture summary, scope-aware canonical coverage units, and explicit prior-run limitations. It does not spawn agents; reports are caller-supplied. The `cloudflare_*_validate` tools run upstream validators and schema preserved under `vendor/cloudflare-security-audit-skill/`. Upstream methodology, companion guidance, validator tests, and notices are also preserved there under MIT.

The workflow is intentionally explicit: reconnaissance inventory is not a completed review; heuristic matches are not confirmed vulnerabilities; a separate reviewer must provide verification checks; and incomplete coverage or verification keeps the run marked incomplete.

## Requirements

- Node.js 20.11 or newer
- An MCP-compatible host
- Optional GitHub fine-grained token for higher API limits or private repositories

## Install and build

```bash
npm install
npm run typecheck
npm test
npm run build
npm start
```

For local development:

```bash
npm run dev
```

## MCP host configuration

Example for a host that launches a local Node process:

```json
{
  "mcpServers": {
    "security-audit-mcp-ver": {
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/index.js"],
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
- Source pattern matches are candidate leads, not proof of exploitability.
- Potential credential evidence is redacted before candidate output.
- Only confirmed records may contain severity; `needs_validation` records cannot.
- The server does not spawn independent sub-agents. The upstream validation tools validate record structure and semantics; they do not independently re-read repository source or establish a vulnerability by themselves. Phase 5 requires separately supplied reviewer checks.
- Reports are marked `incomplete` unless coverage and independent-verification gates pass.
- Do not submit secrets or private source code unless you are authorized to share them.

A future sandboxed runner would require OS-enforced isolation, no external network access, restricted environment variables, resource limits, and scratch-only writes. This project does not implement such a runner.

## Workflow model

1. **Reconnaissance:** use `cloudflare_reconnaissance_prepare` with four source-cited scout reports and coverage-unit candidates; it emits `run-metadata.json`, `architecture.md`, and a canonical `coverage-ledger.json` validated by Cloudflare's upstream validator. It does not spawn agents.
2. **Coverage planning:** create and validate one ledger entry for every in-scope path.
3. **Candidate generation:** inspect source and produce heuristic leads with file/line evidence.
4. **Structured findings:** validate records, verdicts, evidence and unique fingerprints.
5. **Independent verification:** compare findings against a separate reviewer’s checks.
6. **Reporting:** generate `findings.json`, `REPORT.md`, `FINDINGS-DETAIL.md`, and `NEEDS-VALIDATION.md`; disclose incomplete runs.

The current implementation provides workflow primitives, not an autonomous six-phase audit agent. It does not claim that a complete audit has occurred merely because tools were called.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](./LICENSE).

Upstream inspiration and attribution details: [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

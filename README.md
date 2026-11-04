# Security-Audit-MCP-Ver

Read-only source-code security review tools exposed through the Model Context Protocol (MCP).

This is an independent implementation inspired by the workflow in [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill). It is not affiliated with or endorsed by Cloudflare.

## Current status

**Early scaffold (v0.1.0).** The server currently provides:

- `repository_inspect` — read repository metadata.
- `repository_tree` — list repository paths.
- `repository_read_file` — read a bounded text file.
- `source_security_review` — run basic heuristic checks against source text supplied by the caller.

The heuristic reviewer emits `needs_validation` leads only. It does not confirm vulnerabilities, assign severity, execute code, or contact deployed application endpoints.

## Requirements

- Node.js 20.11 or newer
- An MCP-compatible host
- Optional GitHub fine-grained token for higher API limits or private repositories

## Install and build

```bash
npm install
npm run build
npm start
```

For local development:

```bash
npm run dev
```

## MCP host configuration

Example for an MCP host that launches a local Node process:

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

Use a fine-grained GitHub token with read-only repository Contents and Metadata permissions. Do not use a personal access token with write permissions for this read-only server.

## Safety model

- Repository operations use GitHub's read APIs only.
- The server never clones or executes target repository code.
- No deployed endpoint, production service, or third-party infrastructure is probed.
- Source pattern matches are heuristic leads, not proof of a vulnerability.
- Findings remain `needs_validation` until independently validated with sufficient source context.
- Do not submit secrets or private source code unless you are authorized to share them.

A future sandboxed audit runner would require operating-system-enforced isolation, no external network access, restricted environment variables, resource limits, and scratch-only writes. This initial MCP server does not implement that runner.

## Development roadmap

1. Repository reconnaissance and bounded source retrieval.
2. Coverage ledger and explicit review scope.
3. Heuristic candidate generation with source locations.
4. Independent validation workflow and structured finding schema.
5. Evidence consistency checks.
6. Target-neutral Markdown and JSON reports.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](./LICENSE).

Upstream inspiration and attribution details: [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

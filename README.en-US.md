# Security-Audit-MCP-Ver

[English (EU)](./README.md) · [English (US)](./README.en-US.md) · [Bahasa Indonesia](./README.id.md) · [Malay (Singapore)](./README.ms-SG.md)

Read-only, evidence-led source-code security audit tools exposed through the Model Context Protocol (MCP).

Independent implementation inspired by the workflow in [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill). This project is not affiliated with or endorsed by Cloudflare. Cloudflare's upstream material remains under its original MIT license; this project's own code is licensed under AGPL-3.0-or-later. See [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

## Status

**Version 0.3.0 release publication status: pending.** The release tag and formal GitHub Release must exist before this version is described as published. See [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md).

The server exposes 18 MCP tools covering repository reconnaissance, coverage planning, source review, findings validation, independent verification, orchestration contracts and report generation. It provides workflow primitives, not an autonomous audit agent.

## Requirements

- Node.js 22 or newer (use a supported LTS release).
- An MCP-compatible client.
- Optional fine-grained GitHub token for private repositories or higher API limits. Grant only **Contents: read-only** and **Metadata: read-only**.

## Install from source

```bash
git clone https://github.com/Hanzet22/Security-Audit-MCP-Ver.git
cd Security-Audit-MCP-Ver
npm ci
npm run build
```

To run the complete local validation suite:

```bash
npm run typecheck
npm test
npm run build
```

The production STDIO entry point is `dist/stdio.js`. The server currently supports **local STDIO only**; it does not provide an HTTP endpoint, remote MCP URL, OAuth flow or hosted service.

## Configure an MCP client

Replace `/absolute/path/to/Security-Audit-MCP-Ver` with the actual path to the cloned repository. Build the project before connecting a client.

### Claude Code

Add a user-level server:

```bash
claude mcp add --transport stdio --scope user security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
claude mcp list
```

Run `/mcp` inside Claude Code to inspect the connection. For project-only configuration, use `--scope project` instead of `--scope user`.

### OpenAI Codex CLI

```bash
codex mcp add security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
codex mcp list
```

Codex stores the entry in `~/.codex/config.toml`. You can also configure it there:

```toml
[mcp_servers.security-audit-mcp-ver]
command = "node"
args = ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
```

### Cursor

Create `.cursor/mcp.json` in your project, or use the global Cursor MCP configuration:

```json
{
  "mcpServers": {
    "security-audit-mcp-ver": {
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
    }
  }
}
```

### Visual Studio Code

For clients that use the VS Code MCP configuration format, create `.vscode/mcp.json`:

```json
{
  "servers": {
    "security-audit-mcp-ver": {
      "type": "stdio",
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
    }
  }
}
```

Client configuration formats can differ. Consult the client's current MCP documentation if its schema changes.

## Optional GitHub token

Public repositories can be read without a token, subject to GitHub's unauthenticated API rate limits. If required, set `GITHUB_TOKEN` in the MCP client's server environment. Use a fine-grained token limited to the repositories needed, with **Contents: read-only** and **Metadata: read-only** permissions. Never commit tokens or paste them into tool arguments.

Example for a client configuration that supports environment variables:

```json
{
  "mcpServers": {
    "security-audit-mcp-ver": {
      "command": "node",
      "args": ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"],
      "env": {
        "GITHUB_TOKEN": "YOUR_READ_ONLY_TOKEN"
      }
    }
  }
}
```

Prefer your operating system's secret manager or the client's secure environment-variable mechanism over storing a token in a shared project file.

## What the server does

- Reads GitHub repository metadata, bounded trees and text files.
- Prepares reconnaissance reports and canonical coverage ledgers.
- Plans bounded hunting waves and validates caller-supplied results.
- Validates findings, evidence structure and unique fingerprints.
- Checks separately supplied reviewer records.
- Generates JSON and Markdown audit reports.

## Safety model and limitations

- GitHub access is read-only.
- The server does not clone or execute target repository code.
- It does not probe deployed endpoints or third-party infrastructure.
- Heuristic matches are candidate leads, not proof of vulnerabilities.
- Caller-supplied refs, line ranges, worker results and orchestration state are not cryptographically attested.
- Workflow gates check record consistency; they do not prove that independent work occurred.
- The server does not spawn agents, run background jobs, persist queues or independently authenticate evidence.
- Reports remain incomplete unless the required coverage and verification gates pass.

Important resource limits include a 15-second GitHub API timeout, a 5 MB response-body cap, up to 500 returned tree entries, a 300 KB individual-file limit and 100,000 characters of source text per review operation. Truncated or rejected inputs must not be treated as fully reviewed.

## Development and contribution

```bash
npm ci
npm run typecheck
npm test
npm run build
```

See [CONTRIBUTING.md](./CONTRIBUTING.md), [SECURITY.md](./SECURITY.md), [CHANGELOG.md](./CHANGELOG.md) and [RELEASE_CHECKLIST.md](./RELEASE_CHECKLIST.md).

## Licence

Project code: **GNU Affero General Public License v3.0 or later**. See [LICENSE](./LICENSE).

Third-party upstream material: see [ATTRIBUTIONS.md](./ATTRIBUTIONS.md) and the preserved notices in `vendor/cloudflare-security-audit-skill/`.

# Setup Guide

This guide covers installing Security-Audit-MCP-Ver and connecting it to MCP-compatible clients. The server currently uses **local STDIO transport**.

## Requirements

- Node.js 22 or newer.
- Git.
- An MCP-compatible client such as Claude Code, OpenAI Codex CLI, Cursor or Visual Studio Code.

## 1. Download and build

```bash
git clone https://github.com/Hanzet22/Security-Audit-MCP-Ver.git
cd Security-Audit-MCP-Ver
npm ci
npm run build
```

The compiled server entry point is `dist/stdio.js`. Keep the repository directory on your device; the MCP client launches this file directly.

Find the absolute path to the cloned repository. Examples:

- Linux/macOS: `/home/you/Security-Audit-MCP-Ver`
- Windows: `C:\\Users\\you\\Security-Audit-MCP-Ver`

Replace `/absolute/path/to/Security-Audit-MCP-Ver` in the examples below with that path. On Windows, use the actual path and ensure Node.js is available on PATH.

## 2. Connect an MCP client

### Claude Code

Register the server for your user account:

```bash
claude mcp add --transport stdio --scope user security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
claude mcp list
```

For a project-scoped server, use `--scope project` instead of `--scope user`. In Claude Code, run `/mcp` to inspect the connection.

### OpenAI Codex CLI

```bash
codex mcp add security-audit-mcp-ver -- node /absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js
codex mcp list
```

Alternatively, add this to `~/.codex/config.toml`:

```toml
[mcp_servers.security-audit-mcp-ver]
command = "node"
args = ["/absolute/path/to/Security-Audit-MCP-Ver/dist/stdio.js"]
```

### Cursor

Add the following server to your project's `.cursor/mcp.json` or Cursor's global MCP configuration:

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

For VS Code MCP support, add the following to `.vscode/mcp.json`:

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

Other MCP clients may use a different configuration schema. Follow the client's current MCP documentation.

## 3. Optional GitHub token

Public repositories can be inspected without a token, subject to GitHub's unauthenticated API limits. For private repositories or higher API limits, configure `GITHUB_TOKEN` in the MCP server environment.

Use a fine-grained token restricted to the required repositories, with only:

- **Contents: read-only**
- **Metadata: read-only**

Never commit a token or put it in a shared configuration file. Prefer your operating system's secret manager or the client's secure environment-variable facility.

For clients supporting an `env` field, the configuration shape is:

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

## 4. Verify the connection

- Run `claude mcp list` or `codex mcp list`, as applicable.
- Use the client's MCP status view to confirm the server is connected.
- Confirm the client can discover the server's tools.

If the server does not start, check that Node.js 22+ is installed, `npm run build` completed successfully, the configured absolute path is correct, and the client can find `node`.

## Transport and security boundaries

- Only local STDIO transport is currently supported; there is no hosted HTTP endpoint or remote MCP URL.
- GitHub access is read-only.
- The server does not execute target repository code or probe deployed services.
- Caller-supplied evidence and orchestration state are not cryptographically attested.
- Heuristic matches are leads for review, not proof of vulnerabilities.

See [README.md](./README.md), [SECURITY.md](./SECURITY.md), [CONTRIBUTING.md](./CONTRIBUTING.md) and [ATTRIBUTIONS.md](./ATTRIBUTIONS.md).

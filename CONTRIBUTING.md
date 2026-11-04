# Contributing

Thank you for considering a contribution to Security-Audit-MCP-Ver.

## Project boundaries

This project provides read-only, evidence-led source-review tools over the GitHub API. Contributions must preserve these boundaries:

- Do not execute target repository code.
- Do not probe deployed services or third-party infrastructure.
- Do not add write operations to the target-repository API path.
- Treat heuristic matches as candidate leads, never automatic vulnerability confirmations.
- Keep caller-supplied evidence, worker results, and orchestration state explicitly untrusted unless independently authenticated by a separately documented mechanism.
- Do not describe the server as an autonomous agent runtime; it does not spawn workers or background jobs.

## Development setup

Requirements: Node.js 22 or newer and npm.

```bash
npm ci
npm run typecheck
npm test
npm run build
```

For local development, run `npm run dev`. The production entry point is `dist/stdio.js`.

The test command runs the project unit/integration suite and the preserved upstream validator tests. If dependencies change, update and commit `package-lock.json` with the manifest.

## Pull request expectations

- Keep changes focused and explain the user-visible or security-relevant behavior.
- Add regression tests for changed contracts, validation rules, and security boundaries.
- Preserve strict input validation, bounded resource use, sanitized errors, and read-only behavior.
- Update README.md and CHANGELOG.md when behavior, limits, or public interfaces change.
- Do not weaken a test or validation gate merely to make a change pass.
- Do not include real credentials, private source code, personal data, or live exploit material in fixtures.
- Pin GitHub Actions to immutable commit SHAs and use the least permissions required.

## Licensing and upstream material

Original project code is licensed under GNU AGPL-3.0-or-later; see [LICENSE](./LICENSE).

Material copied from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) remains under its original MIT license in `vendor/cloudflare-security-audit-skill/`. Preserve its copyright and license notices. See [ATTRIBUTIONS.md](./ATTRIBUTIONS.md) and the vendor `LICENSE`/ `UPSTREAM.md` files.

Do not imply that this project is affiliated with, sponsored by, or endorsed by Cloudflare.

## Security reports

Please do not disclose vulnerability details in a public issue. Follow [SECURITY.md](./SECURITY.md) and use GitHub's private vulnerability reporting feature when available.

# Changelog

All notable project changes are documented here.

## [0.3.0] - 2026-11-04

### Security and correctness
- Reject malformed repository identifiers, dot-segment file paths, invalid base64 content, and invalid UTF-8 source files at the GitHub read boundary.
- Expand heuristic evidence redaction for common bearer/basic auth, GitHub, Slack, GitLab, Google, Stripe, AWS access-key, JWT, and URL-credential formats.
- Ensure report generation and independent verification reject duplicate finding fingerprints and unrelated reviewer records.
- Escape untrusted finding and scout-report text before emitting Markdown reports and architecture summaries.
- Require every deferred coverage unit to be explicitly accepted by the critic before the next-wave gate can pass.
- Classify vendored upstream material and package manifests as dependencies rather than generated output.
- Raise the minimum Node.js runtime to 22 because Node.js 20 reached end of life.
- Add fast-check property tests for duplicate fingerprints, one-to-one independent review, and unknown review references.
- Align MCP worker-task and hunter-result input schemas with their runtime contracts; reject empty task coverage/path scopes and hunter units without required checks at the protocol boundary.
- Upgrade OSV-Scanner to v2.7.0 and Anchore SBOM Action to v0.24.3, with action references pinned to immutable commits.

### Added
- MCP server factory and dedicated stdio entry point.
- In-process MCP client/server integration smoke test.
- Integration regression coverage for malformed worker-task inputs, nested task contracts, and hunter results missing required checks.
- Structured reconnaissance, hunting, coverage, findings, verification, and reporting workflow tools.
- Stateless caller-managed worker and critic orchestration contracts.
- GitHub API response boundary protections, including URL validation, bounded response reads, content-type checks, timeouts, and sanitized upstream errors.
- Integration checks for embedded URL credentials, non-standard ports, and repository path traversal.

### Changed
- README documentation now describes the 18 exposed MCP tools and the explicit, non-autonomous workflow model.
- Document the current stdio-only transport, GitHub token handling, fixed API/resource bounds, and caller-supplied evidence trust boundaries.
- CI now exercises supported Node.js LTS lines 22, 24, and 26 and uses `npm ci` with the committed npm-generated lockfile.

### Security
- Repository source inspection remains read-only; target source code is not executed and deployed endpoints are not probed.
- Upstream Cloudflare material remains attributed under its MIT license in the vendor directory.

> This dated entry describes the v0.3.0 release candidate. The version is not published until the `v0.3.0` Git tag and corresponding GitHub Release are created after all release gates pass.

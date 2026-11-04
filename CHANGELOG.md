# Changelog

All notable project changes are documented here.

## [0.3.0] - Unreleased

### Security and correctness
- Reject malformed repository identifiers, dot-segment file paths, invalid base64 content, and invalid UTF-8 source files at the GitHub read boundary.
- Expand heuristic evidence redaction for common token, bearer, GitHub token, AWS access-key, and JWT formats.
- Ensure report generation and independent verification reject duplicate finding fingerprints and unrelated reviewer records.
- Require every deferred coverage unit to be explicitly accepted by the critic before the next-wave gate can pass.
- Classify vendored upstream material and package manifests as dependencies rather than generated output.
- Raise the minimum Node.js runtime to 22 because Node.js 20 reached end of life.

### Added
- MCP server factory and dedicated stdio entry point.
- In-process MCP client/server integration smoke test.
- Structured reconnaissance, hunting, coverage, findings, verification, and reporting workflow tools.
- Stateless caller-managed worker and critic orchestration contracts.
- GitHub API response boundary protections, including URL validation, bounded response reads, content-type checks, timeouts, and sanitized upstream errors.
- Integration checks for embedded URL credentials, non-standard ports, and repository path traversal.

### Changed
- README documentation now describes the 18 exposed MCP tools and the explicit, non-autonomous workflow model.
- CI now exercises supported Node.js LTS lines 22, 24, and 26 and uses `npm ci` with the committed npm-generated lockfile.

### Security
- Repository source inspection remains read-only; target source code is not executed and deployed endpoints are not probed.
- Upstream Cloudflare material remains attributed under its MIT license in the vendor directory.

> This entry records the current development state. It is not a statement that a formal v0.3.0 release has been published or that all release gates have passed.

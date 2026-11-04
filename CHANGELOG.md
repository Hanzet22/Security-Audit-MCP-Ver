# Changelog

All notable project changes are documented here.

## [0.3.0] - Unreleased

### Added
- MCP server factory and dedicated stdio entry point.
- In-process MCP client/server integration smoke test.
- Structured reconnaissance, hunting, coverage, findings, verification, and reporting workflow tools.
- Stateless caller-managed worker and critic orchestration contracts.
- GitHub API response boundary protections, including URL validation, bounded response reads, content-type checks, timeouts, and sanitized upstream errors.
- Integration checks for embedded URL credentials, non-standard ports, and repository path traversal.

### Changed
- README documentation now describes the 18 exposed MCP tools and the explicit, non-autonomous workflow model.

### Security
- Repository source inspection remains read-only; target source code is not executed and deployed endpoints are not probed.
- Upstream Cloudflare material remains attributed under its MIT license in the vendor directory.

> This entry records the current development state. It is not a statement that a formal v0.3.0 release has been published or that all release gates have passed.

# Security Policy

## Supported versions

Security fixes are currently intended for the latest version on the `main` branch. Once tagged releases are published, the latest supported release will be identified here.

## Reporting a vulnerability

Please do not publish vulnerability details in a public issue, discussion, pull request, or social-media post.

Use GitHub's **Report a vulnerability** feature in the repository's Security tab (private vulnerability reporting / GitHub Security Advisories), if it is available. Include:

- A concise description of the affected component and potential impact.
- The affected version, commit, or branch.
- Reproduction context and steps that do not access data or systems you do not own or have permission to test.
- Relevant logs or a minimal proof of concept, with secrets and personal data removed.

If private reporting is unavailable, contact the maintainer privately through the [maintainer's GitHub profile](https://github.com/Hanzet22). Do not send credentials, access tokens, or private user data.

Please allow the maintainer reasonable time to investigate and coordinate a fix before public disclosure. A response or remediation timeline is not guaranteed.

## Scope

This policy covers this repository's MCP server, adapters, and project-maintained code.

The following are not automatically in scope:

- Vulnerabilities in GitHub, the MCP SDK, Node.js, or other upstream dependencies (report those to their respective maintainers).
- Findings in third-party repositories or deployed systems discovered using this project's read-only tools.
- Reports based only on heuristic candidate matches without a demonstrated security impact.

The server is designed for read-only source review. Do not use it to probe deployed services, access systems without authorization, or test against real users' data.

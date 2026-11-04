# Attributions

## Cloudflare Security Audit Skill

This project is an independent MCP implementation inspired by the security-audit workflow and publicly available guidance in:

- Project: [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill)
- License of upstream project: MIT
- Upstream copyright and license notices remain applicable to any upstream material actually copied or adapted.

The MCP server and adapter layer are independently written. The following upstream files are included verbatim under `vendor/cloudflare-security-audit-skill/` from upstream commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`:

- `validate-findings.cjs`
- `validate-coverage-ledger.cjs`
- `report-schema.json`
- `LICENSE`, `UPSTREAM.md`
- `SKILL.md`, `RECONNAISSANCE.md`, `HUNTING.md`, `VALIDATION-AND-REPORTING.md`
- `ATTACK-CLASSES.md` and the companion guidance files `AI-AND-LLM.md`, `CLIENT-SIDE.md`, `CLOUD-AND-DEPLOYMENT.md`, `DATA-ISOLATION-AND-LIFECYCLE.md`, `DESKTOP-MOBILE-AND-LOCAL-IPC.md`, `MEMORY-SAFETY-AND-BINARY.md`, `PROTOCOLS-RPC-AND-MESSAGING.md`, `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md`, `SUPPLY-CHAIN-AND-RELEASE.md`, and `WEB-PROTOCOL-AND-AUTH.md`
- `validate-coverage-ledger.test.cjs`, `validate-findings.test.cjs`

All files under `vendor/cloudflare-security-audit-skill/` that originate upstream remain under the upstream MIT License. The upstream license is preserved in the vendor directory. The surrounding MCP integration, tests, and project code remain under this repository's AGPL-3.0-or-later license.

## Relationship

This project is not affiliated with, sponsored by, or endorsed by Cloudflare.

## Project license

The original code in this repository is licensed under GNU Affero General Public License version 3 or (at your option) any later version. See [LICENSE](./LICENSE).

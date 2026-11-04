# v0.3.0 Release Checklist

This checklist is for preparing and publishing the v0.3.0 release. A checked item must be verified against the exact commit intended for the tag.

## Version and source

- [ ] `package.json`, `package-lock.json`, and the MCP server metadata report version `0.3.0`.
- [ ] `CHANGELOG.md` contains the reviewed v0.3.0 release notes and date.
- [ ] The release commit is on `main`; record its full commit SHA before tagging.
- [ ] Review the complete diff from the previous release/tag (or the agreed baseline).
- [ ] Confirm no credentials, private data, temporary files, or generated build output are committed.

## Quality and security gates

- [ ] CI passes on the exact release commit for Node.js 22, 24, and 26, including typecheck, unit/integration tests, upstream validator tests, and build.
- [ ] CodeQL workflow completes for JavaScript/TypeScript and GitHub Actions; review the repository's open code-scanning alerts separately.
- [ ] OSV-Scanner completes; review its findings and scan scope. A clean scan is not proof that all vulnerabilities are absent.
- [ ] SBOM generation completes and the artifact is retained for the release record.
- [ ] Review dependency updates, workflow permissions, and immutable action pins.
- [ ] Do not rerun successful test suites in a loop. If a check fails, identify and fix the cause before one justified validation run.

## Documentation and licensing

- [ ] README accurately states the supported local stdio transport and does not imply a hosted HTTP or remote MCP endpoint.
- [ ] README and tool descriptions do not imply autonomous worker spawning, background execution, or cryptographic evidence attestation.
- [ ] `SECURITY.md`, `ATTRIBUTIONS.md`, and `LICENSE` are present and consistent.
- [ ] Original project code remains GNU AGPL-3.0-or-later.
- [ ] Copied Cloudflare Security Audit Skill material retains its upstream MIT license and copyright notices under `vendor/cloudflare-security-audit-skill/`.
- [ ] Cloudflare non-affiliation disclaimer remains visible.
- [ ] Scorecard's `publish_results: false` remains an intentional choice unless public Scorecard publication is explicitly desired.

## Publication

- [ ] Create the annotated Git tag `v0.3.0` pointing to the verified release commit.
- [ ] Create the GitHub Release for `v0.3.0` using the reviewed changelog as the release notes.
- [ ] Attach the reviewed SBOM artifact if it is intended to be distributed with the release.
- [ ] Verify the tag, release page, source archive, and attached assets after publication.
- [ ] Update `SECURITY.md` to identify the supported release once publication is complete.

## Current publication state

The v0.3.0 entry is a release candidate. This checklist does not mean a Git tag or GitHub Release already exists. Do not describe the release as published until the tag and release page are verified.

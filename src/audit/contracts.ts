/**
 * Evidence contracts for Security-Audit-MCP-Ver.
 * Copyright (C) 2026 Hanzet22
 * Licensed under GNU AGPL v3.0 or later. See LICENSE.
 *
 * This schema intentionally excludes exploit payloads and live reproduction
 * instructions. It records source evidence, validation blockers and review state.
 */
import * as z from "zod/v4";

export const EvidenceSchema = z.strictObject({
  file: z.string().min(1),
  line: z.number().int().positive(),
  description: z.string().min(1).max(2000)
});

export const TraceStepSchema = z.strictObject({
  kind: z.enum(["entrypoint", "propagation", "sink"]),
  file: z.string().min(1),
  line: z.number().int().positive(),
  scope: z.string().min(1).max(500),
  description: z.string().min(1).max(2000)
});

const CommonFinding = {
  fingerprint: z.string().min(1).max(200).regex(/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/),
  title: z.string().min(1).max(300),
  description: z.string().min(1).max(5000),
  evidence: z.array(EvidenceSchema).min(1).max(100),
  trace: z.array(TraceStepSchema).min(1).max(100)
};

export const FindingSchema = z.discriminatedUnion("verdict", [
  z.strictObject({
    verdict: z.literal("confirmed"),
    ...CommonFinding,
    root_cause: z.string().min(1).max(3000),
    affected_boundary: z.string().min(1).max(1000),
    impact: z.string().min(1).max(2000),
    severity: z.enum(["informational", "low", "medium", "high", "critical"]),
    confidence: z.enum(["low", "medium", "high"]),
    remediation: z.string().min(1).max(3000),
    independent_verification: z.literal("passed")
  }),
  z.strictObject({
    verdict: z.literal("needs_validation"),
    ...CommonFinding,
    claimed_root_cause: z.string().min(1).max(3000),
    blockers: z.array(z.string().min(1).max(1000)).min(1).max(30),
    validation_plan: z.string().min(1).max(3000)
  }),
  z.strictObject({
    verdict: z.literal("rejected"),
    ...CommonFinding,
    claimed_root_cause: z.string().min(1).max(3000),
    rejection_reason: z.string().min(1).max(3000)
  })
]);

export const CoverageEntrySchema = z.strictObject({
  path: z.string().min(1),
  category: z.enum(["application", "configuration", "dependency", "test", "documentation", "generated", "unknown"]),
  status: z.enum(["reviewed", "not_reviewed", "excluded"]),
  rationale: z.string().min(1).max(2000)
});

export type Finding = z.infer<typeof FindingSchema>;
export type CoverageEntry = z.infer<typeof CoverageEntrySchema>;

export function validateCoverage(scopePaths: string[], entries: CoverageEntry[]) {
  const errors: string[] = [];
  const seen = new Set<string>();
  const scopeSeen = new Set<string>();

  for (const path of scopePaths) {
    if (scopeSeen.has(path)) errors.push(`Duplicate in-scope path: ${path}`);
    scopeSeen.add(path);
  }

  for (const entry of entries) {
    if (seen.has(entry.path)) errors.push(`Duplicate coverage path: ${entry.path}`);
    seen.add(entry.path);
    if (!scopePaths.includes(entry.path)) errors.push(`Out-of-scope coverage path: ${entry.path}`);
    if (entry.status === "excluded" && !entry.rationale.trim()) {
      errors.push(`Excluded path needs a rationale: ${entry.path}`);
    }
  }

  const covered = new Set(entries.map(entry => entry.path));
  const missing = scopePaths.filter(path => !covered.has(path));
  if (missing.length) errors.push(`Missing coverage entries: ${missing.length}`);

  const notReviewed = entries.filter(entry => entry.status === "not_reviewed").map(entry => entry.path);
  if (notReviewed.length) errors.push(`Unreviewed in-scope paths: ${notReviewed.length}`);
  return {
    valid: errors.length === 0,
    errors,
    missing_paths: missing,
    not_reviewed_paths: notReviewed,
    reviewed_count: entries.filter(entry => entry.status === "reviewed").length,
    excluded_count: entries.filter(entry => entry.status === "excluded").length,
    scope_count: scopePaths.length
  };
}

export function validateFindings(input: unknown) {
  const parsed = z.array(FindingSchema).safeParse(input);
  if (!parsed.success) {
    return {
      valid: false,
      errors: parsed.error.issues.map(issue => `${issue.path.join(".")}: ${issue.message}`),
      findings: []
    };
  }

  const errors: string[] = [];
  const fingerprints = new Set<string>();
  for (const finding of parsed.data) {
    if (fingerprints.has(finding.fingerprint)) errors.push(`Duplicate fingerprint: ${finding.fingerprint}`);
    fingerprints.add(finding.fingerprint);
  }

  return {
    valid: errors.length === 0,
    errors,
    findings: parsed.data
  };
}

export function verifyIndependentReview(
  findings: Finding[],
  checks: Array<{ fingerprint: string; agrees: boolean; evidence_matches: boolean; rationale: string }>
) {
  const findingIds = findings.map(finding => finding.fingerprint);
  const duplicateFindings = findingIds.filter((fingerprint, index, all) => all.indexOf(fingerprint) !== index);
  const knownFindings = new Set(findingIds);
  const unknownReviews = checks.filter(check => !knownFindings.has(check.fingerprint)).map(check => check.fingerprint);
  const byFingerprint = new Map(checks.map(check => [check.fingerprint, check]));
  const missing: string[] = [];
  const disagreements: string[] = [];

  for (const finding of findings) {
    const check = byFingerprint.get(finding.fingerprint);
    if (!check) {
      missing.push(finding.fingerprint);
      continue;
    }
    if (!check.agrees || !check.evidence_matches) disagreements.push(finding.fingerprint);
    if (finding.verdict === "confirmed" && (!check.agrees || !check.evidence_matches)) {
      disagreements.push(finding.fingerprint);
    }
  }

  const duplicateChecks = checks
    .map(check => check.fingerprint)
    .filter((fingerprint, index, all) => all.indexOf(fingerprint) !== index);

  return {
    passed: missing.length === 0 && disagreements.length === 0 &&
      duplicateChecks.length === 0 && duplicateFindings.length === 0 && unknownReviews.length === 0,
    missing_reviews: [...new Set(missing)],
    disagreements: [...new Set(disagreements)],
    duplicate_review_records: [...new Set(duplicateChecks)],
    duplicate_finding_records: [...new Set(duplicateFindings)],
    unknown_review_records: [...new Set(unknownReviews)]
  };
}

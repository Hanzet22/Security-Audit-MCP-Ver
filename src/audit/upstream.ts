/**
 * Thin adapter around Cloudflare's published zero-dependency validators.
 * The upstream implementation is preserved verbatim under vendor/ with its MIT license.
 * This project remains independently licensed under AGPL-3.0-or-later.
 */
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const coverageValidator = require("../../vendor/cloudflare-security-audit-skill/validate-coverage-ledger.cjs") as {
  LIMITS: { inputBytes: number; units: number };
  canonicalCoverageId: (refs: Record<string, string>) => string;
  isSafeRelativePath: (value: string) => boolean;
  validateDocument: (ledger: unknown) => string[];
};
const findingsValidator = require("../../vendor/cloudflare-security-audit-skill/validate-findings.cjs") as {
  LIMITS: { validationErrors: number };
  validateDocument: (findings: unknown, schema: unknown) => string[];
};
const reportSchema: unknown = require("../../vendor/cloudflare-security-audit-skill/report-schema.json");

export function canonicalCloudflareCoverageId(refs: { surface: string; boundary: string; subsystem: string; attack_class: string; lifecycle?: string | undefined }): string {
  const canonicalRefs: Record<string, string> = {
    surface: refs.surface,
    boundary: refs.boundary,
    subsystem: refs.subsystem,
    attack_class: refs.attack_class,
    ...(refs.lifecycle === undefined ? {} : { lifecycle: refs.lifecycle })
  };
  return coverageValidator.canonicalCoverageId(canonicalRefs);
}

function serializedInputSize(value: unknown): number {
  let serialized: string | undefined;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error("Input must be JSON-serializable.");
  }
  if (serialized === undefined) throw new Error("Input must be a JSON value.");
  return Buffer.byteLength(serialized, "utf8");
}

export function validateCloudflareCoverageLedger(ledger: unknown) {
  const size = serializedInputSize(ledger);
  if (size > coverageValidator.LIMITS.inputBytes) {
    return {
      valid: false,
      errors: [`Input exceeds ${coverageValidator.LIMITS.inputBytes} byte limit.`],
      unit_count: Array.isArray(ledger) ? ledger.length : null
    };
  }
  const errors = coverageValidator.validateDocument(ledger);
  return {
    valid: errors.length === 0,
    errors,
    unit_count: Array.isArray(ledger) ? ledger.length : null
  };
}

export function validateCloudflareFindings(findings: unknown) {
  const size = serializedInputSize(findings);
  if (size > 5 * 1024 * 1024) {
    return {
      valid: false,
      errors: ["Input exceeds 5242880 byte limit."],
      finding_count: Array.isArray(findings) ? findings.length : null
    };
  }
  const errors = findingsValidator.validateDocument(findings, reportSchema);
  return {
    valid: errors.length === 0,
    errors,
    finding_count: Array.isArray(findings) ? findings.length : null
  };
}

export function isCloudflareSafeRelativePath(value: string): boolean {
  return coverageValidator.isSafeRelativePath(value);
}

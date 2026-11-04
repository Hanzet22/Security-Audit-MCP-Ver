import test from "node:test";
import assert from "node:assert/strict";
import {
  validateCoverage,
  validateFindings,
  verifyIndependentReview,
  type Finding
} from "./contracts.js";

test("coverage is incomplete while any in-scope path is not reviewed", () => {
  const result = validateCoverage(["src/a.ts"], [{
    path: "src/a.ts",
    category: "application",
    status: "not_reviewed",
    rationale: "Inventory only"
  }]);
  assert.equal(result.valid, false);
  assert.deepEqual(result.not_reviewed_paths, ["src/a.ts"]);
});

test("coverage rejects missing and duplicate paths", () => {
  const result = validateCoverage(["src/a.ts", "src/b.ts", "src/b.ts"], [{
    path: "src/a.ts",
    category: "application",
    status: "reviewed",
    rationale: "Reviewed"
  }]);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some(error => error.includes("Missing coverage")));
  assert.ok(result.errors.some(error => error.includes("Duplicate in-scope")));
});

test("needs_validation records cannot carry severity", () => {
  const result = validateFindings([{
    verdict: "needs_validation",
    fingerprint: "RULE:file.ts:10",
    title: "Candidate",
    description: "Potential source issue",
    evidence: [{ file: "file.ts", line: 10, description: "Source match" }],
    trace: [{ kind: "sink", file: "file.ts", line: 10, scope: "request boundary", description: "Potential sink" }],
    claimed_root_cause: "Not yet established",
    blockers: ["Data flow not established"],
    validation_plan: "Review caller and sanitizer context",
    severity: "high"
  }]);
  assert.equal(result.valid, false);
});

test("duplicate finding fingerprints are rejected", () => {
  const finding = {
    verdict: "rejected",
    fingerprint: "RULE:file.ts:10",
    title: "Candidate",
    description: "Candidate was disproved",
    evidence: [{ file: "file.ts", line: 10, description: "Source evidence" }],
    trace: [{ kind: "sink", file: "file.ts", line: 10, scope: "request boundary", description: "Reviewed sink" }],
    claimed_root_cause: "Claimed issue",
    rejection_reason: "No untrusted data reaches this sink"
  };
  const result = validateFindings([finding, finding]);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some(error => error.includes("Duplicate fingerprint")));
});

test("independent verification requires a matching reviewer record", () => {
  const finding = {
    verdict: "rejected",
    fingerprint: "RULE:file.ts:10",
    title: "Candidate",
    description: "Candidate was disproved",
    evidence: [{ file: "file.ts", line: 10, description: "Source evidence" }],
    trace: [{ kind: "sink", file: "file.ts", line: 10, scope: "request boundary", description: "Reviewed sink" }],
    claimed_root_cause: "Claimed issue",
    rejection_reason: "No untrusted data reaches this sink"
  } as Finding;
  const result = verifyIndependentReview([finding], []);
  assert.equal(result.passed, false);
  assert.deepEqual(result.missing_reviews, ["RULE:file.ts:10"]);
});

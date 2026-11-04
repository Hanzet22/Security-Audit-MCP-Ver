import test from "node:test";
import assert from "node:assert/strict";
import * as fc from "fast-check";
import {
  validateCoverage,
  validateFindings,
  verifyIndependentReview,
  type Finding
} from "./contracts.js";


const makeRejectedFinding = (fingerprint: string): Finding => ({
  verdict: "rejected",
  fingerprint,
  title: "Property-generated candidate",
  description: "A property-generated finding fixture.",
  evidence: [{ file: "src/example.ts", line: 1, description: "Source evidence." }],
  trace: [{ kind: "sink", file: "src/example.ts", line: 1, scope: "test boundary", description: "Review trace." }],
  claimed_root_cause: "Unverified claim.",
  rejection_reason: "The test fixture does not establish an issue."
});

test("property: duplicate fingerprints are always rejected", () => {
  fc.assert(fc.property(
    fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,120}$/),
    fingerprint => {
      const result = validateFindings([
        makeRejectedFinding(fingerprint),
        makeRejectedFinding(fingerprint)
      ]);
      assert.equal(result.valid, false);
      assert.ok(result.errors.some(error => error.includes("Duplicate fingerprint")));
    }
  ));
});

test("property: one-to-one independent reviews pass for unique findings", () => {
  fc.assert(fc.property(
    fc.uniqueArray(fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,120}$/), { minLength: 1, maxLength: 12 }),
    fingerprints => {
      const findings = fingerprints.map(makeRejectedFinding);
      const checks = fingerprints.map(fingerprint => ({
        fingerprint, agrees: true, evidence_matches: true, rationale: "Property-generated independent review."
      }));
      assert.equal(verifyIndependentReview(findings, checks).passed, true);
    }
  ));
});

test("property: unrelated review fingerprints never pass", () => {
  fc.assert(fc.property(
    fc.stringMatching(/^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,120}$/),
    unknownFingerprint => {
      fc.pre(unknownFingerprint !== "KNOWN:1");
      const finding = makeRejectedFinding("KNOWN:1");
      const checks = [
        { fingerprint: "KNOWN:1", agrees: true, evidence_matches: true, rationale: "Matched." },
        { fingerprint: unknownFingerprint, agrees: true, evidence_matches: true, rationale: "Unrelated." }
      ];
      const result = verifyIndependentReview([finding], checks);
      assert.equal(result.passed, false);
      assert.deepEqual(result.unknown_review_records, [unknownFingerprint]);
    }
  ));
});

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

test("independent verification rejects duplicate findings and unrelated reviewer records", () => {
  const finding = {
    verdict: "rejected" as const,
    fingerprint: "RULE:file.ts:10",
    title: "Candidate",
    description: "Candidate was disproved",
    evidence: [{ file: "file.ts", line: 10, description: "Source evidence" }],
    trace: [{ kind: "sink" as const, file: "file.ts", line: 10, scope: "request boundary", description: "Reviewed sink" }],
    claimed_root_cause: "Claimed issue",
    rejection_reason: "No untrusted data reaches this sink"
  };
  const duplicate = verifyIndependentReview([finding, finding], [{
    fingerprint: finding.fingerprint, agrees: true, evidence_matches: true, rationale: "Reviewed"
  }]);
  assert.equal(duplicate.passed, false);
  assert.deepEqual(duplicate.duplicate_finding_records, [finding.fingerprint]);

  const unrelated = verifyIndependentReview([finding], [
    { fingerprint: finding.fingerprint, agrees: true, evidence_matches: true, rationale: "Reviewed" },
    { fingerprint: "UNRELATED:file.ts:1", agrees: true, evidence_matches: true, rationale: "Not part of this report" }
  ]);
  assert.equal(unrelated.passed, false);
  assert.deepEqual(unrelated.unknown_review_records, ["UNRELATED:file.ts:1"]);
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

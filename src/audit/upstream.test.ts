import test from "node:test";
import assert from "node:assert/strict";
import {
  validateCloudflareCoverageLedger,
  validateCloudflareFindings
} from "./upstream.js";

test("Cloudflare coverage validator accepts an empty ledger", () => {
  const result = validateCloudflareCoverageLedger([]);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("Cloudflare coverage validator rejects non-canonical ledger entries", () => {
  const result = validateCloudflareCoverageLedger([{ coverage_id: "not-canonical" }]);
  assert.equal(result.valid, false);
  assert.ok(result.errors.length > 0);
});

test("Cloudflare findings validator accepts an empty findings document", () => {
  const result = validateCloudflareFindings([]);
  assert.equal(result.valid, true);
  assert.deepEqual(result.errors, []);
});

test("Cloudflare findings validator rejects needs_validation severity", () => {
  const result = validateCloudflareFindings([{
    verdict: "needs_validation",
    fingerprint: "candidate-1",
    title: "Candidate",
    description: "A source candidate requiring review.",
    claimed_root_cause: "The relevant control is not established.",
    trace: [{
      kind: "entrypoint",
      file: "src/handler.ts",
      line: 1,
      scope: "handle",
      description: "Source entrypoint."
    }],
    evidence: [{
      file: "src/handler.ts",
      line: 1,
      description: "Source location requiring review."
    }],
    blockers: ["The data-flow relationship is not established."],
    validation_plan: { local: "Review the relevant source path." },
    severity: "high"
  }]);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some(error => /severity|additional property/i.test(error)));
});

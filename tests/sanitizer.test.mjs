import assert from "node:assert/strict";
import test from "node:test";

import {
  buildManifest,
  buildSubmissionBundle,
  sanitizeExecutionPayload,
  toExceptionCsv,
} from "../sanitizer.mjs";

const syntheticInput = {
  executions: [
    {
      startedAt: "2026-08-01T12:00:00Z",
      workflow: { id: "private-workflow-id", name: "Private workflow name" },
      error: {
        message: "401 Unauthorized for synthetic.person@example.test token=synthetic-secret",
      },
    },
    {
      startedAt: "2026-08-02T12:00:00Z",
      workflow: { id: "private-workflow-id", name: "Private workflow name" },
      error: {
        message: "schema type mismatch",
        details: {
          expectedField: "payload.region_code",
          observedField: "payload.region_slug",
          expectedType: "string",
          observedType: "string"
        }
      }
    }
  ]
};

function storedZipEntries(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const decoder = new TextDecoder();
  const entries = new Map();
  let offset = 0;
  while (offset + 30 <= bytes.byteLength && view.getUint32(offset, true) === 0x04034b50) {
    assert.equal(view.getUint16(offset + 8, true), 0);
    const size = view.getUint32(offset + 18, true);
    const nameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    const name = decoder.decode(bytes.subarray(nameStart, nameStart + nameLength));
    entries.set(name, decoder.decode(bytes.subarray(dataStart, dataStart + size)));
    offset = dataStart + size;
  }
  return entries;
}

test("sanitizer emits pseudonymous canonical rows without raw values", () => {
  const result = sanitizeExecutionPayload(syntheticInput, { handlingMinutes: 15 });
  assert.equal(result.records.length, 2);
  assert.equal(result.records[0].workflow_ref, "workflow-001");
  assert.equal(result.records[1].workflow_ref, "workflow-001");
  assert.equal(result.records[0].failure_class, "unclassified");
  assert.equal(result.records[0].authority_floor, "authorized_human");
  assert.equal(result.records[1].failure_class, "schema_field_renamed");
  assert.equal(result.records[1].expected_field, "payload.region_code");
  assert.equal(result.records[1].observed_field, "payload.region_slug");
  assert.ok(result.sourceSensitivePatternCount > 0);

  const csv = toExceptionCsv(result.records);
  assert.doesNotMatch(csv, /synthetic\.person|synthetic-secret|private-workflow/i);
  assert.match(csv, /schema_field_renamed/);
});

test("manifest requires explicit rights and sanitization attestations", () => {
  assert.throws(() => buildManifest({
    customerRef: "buyer-001",
    periodStart: "2026-08-01",
    periodEnd: "2026-08-02",
    sourceRightsAttested: true,
    sanitizationAttested: false,
  }), /attest/i);

  const manifest = buildManifest({
    customerRef: "buyer-001",
    periodStart: "2026-08-01",
    periodEnd: "2026-08-02",
    sourceRightsAttested: true,
    sanitizationAttested: true,
  });
  assert.equal(manifest.production_access_authorized, false);
  assert.equal(manifest.customer_data_present, false);
});

test("bundle is deterministic, complete, and contains no raw source", () => {
  const result = sanitizeExecutionPayload(syntheticInput, { handlingMinutes: 15 });
  const manifest = buildManifest({
    customerRef: "buyer-001",
    periodStart: "2026-08-01",
    periodEnd: "2026-08-02",
    sourceRightsAttested: true,
    sanitizationAttested: true,
  });
  const options = {
    manifest,
    records: result.records,
    rejectedCount: result.rejected.length,
    sourceWarningCount: result.sourceSensitivePatternCount,
  };
  const first = buildSubmissionBundle(options);
  const second = buildSubmissionBundle(options);
  assert.deepEqual(first, second);

  const entries = storedZipEntries(first);
  assert.deepEqual([...entries.keys()], ["manifest.json", "exceptions.csv", "SAFETY-RECEIPT.txt"]);
  assert.match(entries.get("SAFETY-RECEIPT.txt"), /NOTHING WAS UPLOADED/);
  const serialized = new TextDecoder().decode(first);
  assert.doesNotMatch(serialized, /synthetic\.person|synthetic-secret|private-workflow/i);
});

test("sanitizer fails closed above 25 records", () => {
  const records = Array.from({ length: 26 }, (_, index) => ({
    startedAt: `2026-08-${String((index % 25) + 1).padStart(2, "0")}T12:00:00Z`,
    error: { message: "timeout" },
  }));
  assert.throws(() => sanitizeExecutionPayload(records), /maximum of 25/i);
});

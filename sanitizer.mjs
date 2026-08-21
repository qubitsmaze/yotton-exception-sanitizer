const MAX_RECORDS = 25;

const SENSITIVE_PATTERNS = [
  /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  /\b(?:sk|pk|rk)_[A-Za-z0-9_-]{8,}\b/i,
  /\bsk-[A-Za-z0-9_-]{8,}\b/i,
  /\b(?:bearer|authorization)\s+[A-Za-z0-9._~+\/-]{8,}\b/i,
  /\b(?:password|passwd|secret|api[_ -]?key|token)\s*[:=]\s*\S+/i,
  /\b(?:\d[ -]*?){13,19}\b/,
  /\b\d{3}-\d{2}-\d{4}\b/,
];

const FAILURE_RULES = [
  {
    category: "Authentication or credential failure",
    pattern: /\b(?:401|unauthori[sz]ed|authentication|credential|api[_ -]?key|token)\b/i,
  },
  {
    category: "Permission or authorization failure",
    pattern: /\b(?:403|forbidden|permission denied|not permitted|access denied)\b/i,
  },
  {
    category: "Rate-limit failure",
    pattern: /\b(?:429|rate[ -]?limit|too many requests|quota exceeded)\b/i,
  },
  {
    category: "Timeout failure",
    pattern: /\b(?:timeout|timed out|deadline exceeded|etimedout)\b/i,
  },
  {
    category: "Missing optional enrichment failure",
    pattern: /\benrichment\b.*\b(?:missing|no result|absent|returned no)\b|\b(?:missing|no result|absent|returned no)\b.*\benrichment\b/i,
  },
  {
    category: "Contract or price change",
    pattern: /\b(?:contract|price change|payment|financial commitment)\b/i,
  },
  {
    category: "Schema or validation failure",
    pattern: /\b(?:schema|validation|required field|invalid (?:field|type)|type mismatch|malformed)\b/i,
  },
  {
    category: "Duplicate or idempotency failure",
    pattern: /\b(?:duplicate|already exists|idempoten|unique constraint|conflict)\b/i,
  },
  {
    category: "Dependency availability failure",
    pattern: /\b(?:5\d\d|unavailable|connection refused|econnrefused|bad gateway|service down)\b/i,
  },
];

function candidateArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== "object") return [];
  for (const key of ["executions", "errors", "results", "items", "data"]) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  if (payload.execution && typeof payload.execution === "object") {
    return [payload.execution];
  }
  return [payload];
}

function nestedValue(value, paths) {
  for (const path of paths) {
    let current = value;
    for (const segment of path) {
      if (!current || typeof current !== "object") {
        current = undefined;
        break;
      }
      current = current[segment];
    }
    if (typeof current === "string" || typeof current === "number") {
      const text = String(current).trim();
      if (text) return text;
    }
  }
  return "";
}

function safeTimestamp(candidate) {
  const raw = nestedValue(candidate, [
    ["startedAt"],
    ["stoppedAt"],
    ["createdAt"],
    ["timestamp"],
    ["occurred_at"],
    ["execution", "startedAt"],
    ["execution", "stoppedAt"],
    ["execution", "timestamp"],
  ]);
  if (!raw) return "";
  const milliseconds = Date.parse(raw);
  if (!Number.isFinite(milliseconds)) return "";
  return new Date(milliseconds).toISOString();
}

function rawErrorMessage(candidate) {
  return nestedValue(candidate, [
    ["error", "message"],
    ["execution", "error", "message"],
    ["trigger", "error", "message"],
    ["message"],
    ["error"],
  ]);
}

function workflowIdentity(candidate, index) {
  return (
    nestedValue(candidate, [
      ["workflow", "id"],
      ["workflowId"],
      ["execution", "workflow", "id"],
      ["workflow", "name"],
      ["workflowName"],
      ["execution", "workflow", "name"],
    ]) || `unknown-${index + 1}`
  );
}

function failureCategory(message) {
  for (const rule of FAILURE_RULES) {
    if (rule.pattern.test(message)) return rule.category;
  }
  return "Unclassified workflow failure";
}

const FIELD_PATH_PATTERN = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){0,5}$/;
const PROTECTED_PATH_PATTERN = /(?:^|[._])(?:account|bank|card|contract|credential|delete|email|health|identity|name|password|patient|payment|phone|price|publish|secret|ssn|token)(?:[._]|$)/i;
const PRIMITIVE_TYPES = new Set([
  "array",
  "boolean",
  "integer",
  "null",
  "number",
  "object",
  "string",
]);

function schemaDetailSource(candidate) {
  const sources = [
    candidate?.error?.details,
    candidate?.execution?.error?.details,
    candidate?.details,
  ];
  return sources.find(
    (value) => value && typeof value === "object" && !Array.isArray(value),
  );
}

function structuredSchemaFacts(candidate) {
  const details = schemaDetailSource(candidate);
  if (!details) {
    return { status: "not_supplied", protected: false };
  }
  const values = {
    expectedField: details.expectedField,
    observedField: details.observedField,
    expectedType: details.expectedType,
    observedType: details.observedType,
  };
  if (Object.values(values).every((value) => value === undefined || value === null || value === "")) {
    return { status: "not_supplied", protected: false };
  }
  if (Object.values(values).some((value) => typeof value !== "string")) {
    return { status: "rejected", protected: false };
  }
  const expectedField = values.expectedField.trim();
  const observedField = values.observedField.trim();
  const expectedType = values.expectedType.trim().toLowerCase();
  const observedType = values.observedType.trim().toLowerCase();
  const protectedPath =
    PROTECTED_PATH_PATTERN.test(expectedField) || PROTECTED_PATH_PATTERN.test(observedField);
  const valid =
    expectedField.length <= 128 &&
    observedField.length <= 128 &&
    FIELD_PATH_PATTERN.test(expectedField) &&
    FIELD_PATH_PATTERN.test(observedField) &&
    expectedField !== observedField &&
    PRIMITIVE_TYPES.has(expectedType) &&
    PRIMITIVE_TYPES.has(observedType) &&
    expectedType === observedType &&
    !protectedPath;
  if (!valid) {
    return { status: "rejected", protected: protectedPath };
  }
  return {
    status: "accepted",
    protected: false,
    expectedField,
    observedField,
    expectedType,
    observedType,
  };
}

function canonicalSemantics(message, schemaFacts) {
  if (schemaFacts.status === "accepted") {
    return {
      failureClass: "schema_field_renamed",
      authorityFloor: "bounded_analysis",
      protectedField: false,
    };
  }
  const protectedMessage = /\b(?:auth(?:entication|orization)?|bank|card|contract|credential|delet(?:e|ion)|financial commitment|forbidden|password|patient|payment|permission|price change|publish|secret|token)\b/i.test(
    message,
  );
  if (/\b(?:contract|price change|payment|financial commitment)\b/i.test(message)) {
    return {
      failureClass: "contract_or_price_change",
      authorityFloor: "authorized_human",
      protectedField: true,
    };
  }
  if (/\b(?:duplicate|already exists|idempoten|unique constraint|same buyer|identity conflict)\b/i.test(message)) {
    return {
      failureClass: "duplicate_identity",
      authorityFloor: protectedMessage ? "authorized_human" : "owner_decision",
      protectedField: protectedMessage,
    };
  }
  if (
    /\benrichment\b/i.test(message) &&
    /\b(?:missing|no result|absent|returned no)\b/i.test(message)
  ) {
    return {
      failureClass: "missing_optional_enrichment",
      authorityFloor: "bounded_analysis",
      protectedField: false,
    };
  }
  if (/\b(?:429|5\d\d|bad gateway|connection refused|deadline exceeded|econnrefused|etimedout|malformed|rate[ -]?limit|service down|timed out|timeout|too many requests|unavailable|vendor service)\b/i.test(message)) {
    return {
      failureClass: "integration_fault",
      authorityFloor: "bounded_analysis",
      protectedField: false,
    };
  }
  const protectedField = protectedMessage || schemaFacts.protected;
  return {
    failureClass: "unclassified",
    authorityFloor: protectedField ? "authorized_human" : "owner_decision",
    protectedField,
  };
}

function sensitivePatternCount(value) {
  let serialized = "";
  try {
    serialized = JSON.stringify(value);
  } catch {
    return 1;
  }
  return SENSITIVE_PATTERNS.reduce(
    (count, pattern) => count + (pattern.test(serialized) ? 1 : 0),
    0,
  );
}

export function sanitizeExecutionPayload(payload, options = {}) {
  const handlingMinutes = Number(options.handlingMinutes ?? 15);
  if (
    !Number.isInteger(handlingMinutes) ||
    handlingMinutes < 1 ||
    handlingMinutes > 480
  ) {
    throw new Error("Handling minutes must be an integer between 1 and 480.");
  }

  const candidates = candidateArray(payload);
  if (candidates.length > MAX_RECORDS) {
    throw new Error(`A maximum of ${MAX_RECORDS} records is allowed per audit.`);
  }
  if (candidates.length === 0) {
    throw new Error("No supported execution records were found.");
  }

  const workflowRefs = new Map();
  const records = [];
  const rejected = [];

  candidates.forEach((candidate, index) => {
    if (!candidate || typeof candidate !== "object") {
      rejected.push({ index: index + 1, reason: "record_not_an_object" });
      return;
    }
    const occurredAt = safeTimestamp(candidate);
    const message = rawErrorMessage(candidate);
    if (!occurredAt) {
      rejected.push({ index: index + 1, reason: "missing_or_invalid_timestamp" });
      return;
    }
    if (!message) {
      rejected.push({ index: index + 1, reason: "missing_error_message" });
      return;
    }

    const identity = workflowIdentity(candidate, index);
    if (!workflowRefs.has(identity)) {
      workflowRefs.set(
        identity,
        `workflow-${String(workflowRefs.size + 1).padStart(3, "0")}`,
      );
    }
    const schemaFacts = structuredSchemaFacts(candidate);
    const semantics = canonicalSemantics(message, schemaFacts);

    records.push({
      record_id: `event-${String(records.length + 1).padStart(3, "0")}`,
      occurred_at: occurredAt,
      workflow_ref: workflowRefs.get(identity),
      error_message: failureCategory(message),
      failure_class: semantics.failureClass,
      expected_field: schemaFacts.status === "accepted" ? schemaFacts.expectedField : "",
      observed_field: schemaFacts.status === "accepted" ? schemaFacts.observedField : "",
      expected_type: schemaFacts.status === "accepted" ? schemaFacts.expectedType : "",
      observed_type: schemaFacts.status === "accepted" ? schemaFacts.observedType : "",
      handling_minutes: handlingMinutes,
      authority_floor: semantics.authorityFloor,
      protected_field: semantics.protectedField,
      semantic_detail_status: schemaFacts.status,
    });
  });

  return {
    records,
    rejected,
    sourceSensitivePatternCount: sensitivePatternCount(payload),
    sourceRecordCount: candidates.length,
  };
}

function csvCell(value) {
  const text = String(value ?? "");
  if (!/[",\r\n]/.test(text)) return text;
  return `"${text.replaceAll('"', '""')}"`;
}

export function toExceptionCsv(records) {
  const headers = [
    "record_id",
    "occurred_at",
    "workflow_ref",
    "error_message",
    "failure_class",
    "expected_field",
    "observed_field",
    "expected_type",
    "observed_type",
    "handling_minutes",
    "authority_floor",
    "protected_field",
  ];
  const lines = [headers.join(",")];
  for (const record of records) {
    lines.push(headers.map((header) => csvCell(record[header])).join(","));
  }
  return `${lines.join("\n")}\n`;
}

export function buildManifest({
  customerRef,
  periodStart,
  periodEnd,
  sourceRightsAttested,
  sanitizationAttested,
}) {
  const normalizedRef = String(customerRef ?? "").trim();
  if (!/^[A-Za-z0-9_-]{3,64}$/.test(normalizedRef)) {
    throw new Error(
      "Customer reference must be 3-64 pseudonymous letters, numbers, hyphens, or underscores.",
    );
  }
  const start = String(periodStart ?? "");
  const end = String(periodEnd ?? "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(start) || !/^\d{4}-\d{2}-\d{2}$/.test(end)) {
    throw new Error("Period start and end must use YYYY-MM-DD.");
  }
  if (Date.parse(`${start}T00:00:00Z`) > Date.parse(`${end}T23:59:59Z`)) {
    throw new Error("Period start must not be after period end.");
  }
  if (sourceRightsAttested !== true || sanitizationAttested !== true) {
    throw new Error("Both rights and sanitization attestations must be confirmed.");
  }
  return {
    customer_ref: normalizedRef,
    period_start: start,
    period_end: end,
    source_rights_attested: Boolean(sourceRightsAttested),
    sanitization_attested: Boolean(sanitizationAttested),
    handling_time_source: "owner_supplied_estimate",
    production_access_authorized: false,
    customer_data_present: false,
  };
}

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function concatBytes(parts) {
  const size = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function storedZip(entries) {
  const encoder = new TextEncoder();
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;

  for (const [name, content] of entries) {
    const nameBytes = encoder.encode(name);
    const data = encoder.encode(content);
    const checksum = crc32(data);
    const local = new Uint8Array(30);
    const localView = new DataView(local.buffer);
    localView.setUint32(0, 0x04034b50, true);
    localView.setUint16(4, 20, true);
    localView.setUint16(6, 0x0800, true);
    localView.setUint16(8, 0, true);
    localView.setUint16(10, 0, true);
    localView.setUint16(12, 0x0021, true);
    localView.setUint32(14, checksum, true);
    localView.setUint32(18, data.byteLength, true);
    localView.setUint32(22, data.byteLength, true);
    localView.setUint16(26, nameBytes.byteLength, true);
    localView.setUint16(28, 0, true);
    localParts.push(local, nameBytes, data);

    const central = new Uint8Array(46);
    const centralView = new DataView(central.buffer);
    centralView.setUint32(0, 0x02014b50, true);
    centralView.setUint16(4, 20, true);
    centralView.setUint16(6, 20, true);
    centralView.setUint16(8, 0x0800, true);
    centralView.setUint16(10, 0, true);
    centralView.setUint16(12, 0, true);
    centralView.setUint16(14, 0x0021, true);
    centralView.setUint32(16, checksum, true);
    centralView.setUint32(20, data.byteLength, true);
    centralView.setUint32(24, data.byteLength, true);
    centralView.setUint16(28, nameBytes.byteLength, true);
    centralView.setUint16(30, 0, true);
    centralView.setUint16(32, 0, true);
    centralView.setUint16(34, 0, true);
    centralView.setUint16(36, 0, true);
    centralView.setUint32(38, 0, true);
    centralView.setUint32(42, localOffset, true);
    centralParts.push(central, nameBytes);

    localOffset += local.byteLength + nameBytes.byteLength + data.byteLength;
  }

  const centralDirectory = concatBytes(centralParts);
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  endView.setUint32(0, 0x06054b50, true);
  endView.setUint16(4, 0, true);
  endView.setUint16(6, 0, true);
  endView.setUint16(8, entries.length, true);
  endView.setUint16(10, entries.length, true);
  endView.setUint32(12, centralDirectory.byteLength, true);
  endView.setUint32(16, localOffset, true);
  endView.setUint16(20, 0, true);
  return concatBytes([...localParts, centralDirectory, end]);
}

export function buildSubmissionBundle({
  manifest,
  records,
  rejectedCount = 0,
  sourceWarningCount = 0,
}) {
  if (!manifest || typeof manifest !== "object") {
    throw new Error("A valid manifest is required.");
  }
  if (
    manifest.source_rights_attested !== true ||
    manifest.sanitization_attested !== true ||
    manifest.production_access_authorized !== false ||
    manifest.customer_data_present !== false
  ) {
    throw new Error("The manifest does not satisfy the fail-closed intake contract.");
  }
  if (!Array.isArray(records) || records.length < 1 || records.length > MAX_RECORDS) {
    throw new Error(`The bundle must contain between 1 and ${MAX_RECORDS} safe rows.`);
  }
  for (const [label, value] of [
    ["rejected count", rejectedCount],
    ["source warning count", sourceWarningCount],
  ]) {
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative integer.`);
    }
  }

  const orderedManifest = Object.fromEntries(
    Object.keys(manifest)
      .sort()
      .map((key) => [key, manifest[key]]),
  );
  const receipt = [
    "YOTTON SAFE SUBMISSION BUNDLE",
    "",
    "GENERATED LOCALLY IN YOUR BROWSER. NOTHING WAS UPLOADED.",
    `SAFE ROWS: ${records.length}`,
    `REJECTED SOURCE ROWS: ${rejectedCount}`,
    `SOURCE WARNING CATEGORIES: ${sourceWarningCount}`,
    "PRODUCTION ACCESS AUTHORIZED: NO",
    "EXTERNAL SIDE EFFECTS AUTHORIZED: NO",
    "",
    "Review manifest.json and exceptions.csv before transfer.",
    "This receipt does not prove that the original source was free of sensitive data.",
    "Do not send credentials, identities, payment data, health data, or government identifiers.",
    "",
  ].join("\n");

  return storedZip([
    ["manifest.json", `${JSON.stringify(orderedManifest, null, 2)}\n`],
    ["exceptions.csv", toExceptionCsv(records)],
    ["SAFETY-RECEIPT.txt", receipt],
  ]);
}

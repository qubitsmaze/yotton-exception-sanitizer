import {
  buildManifest,
  buildSubmissionBundle,
  sanitizeExecutionPayload,
  toExceptionCsv,
} from "./sanitizer.mjs";

const MAX_FILE_BYTES = 2_000_000;
const SYNTHETIC_SAMPLE = {
  executions: [
    {
      startedAt: "2026-08-01T14:30:00Z",
      workflow: { id: "synthetic-crm-sync", name: "Synthetic CRM Sync" },
      error: {
        message: "schema validation failed",
        details: {
          expectedField: "payload.region_code",
          observedField: "payload.region_slug",
          expectedType: "string",
          observedType: "string",
        },
      },
    },
    {
      startedAt: "2026-08-02T09:15:00Z",
      workflow: { id: "synthetic-crm-sync", name: "Synthetic CRM Sync" },
      error: { message: "duplicate identity conflict" },
    },
    {
      startedAt: "2026-08-03T17:45:00Z",
      workflow: { id: "synthetic-contract-route", name: "Synthetic Contract Route" },
      sourceNote: "fixture@example.test token=fixture-only",
      error: { message: "payment contract price changed" },
    },
    {
      startedAt: "2026-08-04T11:20:00Z",
      workflow: { id: "synthetic-enrichment", name: "Synthetic Enrichment" },
      error: { message: "optional enrichment returned no result" },
    },
    {
      startedAt: "2026-08-05T08:05:00Z",
      workflow: { id: "synthetic-enrichment", name: "Synthetic Enrichment" },
      error: { message: "429 rate limit exceeded" },
    },
  ],
};

const byId = (id) => document.getElementById(id);
const elements = {
  file: byId("json-file"),
  dropZone: byId("drop-zone"),
  handlingMinutes: byId("handling-minutes"),
  customerRef: byId("customer-ref"),
  periodStart: byId("period-start"),
  periodEnd: byId("period-end"),
  rightsAttested: byId("rights-attested"),
  sanitizationAttested: byId("sanitization-attested"),
  resultPanel: byId("result-panel"),
  errorBox: byId("error-box"),
  statusBox: byId("status-box"),
  sourceWarning: byId("source-warning"),
  preview: byId("preview"),
  safeCount: byId("safe-count"),
  rejectedCount: byId("rejected-count"),
  warningCount: byId("warning-count"),
  downloadBundle: byId("download-bundle"),
  downloadCsv: byId("download-csv"),
  downloadManifest: byId("download-manifest"),
  checksum: byId("checksum"),
  checksumValue: byId("checksum-value"),
};

let result = null;

function showError(message) {
  elements.errorBox.textContent = `REJECTED // ${message}`;
  elements.errorBox.hidden = false;
  elements.statusBox.hidden = true;
}

function showStatus(message) {
  elements.statusBox.textContent = message;
  elements.statusBox.hidden = false;
  elements.errorBox.hidden = true;
}

function clearMessages() {
  elements.errorBox.hidden = true;
  elements.statusBox.hidden = true;
  elements.checksum.hidden = true;
}

function dateString(date) {
  return date.toISOString().slice(0, 10);
}

function ensureDefaultDates() {
  if (!elements.periodEnd.value) elements.periodEnd.value = dateString(new Date());
  if (!elements.periodStart.value) {
    const start = new Date();
    start.setUTCDate(start.getUTCDate() - 30);
    elements.periodStart.value = dateString(start);
  }
}

function saveBlob(filename, blob) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function saveText(filename, text, type) {
  saveBlob(filename, new Blob([text], { type }));
}

function saveBytes(filename, bytes, type) {
  saveBlob(filename, new Blob([bytes.slice().buffer], { type }));
}

function currentManifest() {
  return buildManifest({
    customerRef: elements.customerRef.value,
    periodStart: elements.periodStart.value,
    periodEnd: elements.periodEnd.value,
    sourceRightsAttested: elements.rightsAttested.checked,
    sanitizationAttested: elements.sanitizationAttested.checked,
  });
}

function readyToDownload() {
  return Boolean(
    result?.records?.length &&
      elements.periodStart.value &&
      elements.periodEnd.value &&
      elements.customerRef.value.trim() &&
      elements.rightsAttested.checked &&
      elements.sanitizationAttested.checked,
  );
}

function updateButtons() {
  const ready = readyToDownload();
  elements.downloadBundle.disabled = !ready;
  elements.downloadCsv.disabled = !ready;
  elements.downloadManifest.disabled = !ready;
}

function previewRow(record) {
  const row = document.createElement("div");
  row.className = "preview-row";
  const occurred = document.createElement("span");
  occurred.textContent = record.occurred_at;
  const workflow = document.createElement("span");
  workflow.textContent = record.workflow_ref;
  const detail = document.createElement("strong");
  detail.textContent = record.error_message;
  const semantics = document.createElement("small");
  semantics.textContent = `${record.failure_class} · ${record.authority_floor} · ${record.protected_field ? "PROTECTED" : "NON-PROTECTED"} · SEMANTIC ${record.semantic_detail_status.toUpperCase()}`;
  detail.append(semantics);
  row.append(occurred, workflow, detail);
  return row;
}

function renderResult(next, label) {
  result = next;
  elements.preview.replaceChildren(...next.records.map(previewRow));
  elements.safeCount.textContent = String(next.records.length);
  elements.rejectedCount.textContent = String(next.rejected.length);
  elements.warningCount.textContent = String(next.sourceSensitivePatternCount);
  elements.sourceWarning.hidden = next.sourceSensitivePatternCount === 0;
  elements.resultPanel.hidden = false;
  elements.checksum.hidden = true;
  updateButtons();
  showStatus(`${label} // ${next.records.length} safe row(s) produced locally. Review before attesting.`);
  elements.resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function sanitizePayload(payload, label) {
  clearMessages();
  const handlingMinutes = Number(elements.handlingMinutes.value);
  const next = sanitizeExecutionPayload(payload, { handlingMinutes });
  if (!next.records.length) {
    throw new Error(`No safe rows were produced. ${next.rejected.length} record(s) were rejected.`);
  }
  renderResult(next, label);
}

async function processFile(file) {
  clearMessages();
  if (!file) return;
  if (file.size > MAX_FILE_BYTES) {
    throw new Error("File rejected: the local-only limit is 2 MB.");
  }
  const payload = JSON.parse(await file.text());
  sanitizePayload(payload, "LOCAL FILE READ");
}

async function onFileChange() {
  try {
    await processFile(elements.file.files?.[0]);
  } catch (error) {
    result = null;
    elements.resultPanel.hidden = true;
    showError(error instanceof Error ? error.message : "The file could not be processed.");
  } finally {
    elements.file.value = "";
  }
}

function loadSample() {
  try {
    ensureDefaultDates();
    elements.customerRef.value = "synthetic-demo";
    elements.rightsAttested.checked = false;
    elements.sanitizationAttested.checked = false;
    sanitizePayload(SYNTHETIC_SAMPLE, "SYNTHETIC FIXTURE");
  } catch (error) {
    showError(error instanceof Error ? error.message : "The synthetic fixture failed.");
  }
}

function downloadCsv() {
  try {
    if (!result || !readyToDownload()) return;
    currentManifest();
    saveText("exceptions.csv", toExceptionCsv(result.records), "text/csv;charset=utf-8");
    showStatus("CSV CREATED LOCALLY // Inspect before transfer.");
  } catch (error) {
    showError(error instanceof Error ? error.message : "CSV export failed.");
  }
}

function downloadManifest() {
  try {
    if (!readyToDownload()) return;
    saveText(
      "manifest.json",
      `${JSON.stringify(currentManifest(), null, 2)}\n`,
      "application/json;charset=utf-8",
    );
    showStatus("MANIFEST CREATED LOCALLY // Keep it paired with the CSV.");
  } catch (error) {
    showError(error instanceof Error ? error.message : "Manifest export failed.");
  }
}

async function downloadBundle() {
  try {
    if (!result || !readyToDownload()) return;
    const bytes = buildSubmissionBundle({
      manifest: currentManifest(),
      records: result.records,
      rejectedCount: result.rejected.length,
      sourceWarningCount: result.sourceSensitivePatternCount,
    });
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
    const checksum = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
    const safeRef = elements.customerRef.value.trim();
    saveBytes(`yotton-${safeRef}-safe-submission.zip`, bytes, "application/zip");
    elements.checksumValue.textContent = checksum;
    elements.checksum.hidden = false;
    showStatus("COMPLETE ZIP CREATED LOCALLY // No upload occurred.");
  } catch (error) {
    showError(error instanceof Error ? error.message : "Bundle export failed.");
  }
}

function prevent(event) {
  event.preventDefault();
  event.stopPropagation();
}

for (const name of ["dragenter", "dragover"]) {
  elements.dropZone.addEventListener(name, (event) => {
    prevent(event);
    elements.dropZone.classList.add("is-dragging");
  });
}
for (const name of ["dragleave", "drop"]) {
  elements.dropZone.addEventListener(name, (event) => {
    prevent(event);
    elements.dropZone.classList.remove("is-dragging");
  });
}
elements.dropZone.addEventListener("drop", async (event) => {
  try {
    await processFile(event.dataTransfer?.files?.[0]);
  } catch (error) {
    result = null;
    elements.resultPanel.hidden = true;
    showError(error instanceof Error ? error.message : "The dropped file could not be processed.");
  }
});

elements.file.addEventListener("change", () => void onFileChange());
byId("load-sample").addEventListener("click", loadSample);
byId("load-sample-top").addEventListener("click", () => {
  document.querySelector("#tool").scrollIntoView({ behavior: "smooth" });
  loadSample();
});
elements.downloadCsv.addEventListener("click", downloadCsv);
elements.downloadManifest.addEventListener("click", downloadManifest);
elements.downloadBundle.addEventListener("click", () => void downloadBundle());
for (const element of [
  elements.handlingMinutes,
  elements.customerRef,
  elements.periodStart,
  elements.periodEnd,
  elements.rightsAttested,
  elements.sanitizationAttested,
]) {
  element.addEventListener("input", updateButtons);
  element.addEventListener("change", updateButtons);
}
ensureDefaultDates();
updateButtons();

# Yotton Local Exception Sanitizer

A browser-only, no-upload safe-export tool for small sets of n8n-style workflow error records.

**Live tool:** https://qubitsmaze.github.io/yotton-exception-sanitizer/

**Fixed-scope paid audit:** https://yotton.monatomicsmaze.workers.dev/#request

**Synthetic six-page sample:** https://yotton.monatomicsmaze.workers.dev/yotton-sample-exception-audit.pdf

## What it does

- Reads one JSON file locally in the browser.
- Hard-caps input at **2 MB / 25 records**.
- Replaces workflow names and IDs with deterministic pseudonyms.
- Replaces raw error text with coarse failure categories.
- Preserves non-weakenable authority boundaries for money, contracts, credentials, identity, deletion, and other protected cases.
- Generates a deterministic ZIP containing exactly:
  - `manifest.json`
  - `exceptions.csv`
  - `SAFETY-RECEIPT.txt`
- Uses no upload endpoint, analytics, cookies, credentials, or production access.

## What it does not prove

This tool is an additional safety layer, not a privacy, security, legal, or compliance certification. It does not prove the original source is safe, repair a workflow, observe a production postcondition, measure recurrence reduction, or establish ROI. Review every generated file before transfer.

The included demo and sample are explicitly synthetic. They are not customer results.

## Supported input shapes

The sanitizer accepts:

- an array of execution/error objects;
- an object containing an array under `executions`, `errors`, `results`, `items`, or `data`;
- one object or one nested `execution` object.

A usable record needs a parseable timestamp and error message. Unsupported records are rejected instead of guessed.

## Run locally

```bash
python3 -m http.server 4173
```

Open `http://localhost:4173/`.

## Verify

```bash
npm test
npm run verify
```

The test suite checks pseudonymization, raw-value exclusion, authority floors, deterministic ZIP members, explicit attestations, the 25-record cap, the absence of browser upload calls, SEO files, and secret-shaped values.

## Security model

- Static files only.
- `connect-src 'none'` Content Security Policy.
- No `fetch`, `XMLHttpRequest`, WebSocket, beacon, or analytics code.
- Local file processing via `File.text()`.
- Generated downloads via in-memory `Blob` URLs.
- Source code is published for inspection; see `LICENSE.md` for use rights.

## Commercial flow

The free sanitizer prepares bounded evidence. The separate **$249 Yotton Exception Audit** turns up to 25 reviewed, sanitized records into a recurrence map, supplied-time cost ranking, authority map, remediation brief, and one reversible fixture-only policy draft when eligible. Fit and safe-data format are confirmed before invoice; the request form does not collect a card.

## Privacy and terms

- https://yotton.monatomicsmaze.workers.dev/privacy
- https://yotton.monatomicsmaze.workers.dev/terms

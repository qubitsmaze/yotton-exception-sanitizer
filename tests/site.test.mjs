import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (name) => readFile(new URL(name, root), "utf8");

test("site is a self-contained local-only acquisition tool", async () => {
  const [html, app] = await Promise.all([read("index.html"), read("app.mjs")]);
  assert.match(html, /Yotton Local Exception Sanitizer/);
  assert.match(html, /Nothing leaves your browser/i);
  assert.match(html, /\$249 Exception Audit/i);
  assert.match(html, /https:\/\/yotton\.monatomicsmaze\.workers\.dev/);
  assert.match(html, /Content-Security-Policy/);
  assert.doesNotMatch(html, /testimonial|guaranteed savings|customer logo/i);
  assert.doesNotMatch(app, /\bfetch\s*\(|XMLHttpRequest|axios|sendBeacon|WebSocket/i);
  assert.match(app, /file\.text\(\)/);
  assert.match(app, /buildSubmissionBundle/);
});

test("SEO and safety support files exist and exclude private surfaces", async () => {
  const [robots, sitemap, readme, indexNow, indexNowKey] = await Promise.all([
    read("robots.txt"),
    read("sitemap.xml"),
    read("README.md"),
    read("scripts/submit-indexnow.mjs"),
    read("978b65cd2ef156f8528da569b9dbb85b.txt"),
  ]);
  assert.match(robots, /Allow: \//);
  assert.match(sitemap, /qubitsmaze\.github\.io\/yotton-exception-sanitizer/);
  assert.match(readme, /No upload/i);
  assert.match(readme, /synthetic/i);
  assert.doesNotMatch(readme, /guarantee|observed ROI/i);
  assert.match(indexNow, /api\.indexnow\.org\/indexnow/);
  assert.match(indexNow, /qubitsmaze\.github\.io\/yotton-exception-sanitizer/);
  assert.equal(indexNowKey.trim(), "978b65cd2ef156f8528da569b9dbb85b");
});

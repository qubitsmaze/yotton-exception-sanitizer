import assert from "node:assert/strict";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const root = new URL("../", import.meta.url);
const required = [
  "index.html",
  "styles.css",
  "app.mjs",
  "sanitizer.mjs",
  "sample-n8n-errors.json",
  "robots.txt",
  "sitemap.xml",
  "README.md",
  "LICENSE.md",
  "978b65cd2ef156f8528da569b9dbb85b.txt",
];
for (const name of required) {
  const file = new URL(name, root);
  const info = await stat(file);
  assert.ok(info.isFile() && info.size > 0, `${name} must be non-empty`);
}
const all = await readdir(root);
assert.equal(all.some((name) => name.startsWith(".env")), false, "no env files may ship");
for (const name of ["index.html", "styles.css", "app.mjs", "sanitizer.mjs", "README.md"]) {
  const text = await readFile(new URL(name, root), "utf8");
  assert.doesNotMatch(text, /(?:sk|pk|rk)_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}/, `${name} contains a token-shaped value`);
}
console.log(`Verified ${required.length} deployable files; no env files or token-shaped values.`);

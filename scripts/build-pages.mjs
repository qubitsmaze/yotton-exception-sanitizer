import { cp, mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(new URL("../", import.meta.url).pathname);
const dist = resolve(root, "dist");
const files = [
  "index.html",
  "styles.css",
  "app.mjs",
  "sanitizer.mjs",
  "sample-n8n-errors.json",
  "robots.txt",
  "sitemap.xml",
  "README.md",
  "LICENSE.md",
];
await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
for (const file of files) {
  await cp(resolve(root, file), resolve(dist, file));
}
await cp(resolve(root, "index.html"), resolve(dist, "404.html"));
console.log(`Built GitHub Pages artifact with ${files.length + 1} files at ${dist}`);

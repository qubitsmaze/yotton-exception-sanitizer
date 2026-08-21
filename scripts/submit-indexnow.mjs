import { readFile } from "node:fs/promises";

const key = (await readFile(new URL("../978b65cd2ef156f8528da569b9dbb85b.txt", import.meta.url), "utf8")).trim();
const page = "https://qubitsmaze.github.io/yotton-exception-sanitizer/";
const payload = {
  host: "qubitsmaze.github.io",
  key,
  keyLocation: `${page}${key}.txt`,
  urlList: [page],
};
const response = await fetch("https://api.indexnow.org/indexnow", {
  method: "POST",
  headers: { "content-type": "application/json; charset=utf-8" },
  body: JSON.stringify(payload),
});
if (![200, 202].includes(response.status)) {
  const text = (await response.text()).slice(0, 500);
  throw new Error(`IndexNow submission failed: HTTP ${response.status} ${text}`);
}
console.log(`IndexNow accepted ${payload.urlList.length} URL(s): HTTP ${response.status}`);

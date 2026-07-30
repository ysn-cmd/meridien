const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

// katana JSONL çıktısı: her satır crawl edilen bir istek
// {"request":{"method":"GET","endpoint":"http://.../x","tag":"link","source":"..."},
//  "response":{"status_code":200,"content_length":842}}
// Tümünü tek JSON.parse ile okumak PATLAR — satır satır ayrıştırıyoruz.

// Dikkat çekici uzantı/yol → severity ipucu (crawl'da riskli dosya görülürse).
const NOTABLE = [
  /\.git/i, /\.env/i, /\.sql$/i, /\.bak$/i, /backup/i, /\/admin/i,
  /\.config$/i, /phpinfo/i, /\.log$/i, /\/api\//i,
];

function parse(raw, target) {
  const seen = new Map(); // endpoint → obje (aynı URL birden çok kez gelebilir)
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try {
      o = JSON.parse(t);
    } catch {
      continue;
    }
    const req = o && o.request;
    const endpoint = req && req.endpoint;
    if (!endpoint) continue;
    if (!seen.has(endpoint)) seen.set(endpoint, o);
  }

  const out = [];
  for (const o of seen.values()) {
    const req = o.request || {};
    const res = o.response || {};
    const url = req.endpoint;
    const notable = NOTABLE.some((re) => re.test(url));
    out.push(
      makeFinding({
        target: target.raw,
        type: "recon",
        severity: notable ? "low" : "info", // riskli görünen URL → low, diğer → info
        title: `Keşfedilen URL: ${req.method || "GET"} ${url}${res.status_code ? ` [${res.status_code}]` : ""}`,
        description: req.source ? `Kaynak: ${req.source}` : "",
        evidence: {
          url,
          method: req.method || "GET",
          status_code: res.status_code || null,
          tag: req.tag || null,
          source: req.source || null,
          content_length: res.content_length || null,
        },
        source_tool: "katana",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "katana",
  category: "recon",
  defaultBin: "katana",
  binEnv: "KATANA_PATH",
  supports: (t) => ["url", "domain"].includes(t.type),
  outputFile: true,
  timeoutMs: 300000,
  buildArgs: (t, { outFile }) => [
    "-u", ensureUrl(t.raw),
    "-jsonl",
    "-silent",
    "-d", "2",            // crawl derinliği
    "-or", "-ob",         // ham request/response ve body'yi at
    "-o", outFile,
  ],
  parse,
});
module.exports.parse = parse; // test için

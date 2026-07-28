const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

// Varsayılan wordlist — Kali'de dirb hazır gelir. FFUF_WORDLIST ile override.
const DEFAULT_WORDLIST =
  process.env.FFUF_WORDLIST || "/usr/share/wordlists/dirb/common.txt";

// Hassas path/dosya kalıpları → bulunursa severity yükseltilir.
const SENSITIVE = [
  /\.git/i, /\.env/i, /\.htpasswd/i, /\.htaccess/i, /\.sql/i, /\.bak$/i,
  /backup/i, /\bconfig\b/i, /phpinfo/i, /php\.ini/i, /phpmyadmin/i,
  /wp-admin/i, /\badmin\b/i, /\.ssh/i, /id_rsa/i, /\.aws/i, /server-status/i,
];

function severityFor(path, status) {
  if (SENSITIVE.some((re) => re.test(path))) return "medium";
  if (status === 403) return "low"; // var ama korumalı — yine de bilgi
  return "info";
}

function parse(raw, target) {
  const data = JSON.parse(raw);
  const results = Array.isArray(data.results) ? data.results : [];
  const out = [];
  for (const r of results) {
    const path = (r.input && r.input.FUZZ) || "";
    const status = r.status;
    out.push(
      makeFinding({
        target: target.raw,
        type: "dast",
        severity: severityFor(path, status),
        title: `Keşfedilen yol: /${path} [${status}]`,
        description: r.redirectlocation ? `Yönlendirme: ${r.redirectlocation}` : "",
        evidence: {
          url: r.url,
          path: `/${path}`,
          status,
          length: r.length,
          words: r.words,
          lines: r.lines,
          content_type: r["content-type"],
          redirect: r.redirectlocation || null,
        },
        source_tool: "ffuf",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "ffuf",
  category: "dast",
  defaultBin: "ffuf",
  binEnv: "FFUF_PATH",
  supports: (t) => ["url", "domain", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 300000,
  buildArgs: (t, { outFile }) => [
    "-u", `${ensureUrl(t.raw).replace(/\/$/, "")}/FUZZ`,
    "-w", DEFAULT_WORDLIST,
    "-mc", "200,204,301,302,307,401,403",
    "-o", outFile,
    "-of", "json",
    "-s",       // sessiz mod (banner/progress yok)
    "-t", "40", // 40 eşzamanlı istek
  ],
  parse,
});
module.exports.parse = parse; // test için

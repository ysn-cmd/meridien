const { createProcessPlugin } = require("../base");
const { makeFinding } = require("../../core/findings");

// npm audit severity → bizim severity şeması (moderate → medium).
const SEV = {
  critical: "critical",
  high: "high",
  moderate: "medium",
  low: "low",
  info: "info",
};

// npm advisory URL'inden GHSA/CVE kimliği çıkarmaya çalış.
function idFromVia(v) {
  const url = v.url || "";
  const ghsa = url.match(/GHSA-[\w-]+/i);
  if (ghsa) return ghsa[0].toUpperCase();
  return null;
}

function parse(raw, target) {
  const data = JSON.parse(raw);
  const vulns = data.vulnerabilities || {};
  const out = [];
  for (const [pkg, info] of Object.entries(vulns)) {
    const via = Array.isArray(info.via) ? info.via : [];
    for (const v of via) {
      // via bazen string (başka pakete zincir) bazen obje (asıl advisory) olur.
      if (typeof v !== "object" || !v.title) continue;
      const cwe = Array.isArray(v.cwe) && v.cwe.length ? v.cwe[0] : null;
      const cve = (v.url || "").match(/CVE-\d{4}-\d+/i);
      out.push(
        makeFinding({
          target: target.raw,
          type: "dependency",
          severity: SEV[v.severity] || SEV[info.severity] || "info",
          title: `${pkg} — ${v.title}`,
          description: v.url ? `Advisory: ${v.url}` : "",
          cve: cve ? cve[0].toUpperCase() : null,
          cwe,
          evidence: {
            paket: pkg,
            etkilenen_surum: v.range || info.range || null,
            advisory: idFromVia(v),
            url: v.url || null,
            cvss: v.cvss && v.cvss.score ? v.cvss.score : null,
            dogrudan_bagimlilik: info.isDirect === true,
          },
          source_tool: "npm-audit",
        })
      );
    }
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "npm-audit",
  category: "dependency",
  defaultBin: "npm",
  binEnv: "NPM_PATH",
  // Kod deposu / dizin hedefleri (package.json içermeli).
  supports: (t) => t.type === "repo",
  outputFile: false, // npm audit JSON'u stdout'a yazar
  timeoutMs: 180000,
  // npm audit, bulunan zafiyet varsa 1 ile çıkar — bunu hata sayma.
  okExitCodes: [1],
  buildArgs: (t) => [
    "audit",
    "--json",
    "--prefix", t.raw,
  ],
  parse,
});
module.exports.parse = parse; // test için

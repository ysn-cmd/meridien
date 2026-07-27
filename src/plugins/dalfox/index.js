const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

// dalfox severity (baş harf büyük) → bizim severity şeması.
const SEV = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
  Info: "info",
};

// type: V = doğrulanmış/tetiklenmiş XSS, R = reflected, G = grep. En kötü V.
function typeLabel(t) {
  if (t === "V") return "Doğrulanmış XSS";
  if (t === "R") return "Reflected XSS";
  if (t === "G") return "Grep eşleşmesi";
  return "XSS bulgusu";
}

function parse(raw, target) {
  const data = JSON.parse(raw);
  const items = Array.isArray(data) ? data : [];
  const out = [];
  for (const it of items) {
    if (!it || !it.type) continue; // sondaki boş {} objesini atla
    // V (doğrulanmış) bir tık yükselt: dalfox Medium dese de tetiklendiyse high.
    let sev = SEV[it.severity] || "medium";
    if (it.type === "V" && (sev === "medium" || sev === "low")) sev = "high";
    out.push(
      makeFinding({
        target: target.raw,
        type: "dast",
        severity: sev,
        title: `${typeLabel(it.type)} — parametre: ${it.param || "?"}`,
        description: it.message_str || it.evidence || "",
        cwe: it.cwe || "CWE-79",
        evidence: {
          param: it.param,
          method: it.method,
          payload: it.payload,
          poc: it.data,
          inject_type: it.inject_type,
        },
        source_tool: "dalfox",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "dalfox",
  category: "dast",
  defaultBin: "dalfox",
  binEnv: "DALFOX_PATH",
  supports: (t) => ["url", "domain", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 300000,
  buildArgs: (t, { outFile }) => [
    "url", ensureUrl(t.raw),
    "--format", "json",
    "--output", outFile,
    "--silence",
    "--no-spinner",
    "--worker", "30",
  ],
  parse,
});
module.exports.parse = parse; // test için

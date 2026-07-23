const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

const CVE_RE = /CVE-\d{4}-\d{4,}/i;

function niktoSeverity(msg) {
  const m = (msg || "").toLowerCase();
  if (/outdated|vulnerab|exploit|injection|traversal|remote code|rce|default (account|password)/.test(m)) {
    return "medium";
  }
  return "low";
}

function shortTitle(msg, id) {
  if (msg) {
    const t = msg.trim().replace(/\s+/g, " ");
    return t.length > 90 ? t.slice(0, 90) + "…" : t;
  }
  return id ? `nikto #${id}` : "nikto bulgusu";
}

function parse(raw, target) {
  const data = JSON.parse(raw);
  const hosts = Array.isArray(data) ? data : [data];
  const out = [];
  for (const h of hosts) {
    const vulns = h.vulnerabilities || h.vulns || [];
    if (!Array.isArray(vulns)) continue;
    for (const v of vulns) {
      const msg = v.msg || v.message || "";
      const cve = (msg.match(CVE_RE) || [])[0] || null;
      out.push(
        makeFinding({
          target: target.raw,
          type: "dast",
          severity: niktoSeverity(msg),
          title: shortTitle(msg, v.id),
          description: msg,
          cve: cve ? cve.toUpperCase() : null,
          evidence: {
            id: v.id,
            method: v.method,
            url: v.url || v.uri,
            references: v.references,
          },
          source_tool: "nikto",
        })
      );
    }
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "nikto",
  category: "dast",
  defaultBin: "nikto",
  binEnv: "NIKTO_PATH",
  supports: (t) => ["url", "domain", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 180000,
  okExitCodes: [1],
  buildArgs: (t, { outFile }) => [
    "-h", ensureUrl(t.raw),
    "-Format", "json",
    "-output", outFile,
    "-maxtime", "120s",
    "-nointeractive",
    "-ask", "no",
  ],
  parse,
});
module.exports.parse = parse; // test için

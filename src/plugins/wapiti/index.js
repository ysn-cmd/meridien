const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

const CAT = {
  "SQL Injection": { sev: "high", cwe: "CWE-89" },
  "Blind SQL Injection": { sev: "high", cwe: "CWE-89" },
  "Cross Site Scripting": { sev: "medium", cwe: "CWE-79" },
  "Stored Cross Site Scripting": { sev: "high", cwe: "CWE-79" },
  "Command execution": { sev: "critical", cwe: "CWE-78" },
  "Path Traversal": { sev: "high", cwe: "CWE-22" },
  "CRLF Injection": { sev: "medium", cwe: "CWE-93" },
  "Server Side Request Forgery": { sev: "high", cwe: "CWE-918" },
  "XML External Entity": { sev: "high", cwe: "CWE-611" },
  "Secure Flag cookie": { sev: "low", cwe: "CWE-614" },
  "HttpOnly Flag cookie": { sev: "low", cwe: "CWE-1004" },
  "Content Security Policy Configuration": { sev: "low", cwe: null },
  "HTTP Secure Headers": { sev: "low", cwe: null },
  "Backup file": { sev: "medium", cwe: "CWE-530" },
  "Weak credentials": { sev: "high", cwe: "CWE-521" },
  "Htaccess Bypass": { sev: "medium", cwe: null },
  "Fingerprint web technology": { sev: "info", cwe: null },
};

function parse(raw, target) {
  const data = JSON.parse(raw);
  const vulns = data.vulnerabilities || {};
  const out = [];
  for (const [category, items] of Object.entries(vulns)) {
    if (!Array.isArray(items)) continue;
    const meta = CAT[category] || { sev: "medium", cwe: null };
    for (const it of items) {
      out.push(
        makeFinding({
          target: target.raw,
          type: "dast",
          severity: meta.sev,
          title: category,
          description: it.info || "",
          cwe: meta.cwe,
          evidence: {
            method: it.method,
            path: it.path,
            parameter: it.parameter,
            module: it.module,
            level: it.level,
          },
          source_tool: "wapiti",
        })
      );
    }
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "wapiti",
  category: "dast",
  defaultBin: "wapiti",
  binEnv: "WAPITI_PATH",
  supports: (t) => ["url", "domain", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 180000,
  buildArgs: (t, { outFile }) => [
    "-u", ensureUrl(t.raw),
    "-f", "json",
    "-o", outFile,
    "--flush-session",
    "--scope", "folder",
    "--max-scan-time", "120",
    "-m", "xss,sql,exec,file,crlf",
    "-d", "2",
    "-v", "0",
  ],
  parse,
});

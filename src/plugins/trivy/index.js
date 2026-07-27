const { createProcessPlugin } = require("../base");
const { makeFinding } = require("../../core/findings");

// trivy severity (BÜYÜK harf) → bizim severity şeması.
const SEV = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  UNKNOWN: "info",
};

function parse(raw, target) {
  const data = JSON.parse(raw);
  const out = [];
  for (const r of data.Results || []) {
    const vulns = r.Vulnerabilities || [];
    for (const v of vulns) {
      const fixed = v.FixedVersion ? ` → düzeltme: ${v.FixedVersion}` : " (düzeltme yok)";
      out.push(
        makeFinding({
          target: target.raw,
          type: "dependency",
          severity: SEV[v.Severity] || "info",
          title: `${v.PkgName} ${v.InstalledVersion} — ${v.VulnerabilityID}`,
          description: v.Title || v.Description || "",
          cve: /^CVE-/i.test(v.VulnerabilityID || "") ? v.VulnerabilityID.toUpperCase() : null,
          cwe: Array.isArray(v.CweIDs) && v.CweIDs.length ? v.CweIDs[0] : null,
          evidence: {
            paket: v.PkgName,
            kurulu_surum: v.InstalledVersion,
            duzeltilmis_surum: v.FixedVersion || null,
            hedef: r.Target,
            durum: v.Status,
            fix: fixed.trim(),
          },
          source_tool: "trivy",
        })
      );
    }
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "trivy",
  category: "dependency",
  defaultBin: "trivy",
  binEnv: "TRIVY_PATH",
  // trivy hem dizin/repo (fs) hem URL değil — kod deposu / dosya yolu hedefleri.
  supports: (t) => ["repo", "domain", "ip", "url"].includes(t.type),
  outputFile: true,
  timeoutMs: 300000,
  buildArgs: (t, { outFile }) => {
    // URL/domain/ip ise image taraması anlamsız; fs (dosya sistemi) taraması yap.
    // repo/dosya yolu hedefleri için fs modu.
    return [
      "fs",
      "--format", "json",
      "--quiet",
      "--scanners", "vuln",
      "--output", outFile,
      t.raw,
    ];
  },
  parse,
});
module.exports.parse = parse; // test için

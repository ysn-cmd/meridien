const { spawn } = require("child_process");
const { makeFinding } = require("../../core/findings");
const { extractCveFromNuclei } = require("../../core/cve");

// Gerçek DAST plugin'i. nuclei'yi çalıştırır ve JSONL çıktısını ortak
// Finding şemasına normalize eder.
//
// Gereksinim: sistemde `nuclei` kurulu ve PATH'te olmalı.
//   https://docs.projectdiscovery.io/tools/nuclei

// nuclei severity → ortak severity eşlemesi
const SEV_MAP = {
  info: "info",
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
  unknown: "info",
};

function runNuclei(url) {
  return new Promise((resolve, reject) => {
    // -jsonl: satır başına bir JSON; -silent: yalnızca sonuç
    const proc = spawn("nuclei", ["-u", url, "-jsonl", "-silent"], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));

    proc.on("error", (e) => reject(new Error(`nuclei çalıştırılamadı: ${e.message}`)));
    proc.on("close", (code) => {
      // nuclei bulgu olmasa da 0 döner; parse hatalarını tolere ederiz.
      if (code !== 0 && !out) {
        return reject(new Error(`nuclei hata koduyla çıktı (${code}): ${err.trim()}`));
      }
      resolve(out);
    });
  });
}

function normalize(rawLine, target) {
  const j = JSON.parse(rawLine);
  const info = j.info || {};
  return makeFinding({
    target: target.raw,
    type: "vuln",
    severity: SEV_MAP[(info.severity || "info").toLowerCase()] || "info",
    title: info.name || j["template-id"] || "nuclei bulgusu",
    description: info.description || "",
    cve: extractCveFromNuclei(j),
    evidence: {
      template: j["template-id"],
      matched_at: j["matched-at"] || j.host,
      tags: info.tags,
    },
    source_tool: "nuclei",
  });
}

const nucleiPlugin = {
  name: "nuclei",

  supports(target) {
    // web hedefleri: url / domain / ip
    return ["url", "domain", "ip"].includes(target.type);
  },

  async run(target) {
    // domain/ip için http(s) öneki ekle
    const url = target.type === "url" ? target.raw : `http://${target.raw}`;
    const out = await runNuclei(url);

    const findings = [];
    for (const line of out.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        findings.push(normalize(trimmed, target));
      } catch {
        // bozuk satırı atla, akışı bozma
      }
    }
    return findings;
  },
};

module.exports = nucleiPlugin;
module.exports.normalize = normalize; // test için dışa aç

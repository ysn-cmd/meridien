const { spawn } = require("child_process");
const { makeFinding } = require("../../core/findings");
const { extractCveFromSemgrep, extractCweFromSemgrep } = require("../../core/cve");

// Gerçek SAST plugin'i. semgrep'i bir kod deposu üzerinde çalıştırır ve
// JSON çıktısını ortak Finding şemasına normalize eder.
//
// Gereksinim: `semgrep` PATH'te olmalı ya da SEMGREP_PATH ile yolu verilmeli.
//   https://semgrep.dev/docs/

// semgrep severity → ortak severity eşlemesi
const SEV_MAP = { ERROR: "high", WARNING: "medium", INFO: "info" };

function runSemgrep(repoPath) {
  return new Promise((resolve, reject) => {
    const bin = process.env.SEMGREP_PATH || "semgrep";
    // --config auto: dile göre kural seti (ilk çalıştırmada ağ gerekir)
    const proc = spawn(
      bin,
      ["--config", "auto", "--json", "--quiet", "--disable-version-check", repoPath],
      { stdio: ["ignore", "pipe", "pipe"] }
    );

    let out = "";
    let err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));

    proc.on("error", (e) => reject(new Error(`semgrep çalıştırılamadı: ${e.message}`)));
    proc.on("close", (code) => {
      // semgrep bulgu bulsa da 0 döner; çıktı yoksa gerçek hata vardır.
      if (!out) {
        return reject(new Error(`semgrep çıktı vermedi (kod ${code}): ${err.trim().slice(0, 200)}`));
      }
      resolve(out);
    });
  });
}

// check_id genelde çok uzun ve noktalı; son parçası okunur kural adıdır.
function ruleName(checkId) {
  const parts = String(checkId || "").split(".");
  return parts[parts.length - 1] || checkId || "semgrep bulgusu";
}

// JSON'ı ortak Finding şemasına çevirir. Yürütmeden ayrı; test edilebilir.
function parseSemgrepJson(jsonStr, target) {
  const data = JSON.parse(jsonStr);
  const results = Array.isArray(data.results) ? data.results : [];

  return results.map((r) => {
    const extra = r.extra || {};
    const severity = SEV_MAP[(extra.severity || "INFO").toUpperCase()] || "info";
    return makeFinding({
      target: target.raw,
      type: "sast",
      severity,
      title: ruleName(r.check_id),
      description: extra.message || "",
      cve: extractCveFromSemgrep(r),
      cwe: extractCweFromSemgrep(r),
      evidence: {
        check_id: r.check_id,
        file: r.path,
        line: r.start && r.start.line,
        code: (extra.lines || "").trim().slice(0, 300),
        cwe: extra.metadata && extra.metadata.cwe,
      },
      source_tool: "semgrep",
    });
  });
}

const semgrepPlugin = {
  name: "semgrep",

  supports(target) {
    // SAST: kod deposu / dosya yolu hedeflerinde çalışır
    return target.type === "repo";
  },

  async run(target) {
    const out = await runSemgrep(target.raw);
    return parseSemgrepJson(out, target);
  },
};

module.exports = semgrepPlugin;
module.exports.parseSemgrepJson = parseSemgrepJson; // test için dışa aç

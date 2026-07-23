const { createProcessPlugin } = require("../base");
const { makeFinding } = require("../../core/findings");

// Sızdırılan sırrı raporda AÇIK GÖSTERMEYİZ — kısmen maskeleriz.
function redact(s) {
  if (!s) return null;
  const str = String(s);
  return str.length <= 8 ? "****" : `${str.slice(0, 4)}…${str.slice(-2)}`;
}

function parse(raw, target) {
  const arr = JSON.parse(raw);
  if (!Array.isArray(arr)) return [];
  return arr.map((x) =>
    makeFinding({
      target: target.raw,
      type: "secrets",
      severity: "high",
      title: `Sızdırılmış sır: ${x.RuleID || x.Description || "bilinmeyen"}`,
      description: x.Description || "",
      evidence: {
        file: x.File,
        line: x.StartLine,
        rule: x.RuleID,
        match: redact(x.Match || x.Secret),
        commit: x.Commit ? String(x.Commit).slice(0, 10) : undefined,
      },
      source_tool: "gitleaks",
    })
  );
}

module.exports = createProcessPlugin({
  name: "gitleaks",
  category: "secrets",
  defaultBin: "gitleaks",
  binEnv: "GITLEAKS_PATH",
  supports: (t) => t.type === "repo",
  outputFile: true,
  timeoutMs: 180000,
  okExitCodes: [1], // sır bulununca 1 döner
  buildArgs: (t, { outFile }) => [
    "detect",
    "--source", t.raw,
    "--no-git", // git geçmişi yerine dosya sistemini tara (git olmayan dizinlerde de çalışır)
    "--report-format", "json",
    "--report-path", outFile,
    "--no-banner",
  ],
  parse,
});
module.exports.parse = parse; // test için

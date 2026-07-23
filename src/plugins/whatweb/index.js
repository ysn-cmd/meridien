const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

// whatweb bir parmak izi (recon) aracıdır: tespit edilen her teknoloji/başlık
// için bir "info" bulgusu üretiriz. Gürültüyü azaltmak için salt konum/dil
// gibi eklentileri atlarız.
const SKIP = new Set(["Country", "IP", "RedirectLocation", "Title", "UncommonHeaders"]);

function summarize(val) {
  if (!val) return null;
  const parts = [];
  if (Array.isArray(val.version) && val.version.length) parts.push("v" + val.version.join("/"));
  if (Array.isArray(val.string) && val.string.length) parts.push(val.string.join(", "));
  return parts.join(" ") || null;
}

function parse(raw, target) {
  const data = JSON.parse(raw);
  const rows = Array.isArray(data) ? data : [data];
  const out = [];
  for (const row of rows) {
    const plugins = row.plugins || {};
    for (const [tech, val] of Object.entries(plugins)) {
      if (SKIP.has(tech)) continue;
      const detail = summarize(val);
      out.push(
        makeFinding({
          target: target.raw,
          type: "recon",
          severity: "info",
          title: `Teknoloji: ${tech}${detail ? " (" + detail + ")" : ""}`,
          description: `whatweb tespiti: ${tech}`,
          evidence: {
            plugin: tech,
            detail,
            http_status: row.http_status,
          },
          source_tool: "whatweb",
        })
      );
    }
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "whatweb",
  category: "recon",
  defaultBin: "whatweb",
  binEnv: "WHATWEB_PATH",
  supports: (t) => ["url", "domain", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 120000,
  buildArgs: (t, { outFile }) => [ensureUrl(t.raw), `--log-json=${outFile}`, "--quiet", "--no-errors"],
  parse,
});
module.exports.parse = parse; // test için

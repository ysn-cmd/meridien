const { createProcessPlugin } = require("../base");
const { makeFinding } = require("../../core/findings");

// subfinder JSONL çıktısı: her satır bir JSON objesi
// {"host":"api.example.com","input":"example.com","source":"crtsh"}
// Tümünü tek JSON.parse ile okumak PATLAR — satır satır ayrıştırıyoruz.
function parse(raw, target) {
  const seen = new Map(); // host → kaynak seti (aynı subdomain birden çok kaynaktan gelebilir)
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let obj;
    try {
      obj = JSON.parse(t);
    } catch {
      continue; // bozuk satırı atla
    }
    if (!obj || !obj.host) continue;
    if (!seen.has(obj.host)) seen.set(obj.host, new Set());
    if (obj.source) seen.get(obj.host).add(obj.source);
  }

  const out = [];
  for (const [host, sources] of seen) {
    const srcList = [...sources];
    out.push(
      makeFinding({
        target: target.raw,
        type: "recon",
        severity: "info", // keşif bilgisi — zafiyet değil
        title: `Subdomain: ${host}`,
        description: srcList.length ? `Kaynak: ${srcList.join(", ")}` : "",
        evidence: { host, sources: srcList },
        source_tool: "subfinder",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "subfinder",
  category: "recon",
  defaultBin: "subfinder",
  binEnv: "SUBFINDER_PATH",
  // Yalnızca domain hedefi anlamlı (URL/IP'de subdomain keşfi yapılmaz).
  supports: (t) => t.type === "domain",
  outputFile: true,
  timeoutMs: 300000,
  buildArgs: (t, { outFile }) => [
    "-d", t.raw,
    "-oJ",
    "-o", outFile,
    "-silent",
  ],
  parse,
});
module.exports.parse = parse; // test için

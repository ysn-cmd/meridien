const { createProcessPlugin } = require("../base");
const { makeFinding } = require("../../core/findings");

// httpx JSONL çıktısı: her satır bir canlı host objesi
// {"url":"https://x","status_code":200,"title":"...","tech":["nginx"],"webserver":"...","location":"..."}
// Tümünü tek JSON.parse ile okumak PATLAR — satır satır ayrıştırıyoruz.
function parse(raw, target) {
  const out = [];
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try {
      o = JSON.parse(t);
    } catch {
      continue;
    }
    if (!o || o.failed || !o.url) continue;

    const sc = o.status_code;
    const tech = Array.isArray(o.tech) ? o.tech : [];
    const parts = [];
    if (sc != null) parts.push(`[${sc}]`);
    if (o.webserver) parts.push(o.webserver);
    if (tech.length) parts.push(`(${tech.slice(0, 6).join(", ")})`);

    out.push(
      makeFinding({
        target: target.raw,
        type: "recon",
        severity: "info", // canlı host + teknoloji bilgisi — keşif verisi
        title: `Canlı: ${o.url} ${parts.join(" ")}`.trim(),
        description: o.title ? `Başlık: ${o.title}` : "",
        evidence: {
          url: o.url,
          status_code: sc,
          webserver: o.webserver || null,
          tech,
          host: o.host,
          port: o.port,
          scheme: o.scheme,
          location: o.location || null,
          cdn: o.cdn_name || null,
          content_length: o.content_length,
        },
        source_tool: "httpx",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "httpx",
  category: "recon",
  // Kali paketi ProjectDiscovery httpx'i "httpx-toolkit" adıyla kurar
  // ("httpx" adı Python httpx'e gidebilir). HTTPX_PATH ile override edilebilir.
  defaultBin: "httpx-toolkit",
  binEnv: "HTTPX_PATH",
  // Tek hedefi probe eder (domain/url/ip). subfinder liste verir; httpx tek host.
  supports: (t) => ["domain", "url", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 180000,
  buildArgs: (t, { outFile }) => [
    "-u", t.raw,
    "-json",
    "-silent",
    "-status-code",
    "-title",
    "-tech-detect",
    "-web-server",
    "-o", outFile,
  ],
  parse,
});

// Zincir modu: bir host listesini tek httpx çalıştırmasında probe eder.
// Orchestrator, subfinder gibi keşif plugin'lerinin (scope'tan geçmiş)
// çıktısını buraya besler. Aynı JSONL parse'ı kullanır.
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

module.exports.runList = async function runList(hosts, { raw }) {
  if (!Array.isArray(hosts) || hosts.length === 0) return [];
  const bin = process.env.HTTPX_PATH || "httpx-toolkit";
  const listFile = path.join(os.tmpdir(), `meridien-httpx-in-${Date.now()}.txt`);
  const outFile = path.join(os.tmpdir(), `meridien-httpx-out-${Date.now()}.json`);
  fs.writeFileSync(listFile, hosts.join("\n"));

  const args = ["-l", listFile, "-json", "-silent", "-status-code",
    "-title", "-tech-detect", "-web-server", "-o", outFile];

  await new Promise((resolve) => {
    const proc = spawn(bin, args, { stdio: ["ignore", "ignore", "ignore"], detached: true });
    const timer = setTimeout(() => { try { process.kill(-proc.pid, "SIGKILL"); } catch {} resolve(); }, 300000);
    proc.on("close", () => { clearTimeout(timer); resolve(); });
    proc.on("error", () => { clearTimeout(timer); resolve(); });
  });

  let out = [];
  try {
    const rawOut = fs.readFileSync(outFile, "utf8");
    out = parse(rawOut, { raw });
  } catch {}
  try { fs.unlinkSync(listFile); } catch {}
  try { fs.unlinkSync(outFile); } catch {}
  return out;
};

module.exports.parse = parse; // test için

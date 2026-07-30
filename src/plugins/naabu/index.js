const { createProcessPlugin } = require("../base");
const { makeFinding } = require("../../core/findings");

// naabu JSONL çıktısı: her satır bir açık port
// {"host":"x","ip":"1.2.3.4","port":80,"protocol":"tcp","tls":false}
// Tümünü tek JSON.parse ile okumak PATLAR — satır satır ayrıştırıyoruz.

// Bilinen riskli/dikkat çekici portlar → küçük bir severity ipucu.
// Port açık olması zafiyet değildir (info), ama bazıları not düşmeye değer.
const NOTABLE = {
  21: "FTP", 23: "Telnet (şifresiz)", 3389: "RDP", 3306: "MySQL",
  5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
  5900: "VNC", 445: "SMB", 139: "NetBIOS",
};

function parse(raw, target) {
  const seen = new Map(); // port → obje (aynı port birden çok kez gelebilir)
  for (const line of raw.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let o;
    try {
      o = JSON.parse(t);
    } catch {
      continue;
    }
    if (!o || o.port == null) continue;
    const key = `${o.host || o.ip}:${o.port}`;
    if (!seen.has(key)) seen.set(key, o);
  }

  const out = [];
  for (const o of seen.values()) {
    const note = NOTABLE[o.port];
    out.push(
      makeFinding({
        target: target.raw,
        type: "recon",
        severity: note ? "low" : "info", // dikkat çekici servis → low, diğer → info
        title: `Açık port: ${o.port}/${o.protocol || "tcp"}${note ? ` (${note})` : ""}`,
        description: o.tls ? "TLS aktif" : "",
        evidence: {
          host: o.host || null,
          ip: o.ip || null,
          port: o.port,
          protocol: o.protocol || "tcp",
          tls: o.tls === true,
          servis: note || null,
        },
        source_tool: "naabu",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "naabu",
  category: "recon",
  defaultBin: "naabu",
  binEnv: "NAABU_PATH",
  supports: (t) => ["domain", "ip"].includes(t.type),
  outputFile: true,
  timeoutMs: 300000,
  buildArgs: (t, { outFile }) => [
    "-host", t.raw,
    "-json",
    "-silent",
    "-o", outFile,
  ],
  parse,
});
module.exports.parse = parse; // test için

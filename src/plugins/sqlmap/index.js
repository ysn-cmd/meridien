const { createProcessPlugin, ensureUrl } = require("../base");
const { makeFinding } = require("../../core/findings");

// sqlmap JSON vermez — stdout'taki "injection point(s)" özetini metin parse ederiz.
// Format:
//   Parameter: id (GET)
//       Type: boolean-based blind
//       Title: AND boolean-based blind - WHERE or HAVING clause
//       Payload: id=1 AND 7933=7933
//       (bir parametre birden çok Type bloğu içerebilir)
//
// GÜVENLİK: bu plugin TESPİT-ONLY. --batch ile interaktif değil; --dump,
// --os-shell gibi sömürü bayrakları ASLA kullanılmaz. Sadece "açık mı" der.
function parse(raw, target) {
  const out = [];
  // Her "Parameter: X (Y)" bloğunu yakala.
  const paramRe = /Parameter:\s*([^\(]+?)\s*\(([^)]+)\)([\s\S]*?)(?=Parameter:|---|\n\[|$)/g;
  let m;
  while ((m = paramRe.exec(raw)) !== null) {
    const param = m[1].trim();
    const place = m[2].trim(); // GET / POST / Cookie ...
    const body = m[3];

    // Blok içindeki teknikleri topla.
    const types = [...body.matchAll(/Type:\s*(.+)/g)].map((x) => x[1].trim());
    const titles = [...body.matchAll(/Title:\s*(.+)/g)].map((x) => x[1].trim());
    const payloads = [...body.matchAll(/Payload:\s*(.+)/g)].map((x) => x[1].trim());

    out.push(
      makeFinding({
        target: target.raw,
        type: "dast",
        severity: "high", // SQL injection ciddi zafiyet
        title: `SQL Injection: '${param}' parametresi (${place})`,
        description: types.length ? `Teknik(ler): ${types.join("; ")}` : "SQL injection tespit edildi",
        cwe: "CWE-89",
        evidence: {
          parametre: param,
          konum: place,
          teknikler: types,
          basliklar: titles,
          ornek_payload: payloads[0] || null,
        },
        source_tool: "sqlmap",
      })
    );
  }
  return out;
}

module.exports = createProcessPlugin({
  name: "sqlmap",
  category: "dast",
  defaultBin: "sqlmap",
  binEnv: "SQLMAP_PATH",
  // URL'de parametre gerekir (?id=1 gibi). Domain/IP tek başına anlamsız.
  supports: (t) => t.type === "url",
  outputFile: false,     // stdout parse ediyoruz
  timeoutMs: 900000,     // 15 dk — sqlmap yavaş bir araç
  okExitCodes: [0, 1],   // bulamazsa da hata sayma
  buildArgs: (t) => [
    "-u", ensureUrl(t.raw),
    "--batch",           // interaktif DEĞİL
    "--level=2",
    "--risk=2",
    "--flush-session",
    "--disable-coloring", // temiz metin çıktı (ANSI kod yok)
    // NOT: --dump / --os-shell / --dbs gibi sömürü bayrakları BİLİNÇLİ olarak YOK.
    // Bu plugin sadece tespit yapar.
  ],
  parse,
});
module.exports.parse = parse; // test için

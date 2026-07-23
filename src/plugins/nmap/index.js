const { spawn } = require("child_process");
const { XMLParser } = require("fast-xml-parser");
const { makeFinding } = require("../../core/findings");

// Gerçek recon plugin'i. nmap'i XML çıktısıyla çalıştırır ve açık
// portları/servisleri ortak Finding şemasına normalize eder.
//
// Gereksinim: sistemde `nmap` kurulu ve PATH'te olmalı.

// Bazı riskli/eski servisleri düşük seviyede işaretle; geri kalan açık
// portlar bilgilendirme (info) seviyesindedir.
const RISKY_SERVICES = {
  telnet: "low",   // şifresiz
  ftp: "low",      // şifresiz
  rlogin: "low",
  rsh: "low",
  vnc: "low",
};

function hostFromTarget(target) {
  // url ise host kısmını çıkar, değilse olduğu gibi kullan
  if (target.type === "url") {
    try {
      return new URL(target.raw).hostname;
    } catch {
      return target.raw;
    }
  }
  return target.raw;
}

function runNmap(host) {
  return new Promise((resolve, reject) => {
    // -Pn: host discovery atla (belirli izinli hedef)
    // -sV: servis/sürüm tespiti
    // -oX -: XML çıktısını stdout'a ver
    const proc = spawn("nmap", ["-Pn", "-sV", "-oX", "-", host], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    proc.stdout.on("data", (d) => (out += d.toString()));
    proc.stderr.on("data", (d) => (err += d.toString()));

    proc.on("error", (e) => reject(new Error(`nmap çalıştırılamadı: ${e.message}`)));
    proc.on("close", (code) => {
      if (code !== 0 && !out) {
        return reject(new Error(`nmap hata koduyla çıktı (${code}): ${err.trim()}`));
      }
      resolve(out);
    });
  });
}

// XML'i ortak Finding şemasına çevirir. Test edilebilir olması için
// yürütmeden ayrı tutulmuştur.
function parseNmapXml(xml, target) {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "" });
  const doc = parser.parse(xml);

  const hosts = [].concat(doc?.nmaprun?.host || []);
  const findings = [];

  for (const host of hosts) {
    const ports = [].concat(host?.ports?.port || []);
    for (const p of ports) {
      const state = p.state?.state;
      if (state !== "open") continue;

      const svc = p.service || {};
      const name = svc.name || "unknown";
      const versionParts = [svc.product, svc.version].filter(Boolean).join(" ");
      const severity = RISKY_SERVICES[name] || "info";

      findings.push(
        makeFinding({
          target: target.raw,
          type: "recon",
          severity,
          title: `Açık port: ${p.portid}/${p.protocol} (${name})`,
          description: versionParts
            ? `${name} servisi tespit edildi: ${versionParts}`
            : `${name} servisi tespit edildi.`,
          evidence: {
            port: Number(p.portid),
            protocol: p.protocol,
            service: name,
            product: svc.product || null,
            version: svc.version || null,
          },
          source_tool: "nmap",
        })
      );
    }
  }

  return findings;
}

const nmapPlugin = {
  name: "nmap",
  category: "recon",

  supports(target) {
    // recon: domain / ip / url hedeflerinde çalışır (repo/kod hariç)
    return ["domain", "ip", "url"].includes(target.type);
  },

  async run(target) {
    const host = hostFromTarget(target);
    const xml = await runNmap(host);
    return parseNmapXml(xml, target);
  },
};

module.exports = nmapPlugin;
module.exports.parseNmapXml = parseNmapXml; // test için dışa aç

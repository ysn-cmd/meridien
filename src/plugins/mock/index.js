const { makeFinding } = require("../../core/findings");

// Test/geliştirme plugin'i. Gerçek bir araç çalıştırmaz; sabit örnek
// bulgular döner. Amacı, gerçek araçlar (nuclei, nmap ...) kurulu
// olmadan uçtan uca akışı doğrulamaktır. Üretimde kaldırılır/kapatılır.
const mockPlugin = {
  name: "mock",

  supports() {
    return true; // her hedefi kabul eder
  },

  async run(target) {
    return [
      makeFinding({
        target: target.raw,
        type: "vuln",
        severity: "high",
        title: "Örnek: eksik güvenlik başlığı",
        description: "Content-Security-Policy başlığı bulunamadı (örnek bulgu).",
        evidence: { header: "Content-Security-Policy", present: false },
        source_tool: "mock",
      }),
      makeFinding({
        target: target.raw,
        type: "recon",
        severity: "info",
        title: "Örnek: açık port",
        description: "443/tcp açık (örnek bulgu).",
        evidence: { port: 443, service: "https" },
        source_tool: "mock",
      }),
      makeFinding({
        target: target.raw,
        type: "dependency",
        severity: "critical",
        title: "Örnek: zafiyetli bağımlılık",
        description: "lodash@4.17.19 bilinen bir zafiyet içeriyor (örnek bulgu).",
        evidence: { package: "lodash", version: "4.17.19", advisory: "GHSA-xxxx" },
        source_tool: "mock",
      }),
    ];
  },
};

module.exports = mockPlugin;

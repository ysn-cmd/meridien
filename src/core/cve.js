// CVE çıkarım ve doğrulama yardımcıları. Tek dosyada toplandı ki
// bağımsız test edilebilsin ve ileride zenginleştirme (CVSS, NVD referans
// çekme vb.) buraya eklensin — plugin'lere dağılmasın.

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i;

function isCve(s) {
  return typeof s === "string" && CVE_REGEX.test(s.trim());
}

// nuclei bulgu JSON'undan CVE kimliğini çıkarır. Bulamazsa null döner.
// Kaynak önceliği: classification.cve-id → doğrudan CVE olan template-id.
function extractCveFromNuclei(j) {
  const info = j.info || {};
  const cls = info.classification || {};
  const cveId = cls["cve-id"];

  if (Array.isArray(cveId) && cveId.length && isCve(cveId[0])) {
    return String(cveId[0]).toUpperCase();
  }
  if (isCve(cveId)) {
    return String(cveId).toUpperCase();
  }

  const tid = j["template-id"] || "";
  if (isCve(tid)) return tid.toUpperCase();

  return null;
}

module.exports = { CVE_REGEX, isCve, extractCveFromNuclei };

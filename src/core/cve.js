// CVE çıkarım ve doğrulama yardımcıları. Tek dosyada toplandı ki
// bağımsız test edilebilsin ve ileride zenginleştirme (CVSS, NVD referans
// çekme vb.) buraya eklensin — plugin'lere dağılmasın.
//cwe de buraya eklendi fix icin meridien/src/core/cve

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

// semgrep bulgusundan CVE çıkarır (varsa metadata.cve alanında).
function extractCveFromSemgrep(result) {
  const md = (result && result.extra && result.extra.metadata) || {};
  const cve = md.cve;
  if (Array.isArray(cve) && cve.length && isCve(cve[0])) return String(cve[0]).toUpperCase();
  if (isCve(cve)) return String(cve).toUpperCase();
  return null;
}

// --- CWE (zafiyet sınıfı) ---
// CVE spesifik bir yayınlanmış zafiyettir; CWE ise zafiyetin türüdür
// (ör. CWE-78 = OS command injection). semgrep bulguları genelde CWE taşır.
const CWE_REGEX = /CWE-\d+/i;

function normalizeCwe(v) {
  const s = Array.isArray(v) ? v[0] : v;
  const m = String(s || "").match(CWE_REGEX);
  return m ? m[0].toUpperCase() : null;
}

function extractCweFromSemgrep(result) {
  const md = (result && result.extra && result.extra.metadata) || {};
  return normalizeCwe(md.cwe);
}

module.exports = {
  CVE_REGEX,
  CWE_REGEX,
  isCve,
  extractCveFromNuclei,
  extractCveFromSemgrep,
  normalizeCwe,
  extractCweFromSemgrep,
};

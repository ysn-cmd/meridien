const crypto = require("crypto");

// Severity seviyeleri — sıralama skorlama ve özet için kullanılır.
const SEVERITY = ["info", "low", "medium", "high", "critical"];
const SEVERITY_RANK = Object.fromEntries(SEVERITY.map((s, i) => [s, i]));

// Ortak Finding şeması. TÜM plugin'ler bu yapıyı döner.
// Sistemin "ortak dili" budur; çekirdek yalnızca bu şemayı tanır.
function makeFinding({
  target,
  type,
  severity = "info",
  title,
  description = "",
  evidence = {},
  source_tool,
}) {
  if (!SEVERITY.includes(severity)) severity = "info";
  return {
    id: crypto.randomUUID(),
    target,
    type,            // recon | vuln | dependency ...
    severity,        // info | low | medium | high | critical
    title,
    description,
    evidence,        // araca özgü kanıt (port, istek/yanıt, kod satırı ...)
    source_tool,     // bulguyu üreten araç (nuclei, nmap, semgrep ...)
    timestamp: new Date().toISOString(),
  };
}

// Bir bulgu dizisinden severity dağılımı çıkarır → {critical: 2, high: 5, ...}
function severitySummary(findings) {
  const summary = {};
  for (const f of findings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
  }
  return summary;
}

// Bulguları en yüksek severity üstte olacak şekilde sıralar.
function sortBySeverity(findings) {
  return [...findings].sort(
    (a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0)
  );
}

// Hedefi normalize eder ve tipini belirler (plugin'ler supports() içinde kullanır).
function classifyTarget(raw) {
  const value = String(raw).trim();
  let type;
  if (/^https?:\/\//i.test(value)) type = "url";
  else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) type = "ip";
  else if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) type = "domain";
  else type = "repo"; // aksi halde kod deposu / dosya yolu varsayılır
  return { raw: value, type };
}

// Bir bulgunun tekillik imzası. Aynı imzaya sahip bulgular "aynı"
// kabul edilir. evidence dahil edildiği için farklı port/başlık/şablon
// ayrı kalır; yalnızca birebir aynılar birleşir.
function fingerprint(f) {
  const ev = JSON.stringify(f.evidence || {}, Object.keys(f.evidence || {}).sort());
  return [f.source_tool, f.type, f.severity, f.title, ev].join("|");
}

// Tekrarlayan bulguları birleştirir. Silmez — temsilciyi tutar ve kaç
// kez göründüğünü evidence.occurrences alanına yazar (>1 ise).
function dedupe(findings) {
  const seen = new Map();
  for (const f of findings) {
    const key = fingerprint(f);
    if (seen.has(key)) {
      seen.get(key)._count += 1;
    } else {
      seen.set(key, { ...f, _count: 1 });
    }
  }
  return [...seen.values()].map(({ _count, ...f }) => {
    if (_count > 1) f.evidence = { ...f.evidence, occurrences: _count };
    return f;
  });
}

module.exports = {
  SEVERITY,
  SEVERITY_RANK,
  makeFinding,
  severitySummary,
  sortBySeverity,
  classifyTarget,
  dedupe,
};

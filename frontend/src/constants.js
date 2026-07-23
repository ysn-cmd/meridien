export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const SEV_COLOR = {
  critical: "#b91c1c",
  high: "#dc2626",
  medium: "#d97706",
  low: "#0891b2",
  info: "#6b7280",
};

export const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function fmtDate(iso) {
  if (!iso) return "-";
  try {
    return new Date(iso).toLocaleString("tr-TR");
  } catch {
    return iso;
  }
}

// Kategori başlık etiketleri + gösterim sırası (rapor ile aynı).
export const CATEGORY_LABEL = {
  recon: "Keşif (Recon)",
  dast: "Dinamik Test (DAST)",
  sast: "Kod Analizi (SAST)",
  secrets: "Sızan Sırlar (Secrets)",
  dependency: "Bağımlılık",
  other: "Diğer",
};
export const CATEGORY_ORDER = ["dast", "sast", "secrets", "recon", "dependency", "other"];

// Bulguları kategoriye göre gruplar; her grup severity sıralı (yüksek üstte).
export function groupByCategory(findings, sevRank) {
  const groups = {};
  for (const f of findings) {
    const key = f.category || "other";
    (groups[key] ||= []).push(f);
  }
  const ordered = [];
  const seen = new Set();
  for (const cat of CATEGORY_ORDER) {
    if (groups[cat]) { ordered.push([cat, groups[cat]]); seen.add(cat); }
  }
  for (const cat of Object.keys(groups)) {
    if (!seen.has(cat)) ordered.push([cat, groups[cat]]);
  }
  return ordered.map(([cat, items]) => [
    cat,
    [...items].sort((a, b) => (sevRank[b.severity] ?? 0) - (sevRank[a.severity] ?? 0)),
  ]);
}

const fs = require("fs");
const path = require("path");

// Raporlama katmanı. Bir tarama işini + Finding[] alır, çıktı üretir.
// Plugin'leri TANIMAZ — yalnızca ortak Finding şemasını tanır. Bu yüzden
// yeni plugin eklendiğinde bu dosyaya dokunmak gerekmez.

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLOR = {
  critical: "#b91c1c",
  high: "#dc2626",
  medium: "#d97706",
  low: "#0891b2",
  info: "#6b7280",
};

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityBadges(summary) {
  return SEV_ORDER.filter((s) => summary[s])
    .map(
      (s) =>
        `<span class="badge" style="background:${SEV_COLOR[s]}">${s.toUpperCase()}: ${summary[s]}</span>`
    )
    .join("");
}

// Kategori başlık etiketleri (finding.category → görünen ad).
const CATEGORY_LABEL = {
  recon: "Keşif (Recon)",
  dast: "Dinamik Test (DAST)",
  sast: "Kod Analizi (SAST)",
  secrets: "Sızan Sırlar (Secrets)",
  dependency: "Bağımlılık",
};
const CATEGORY_ORDER = ["dast", "sast", "secrets", "recon", "dependency"];

// Bulguları kategoriye göre gruplar; her grup kendi içinde severity sıralı.
function groupByCategory(findings) {
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
  return ordered;
}

function findingsByCategory(findings) {
  const groups = groupByCategory(findings);
  return groups
    .map(([cat, items]) => {
      const label = CATEGORY_LABEL[cat] || (cat === "other" ? "Diğer" : cat);
      const sorted = [...items].sort(
        (a, b) => (SEV_ORDER.indexOf(a.severity)) - (SEV_ORDER.indexOf(b.severity))
      );
      return `
    <div class="cat-group">
      <h2 class="cat-head">${esc(label)} <span class="cat-count">${items.length}</span></h2>
      ${sorted.map(findingCard).join("")}
    </div>`;
    })
    .join("");
}

function findingCard(f) {
  const color = SEV_COLOR[f.severity] || "#6b7280";
  const ev = { ...(f.evidence || {}) };
  const occ = ev.occurrences;
  delete ev.occurrences; // rozet olarak ayrı gösteriyoruz
  const evStr = Object.keys(ev).length ? JSON.stringify(ev, null, 2) : "";
  // uzun açıklamaları kısalt — rapor okunabilirliği + sayfalama için
  const desc =
    f.description && f.description.length > 400
      ? f.description.slice(0, 400).trimEnd() + "…"
      : f.description;
  return `
    <div class="finding" style="border-left-color:${color}">
      <div class="finding-head">
        <span class="sev" style="background:${color}">${esc(f.severity.toUpperCase())}</span>
        <span class="title">${esc(f.title)}</span>
        <span class="src">${esc(f.source_tool)}</span>
        ${f.cve ? `<span class="cve">${esc(f.cve)}</span>` : ""}
        ${f.cwe ? `<span class="cwe">${esc(f.cwe)}</span>` : ""}
        ${occ ? `<span class="occ">×${occ}</span>` : ""}
      </div>
      ${desc ? `<div class="desc">${esc(desc)}</div>` : ""}
      ${evStr ? `<pre class="evidence">${esc(evStr)}</pre>` : ""}
    </div>`;
}

function diffLine(f) {
  const color = SEV_COLOR[f.severity] || "#6b7280";
  return `<li>
    <span class="mini-sev" style="background:${color}">${esc(f.severity.toUpperCase())}</span>
    ${esc(f.title)}
    <span class="src">${esc(f.source_tool)}</span>
    ${f.cve ? `<span class="cve">${esc(f.cve)}</span>` : ""}
  </li>`;
}

// Önceki taramaya göre değişiklikler. diff yoksa (ilk tarama) veya boşsa
// uygun mesajı gösterir.
function diffSection(diff) {
  if (!diff) {
    return `<div class="diff-empty">İlk tarama — karşılaştırılacak önceki tarama yok.</div>`;
  }
  const { added = [], removed = [] } = diff;
  if (!added.length && !removed.length) {
    return `<div class="diff-empty">Önceki taramaya göre değişiklik yok.</div>`;
  }
  return `
  <div class="diff">
    <h2>Değişiklikler <span class="diff-counts">+${added.length} yeni · −${removed.length} kapanan</span></h2>
    ${added.length ? `<div class="diff-group added"><h3>Yeni bulgular (+${added.length})</h3><ul>${added.map(diffLine).join("")}</ul></div>` : ""}
    ${removed.length ? `<div class="diff-group removed"><h3>Kapanan bulgular (−${removed.length})</h3><ul>${removed.map(diffLine).join("")}</ul></div>` : ""}
  </div>`;
}

function buildHtml(job, findings, diff) {
  const summary = job.severity_summary || {};
  const generated = new Date().toLocaleString("tr-TR");
  return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Meridien Raporu — ${esc(job.target)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; color: #1f2937; margin: 0; padding: 24px 32px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #6b7280; font-size: 13px; margin-bottom: 14px; }
  .meta { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; font-size: 13px; margin-bottom: 14px; }
  .meta dt { color: #6b7280; }
  .meta dd { margin: 0; font-family: ui-monospace, monospace; }
  .badges { margin: 8px 0 16px; }
  .badge { display: inline-block; color: #fff; font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 4px; margin-right: 6px; }
  .finding { border: 1px solid #e5e7eb; border-left-width: 4px; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; page-break-inside: avoid; }
  .finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .sev { color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; }
  .title { font-weight: 600; font-size: 14px; }
  .src { color: #6b7280; font-size: 12px; font-family: ui-monospace, monospace; }
  .occ { background: #111827; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 10px; }
  .cve { background: #7c3aed; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; font-family: ui-monospace, monospace; }
  .cwe { background: #b45309; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; font-family: ui-monospace, monospace; }
  .desc { color: #374151; font-size: 13px; margin-top: 6px; line-height: 1.5; }
  .evidence { background: #f9fafb; border: 1px solid #f0f0f0; border-radius: 4px; padding: 8px 10px; font-size: 11px; margin: 8px 0 0; overflow-x: auto; white-space: pre-wrap; }
  .cat-group { margin-bottom: 18px; }
  .cat-head { font-size: 15px; margin: 18px 0 8px; padding-bottom: 4px; border-bottom: 2px solid #e5e7eb; color: #111827; }
  .cat-count { font-size: 12px; font-weight: 600; color: #6b7280; background: #f3f4f6; padding: 2px 9px; border-radius: 10px; margin-left: 6px; }
  .footer { color: #9ca3af; font-size: 11px; margin-top: 28px; border-top: 1px solid #e5e7eb; padding-top: 10px; }
  .diff { border: 1px solid #e5e7eb; border-radius: 6px; padding: 4px 16px 12px; margin-bottom: 24px; background: #fafafa; }
  .diff h2 { font-size: 15px; margin: 12px 0 8px; }
  .diff-counts { font-size: 12px; font-weight: 600; color: #6b7280; margin-left: 6px; }
  .diff-group { margin: 8px 0; }
  .diff-group h3 { font-size: 12px; margin: 6px 0; text-transform: uppercase; letter-spacing: 0.03em; }
  .diff-group.added h3 { color: #15803d; }
  .diff-group.removed h3 { color: #6b7280; }
  .diff-group ul { list-style: none; padding: 0; margin: 0; }
  .diff-group li { font-size: 13px; padding: 4px 0 4px 10px; border-left: 3px solid transparent; margin-bottom: 3px; }
  .diff-group.added li { border-left-color: #22c55e; }
  .diff-group.removed li { border-left-color: #9ca3af; color: #6b7280; }
  .mini-sev { color: #fff; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 3px; margin-right: 4px; }
  .diff-empty { color: #6b7280; font-size: 13px; font-style: italic; margin-bottom: 24px; }
</style>
</head>
<body>
  <h1>Meridien — Güvenlik Tarama Raporu</h1>
  <div class="sub">Hedef: <strong>${esc(job.target)}</strong></div>

  <dl class="meta">
    <dt>Durum</dt><dd>${esc(job.status)}</dd>
    <dt>Tarama ID</dt><dd>${esc(job.id)}</dd>
    <dt>Plugin'ler</dt><dd>${esc((job.plugins || []).join(", "))}</dd>
    <dt>Başlatan</dt><dd>${esc(job.created_by || "-")}</dd>
    <dt>Başlangıç</dt><dd>${esc(job.started_at || "-")}</dd>
    <dt>Bitiş</dt><dd>${esc(job.finished_at || "-")}</dd>
    <dt>Toplam bulgu</dt><dd>${esc(job.findings_count ?? findings.length)}</dd>
  </dl>

  <div class="badges">${severityBadges(summary) || '<span class="sub">Bulgu yok</span>'}</div>

  ${diffSection(diff)}

  ${findingsByCategory(findings)}

  <div class="footer">Meridien tarafından üretildi — ${esc(generated)}</div>
</body>
</html>`;
}

// HTML'i PDF'e çevirir. Puppeteer yalnızca burada, tembel (lazy) yüklenir;
// böylece PDF olmasa bile HTML üretimi hiçbir bağımlılığa muhtaç değildir.
async function htmlToPdf(html, outPath) {
  const puppeteer = require("puppeteer");
  const browser = await puppeteer.launch({
    headless: "new",
    // Sistem chromium'unu kullan (arm64/Kali'de Puppeteer'ın kendi Chromium'u
    // uyumsuz olabiliyor). Gerekirse CHROME_PATH ile override edilir.
    executablePath: process.env.CHROME_PATH || "/usr/bin/chromium",
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: "networkidle0" });
    await page.pdf({
      path: outPath,
      format: "A4",
      printBackground: true,
      margin: { top: "18mm", bottom: "18mm", left: "14mm", right: "14mm" },
    });
  } finally {
    await browser.close();
  }
}

// Ana giriş: HTML'i her zaman yazar; PDF'i dener, başarısız olursa uyarır
// ama işi düşürmez.
async function writeReport(job, findings, { dir = "reports", diff = null } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const base = path.join(dir, `report-${job.id}`);
  const html = buildHtml(job, findings, diff);
  const htmlPath = `${base}.html`;
  fs.writeFileSync(htmlPath, html);

  let pdfPath = `${base}.pdf`;
  try {
    await htmlToPdf(html, pdfPath);
  } catch (e) {
    pdfPath = null;
    console.error(`PDF üretilemedi (HTML hazır): ${e.message}`);
  }
  return { htmlPath, pdfPath };
}

module.exports = { buildHtml, writeReport, groupByCategory };

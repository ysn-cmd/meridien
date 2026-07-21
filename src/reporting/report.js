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

function findingCard(f) {
  const color = SEV_COLOR[f.severity] || "#6b7280";
  const ev = { ...(f.evidence || {}) };
  const occ = ev.occurrences;
  delete ev.occurrences; // rozet olarak ayrı gösteriyoruz
  const evStr = Object.keys(ev).length ? JSON.stringify(ev, null, 2) : "";
  return `
    <div class="finding" style="border-left-color:${color}">
      <div class="finding-head">
        <span class="sev" style="background:${color}">${esc(f.severity.toUpperCase())}</span>
        <span class="title">${esc(f.title)}</span>
        <span class="src">${esc(f.source_tool)}</span>
        ${f.cve ? `<span class="cve">${esc(f.cve)}</span>` : ""}
        ${occ ? `<span class="occ">×${occ}</span>` : ""}
      </div>
      ${f.description ? `<div class="desc">${esc(f.description)}</div>` : ""}
      ${evStr ? `<pre class="evidence">${esc(evStr)}</pre>` : ""}
    </div>`;
}

function buildHtml(job, findings) {
  const summary = job.severity_summary || {};
  const generated = new Date().toLocaleString("tr-TR");
  return `<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Meridien Raporu — ${esc(job.target)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, sans-serif; color: #1f2937; margin: 0; padding: 32px; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: #6b7280; font-size: 13px; margin-bottom: 20px; }
  .meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; font-size: 13px; margin-bottom: 20px; }
  .meta dt { color: #6b7280; }
  .meta dd { margin: 0; font-family: ui-monospace, monospace; }
  .badges { margin: 12px 0 24px; }
  .badge { display: inline-block; color: #fff; font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 4px; margin-right: 6px; }
  .finding { border: 1px solid #e5e7eb; border-left-width: 4px; border-radius: 6px; padding: 12px 14px; margin-bottom: 10px; page-break-inside: avoid; }
  .finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .sev { color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; }
  .title { font-weight: 600; font-size: 14px; }
  .src { color: #6b7280; font-size: 12px; font-family: ui-monospace, monospace; }
  .occ { background: #111827; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 10px; }
  .cve { background: #7c3aed; color: #fff; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; font-family: ui-monospace, monospace; }
  .desc { color: #374151; font-size: 13px; margin-top: 6px; line-height: 1.5; }
  .evidence { background: #f9fafb; border: 1px solid #f0f0f0; border-radius: 4px; padding: 8px 10px; font-size: 11px; margin: 8px 0 0; overflow-x: auto; white-space: pre-wrap; }
  .footer { color: #9ca3af; font-size: 11px; margin-top: 28px; border-top: 1px solid #e5e7eb; padding-top: 10px; }
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

  ${findings.map(findingCard).join("")}

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
async function writeReport(job, findings, { dir = "reports" } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const base = path.join(dir, `report-${job.id}`);
  const html = buildHtml(job, findings);
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

module.exports = { buildHtml, writeReport };
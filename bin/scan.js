#!/usr/bin/env node
require("dotenv").config();
const path = require("path");
const registry = require("../src/plugins/register");
const { loadScope } = require("../src/core/scope");
const { openDb } = require("../src/store/db");
const { runScan } = require("../src/core/orchestrator");
const { writeReport, meetsMinSeverity, SEV_ORDER } = require("../src/reporting/report");
const { diffFindings } = require("../src/core/diff");
const { alertOnNewFindings } = require("../src/alerting/checkAlert");
const { AppError } = require("../src/errors/AppError");

function parseArgs(argv) {
  const args = { user: "cli", plugins: null, categories: null, scope: null, report: false, reportDir: "reports", alert: false, minSeverity: "medium", minSeverityExplicit: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--target" || a === "-t") args.target = argv[++i];
    else if (a === "--user" || a === "-u") args.user = argv[++i];
    else if (a === "--plugins" || a === "-p") args.plugins = argv[++i].split(",");
    else if (a === "--category" || a === "-c") args.categories = argv[++i].split(",");
    else if (a === "--scope" || a === "-s") args.scope = argv[++i];
    else if (a === "--report" || a === "-r") args.report = true;
    else if (a === "--report-dir") args.reportDir = argv[++i];
    else if (a === "--alert") args.alert = true;
    else if (a === "--min-severity") { args.minSeverity = argv[++i]; args.minSeverityExplicit = true; }
  }
  return args;
}

function resolvePluginNames(args) {
  if (!args.categories) return args.plugins;
  const valid = registry.categories();
  const names = new Set(args.plugins || []);
  for (const cat of args.categories) {
    const c = cat.trim();
    if (!valid.includes(c)) {
      throw new AppError(
        `Geçersiz kategori: "${c}". Mevcut kategoriler: ${valid.join(", ")}`,
        400
      );
    }
    for (const n of registry.namesByCategory(c)) names.add(n);
  }
  return [...names];
}

const COLORS = {
  critical: "\x1b[41m\x1b[97m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";

function printResults({ job, findings, pluginResults }, reportMinSeverity = null) {
  console.log(`\nTarama işi: ${job.id}`);
  console.log(`Hedef: ${job.target}   Durum: ${job.status}`);
  console.log(`Plugin'ler: ${job.plugins.join(", ")}`);
  for (const r of pluginResults) {
    console.log(
      r.ok
        ? `  ✓ ${r.plugin}: ${r.count} bulgu`
        : `  ✗ ${r.plugin}: ${r.error}`
    );
  }
  console.log(`\nÖzet: ${JSON.stringify(job.severity_summary)}`);
  console.log(`Toplam bulgu: ${job.findings_count}\n`);

  const shown = reportMinSeverity
    ? findings.filter((f) => meetsMinSeverity(f.severity, reportMinSeverity))
    : findings;
  for (const f of shown) {
    const c = COLORS[f.severity] || "";
    const cve = f.cve ? ` \x1b[45m\x1b[97m ${f.cve} \x1b[0m` : "";
    const times = f.evidence?.occurrences ? ` \x1b[1m×${f.evidence.occurrences}\x1b[0m` : "";
    console.log(`${c}[${f.severity.toUpperCase()}]${RESET} ${f.title}  (${f.source_tool})${cve}${times}`);
    if (f.description) console.log(`   ${f.description}`);
  }
  const hidden = findings.length - shown.length;
  if (hidden) console.log(`  (${hidden} bulgu --min-severity=${reportMinSeverity} altında → gizlendi)`);
  console.log("");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.target) {
    console.error("Kullanım: node bin/scan.js --target <hedef> [--user <ad>] [--plugins mock,nuclei] [--category dast,recon] [--scope scope.yaml]");
    process.exit(1);
  }

  const reportMinSeverity = args.minSeverityExplicit ? args.minSeverity : null;
  if (reportMinSeverity && !SEV_ORDER.includes(reportMinSeverity)) {
    console.error(`Geçersiz --min-severity: "${reportMinSeverity}". Seçenekler: ${SEV_ORDER.join(", ")}`);
    process.exit(1);
  }

  const scopePath = args.scope || path.join(__dirname, "..", "scope.yaml");
  const scope = loadScope(scopePath);
  const store = openDb();

  try {
    const pluginNames = resolvePluginNames(args);
    const result = await runScan({
      rawTarget: args.target,
      scope,
      store,
      createdBy: args.user,
      pluginNames,
    });
    printResults(result, reportMinSeverity);

    if (args.report) {
      let diff = null;
      const prev = store.getPreviousJob(result.job.target, result.job.started_at, result.job.plugins);
      if (prev) {
        diff = diffFindings(result.findings, store.getFindings(prev.id));
        console.log(`Önceki taramaya göre: +${diff.added.length} yeni, −${diff.removed.length} kapanan\n`);
      }
      const { htmlPath, pdfPath } = await writeReport(result.job, result.findings, {
        dir: args.reportDir,
        diff,
        minSeverity: reportMinSeverity,
      });
      console.log(`Rapor (HTML): ${htmlPath}`);
      if (pdfPath) console.log(`Rapor (PDF):  ${pdfPath}`);
      console.log("");
    }

    if (args.alert) {
      const { added, alertable } = await alertOnNewFindings({
        job: result.job,
        findings: result.findings,
        store,
        minSeverity: args.minSeverity,
      });
      if (alertable.length) {
        console.log(`Alarm: ${added.length} yeni bulgu, ${alertable.length} tanesi ${args.minSeverity}+ → e-posta gönderildi\n`);
      } else {
        console.log(`Alarm: ${added.length} yeni bulgu, ${args.minSeverity}+ eşiğini geçen yok → e-posta gönderilmedi\n`);
      }
    }
  } catch (err) {
    if (err instanceof AppError) {
      console.error(`\n[REDDEDİLDİ ${err.code}] ${err.message}\n`);
      process.exit(err.code === 403 ? 3 : 2);
    }
    throw err;
  } finally {
    store.close();
  }
}

main().catch((e) => {
  console.error("Beklenmeyen hata:", e);
  process.exit(1);
});

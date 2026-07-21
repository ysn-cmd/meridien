#!/usr/bin/env node
const path = require("path");
const registry = require("../src/core/pluginRegistry");
const { loadScope } = require("../src/core/scope");
const { openDb } = require("../src/store/db");
const { runScan } = require("../src/core/orchestrator");
const { writeReport } = require("../src/reporting/report");
const { diffFindings } = require("../src/core/diff");
const { AppError } = require("../src/errors/AppError");

// --- Plugin kayıt (registry) ---
// Yeni plugin eklemek = burada register etmek. Çekirdeğe dokunulmaz.
registry.register(require("../src/plugins/mock"));
registry.register(require("../src/plugins/nuclei"));
registry.register(require("../src/plugins/nmap"));
registry.register(require("../src/plugins/semgrep"));

// --- Basit argüman ayrıştırma ---
function parseArgs(argv) {
  const args = { user: "cli", plugins: null, scope: null, report: false, reportDir: "reports" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--target" || a === "-t") args.target = argv[++i];
    else if (a === "--user" || a === "-u") args.user = argv[++i];
    else if (a === "--plugins" || a === "-p") args.plugins = argv[++i].split(",");
    else if (a === "--scope" || a === "-s") args.scope = argv[++i];
    else if (a === "--report" || a === "-r") args.report = true;
    else if (a === "--report-dir") args.reportDir = argv[++i];
  }
  return args;
}

const COLORS = {
  critical: "\x1b[41m\x1b[97m",
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};
const RESET = "\x1b[0m";

function printResults({ job, findings, pluginResults }) {
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

  for (const f of findings) {
    const c = COLORS[f.severity] || "";
    const cve = f.cve ? ` \x1b[45m\x1b[97m ${f.cve} \x1b[0m` : "";
    const times = f.evidence?.occurrences ? ` \x1b[1m×${f.evidence.occurrences}\x1b[0m` : "";
    console.log(`${c}[${f.severity.toUpperCase()}]${RESET} ${f.title}  (${f.source_tool})${cve}${times}`);
    if (f.description) console.log(`   ${f.description}`);
  }
  console.log("");
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.target) {
    console.error("Kullanım: node bin/scan.js --target <hedef> [--user <ad>] [--plugins mock,nuclei] [--scope scope.yaml]");
    process.exit(1);
  }

  const scopePath = args.scope || path.join(__dirname, "..", "scope.yaml");
  const scope = loadScope(scopePath);
  const store = openDb();

  try {
    const result = await runScan({
      rawTarget: args.target,
      scope,
      store,
      createdBy: args.user,
      pluginNames: args.plugins,
    });
    printResults(result);

    if (args.report) {
      // Önceki taramayla karşılaştır (aynı hedef). Yoksa diff null kalır.
      let diff = null;
      const prev = store.getPreviousJob(result.job.target, result.job.started_at, result.job.plugins);
      if (prev) {
        diff = diffFindings(result.findings, store.getFindings(prev.id));
        console.log(`Önceki taramaya göre: +${diff.added.length} yeni, −${diff.removed.length} kapanan\n`);
      }
      const { htmlPath, pdfPath } = await writeReport(result.job, result.findings, {
        dir: args.reportDir,
        diff,
      });
      console.log(`Rapor (HTML): ${htmlPath}`);
      if (pdfPath) console.log(`Rapor (PDF):  ${pdfPath}`);
      console.log("");
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

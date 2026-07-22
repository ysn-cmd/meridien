require("dotenv").config();
const fs = require("fs");
const path = require("path");
const YAML = require("yaml");
const cron = require("node-cron");

require("../plugins/register"); // plugin'leri kaydet
const { loadScope } = require("../core/scope");
const { openDb } = require("../store/db");
const { runScan } = require("../core/orchestrator");
const { alertOnNewFindings } = require("../alerting/checkAlert");

const SCHEDULE_PATH = process.env.SCHEDULE || path.join(__dirname, "..", "..", "schedule.yaml");
const SCOPE_PATH = process.env.SCOPE || path.join(__dirname, "..", "..", "scope.yaml");

function loadSchedule() {
  if (!fs.existsSync(SCHEDULE_PATH)) {
    throw new Error(`schedule.yaml bulunamadı: ${SCHEDULE_PATH}`);
  }
  const parsed = YAML.parse(fs.readFileSync(SCHEDULE_PATH, "utf8")) || {};
  return {
    jobs: Array.isArray(parsed.jobs) ? parsed.jobs : [],
    minSeverity: (parsed.alert && parsed.alert.min_severity) || "medium",
  };
}

// Bir zamanlanmış işi çalıştırır: tara → önceki (aynı plugin seti) ile diff
// → yeni bulguları severity eşiğine göre süz → e-posta.
async function runJob(job, { scope, store, minSeverity }) {
  const stamp = new Date().toLocaleString("tr-TR");
  console.log(`[${stamp}] Tarama: ${job.target} (${(job.plugins || []).join(",")})`);
  try {
    const result = await runScan({
      rawTarget: job.target,
      scope,
      store,
      createdBy: "scheduler",
      pluginNames: job.plugins,
    });

    if (job.alert) {
      const { added, alertable } = await alertOnNewFindings({
        job: result.job,
        findings: result.findings,
        store,
        minSeverity,
      });
      console.log(`  → ${result.findings.length} bulgu, ${added.length} yeni, ${alertable.length} alarmlık (${minSeverity}+)`);
      if (alertable.length) {
        console.log(`  → ALARM: ${alertable.length} yeni bulgu için e-posta gönderildi`);
      }
    } else {
      console.log(`  → ${result.findings.length} bulgu (alarm kapalı)`);
    }
  } catch (e) {
    console.error(`  ✗ hata: ${e.message}`);
  }
}

async function main() {
  const runOnce = process.argv.includes("--once");
  const { jobs, minSeverity } = loadSchedule();
  const scope = loadScope(SCOPE_PATH);
  const store = openDb();

  if (!jobs.length) {
    console.log("schedule.yaml'da tanımlı iş yok.");
    return;
  }

  if (runOnce) {
    console.log(`--once: ${jobs.length} iş bir kez çalıştırılıyor (alarm eşiği: ${minSeverity}+)...\n`);
    for (const job of jobs) await runJob(job, { scope, store, minSeverity });
    store.close();
    console.log("\nBitti.");
    return;
  }

  for (const job of jobs) {
    if (!job.cron || !cron.validate(job.cron)) {
      console.error(`Geçersiz/eksik cron: "${job.cron}" (${job.target}) — atlandı`);
      continue;
    }
    cron.schedule(job.cron, () => runJob(job, { scope, store, minSeverity }));
    console.log(`Zamanlandı: ${job.target} [${job.cron}]`);
  }
  console.log(`\nMeridien scheduler çalışıyor (alarm eşiği: ${minSeverity}+). Durdurmak için Ctrl+C.`);
}

main().catch((e) => {
  console.error("Scheduler hatası:", e.message);
  process.exit(1);
});

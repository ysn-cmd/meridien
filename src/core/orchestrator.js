const crypto = require("crypto");
const { classifyTarget, severitySummary, sortBySeverity, dedupe } = require("./findings");
const { assertInScope } = require("./scope");
const registry = require("./pluginRegistry");
const { AppError } = require("../errors/AppError");

// Tek bir tarama işini uçtan uca yürütür:
//   kapsam kontrolü → plugin seçimi → sıralı yürütme → normalizasyon
//   → depolama → özet.
//
// Bir plugin çökerse iş komple durmaz; o adım "başarısız" işaretlenip
// akış devam eder (hata yönetimi).
async function runScan({ rawTarget, scope, store, createdBy = "cli", pluginNames = null }) {
  const startedAt = new Date().toISOString();

  // Kademe 1-4: kapsam + girdi doğrulama. Geçemezse iş hiç başlamaz.
  const target = assertInScope(rawTarget, scope); // AppError fırlatabilir
  const classified = classifyTarget(target);

  const plugins = registry.applicable(classified, pluginNames);
  if (plugins.length === 0) {
    throw new AppError(`Bu hedef tipini (${classified.type}) işleyen plugin yok`, 400);
  }

  const job = {
    id: crypto.randomUUID(),
    target,
    status: "running",
    plugins: plugins.map((p) => p.name),
    created_by: createdBy,
    started_at: startedAt,
    finished_at: null,
    findings_count: 0,
    severity_summary: {},
    error: null,
  };

  const allFindings = [];
  const pluginResults = [];

  for (const plugin of plugins) {
    try {
      const findings = (await plugin.run(classified)) || [];
      // Plugin'in kategorisini bulgulara bas (rapor/dashboard gruplaması için).
      // Plugin kendi finding'inde category vermişse ona dokunma.
      for (const f of findings) {
        if (f.category == null) f.category = plugin.category || null;
      }
      allFindings.push(...findings);
      pluginResults.push({ plugin: plugin.name, ok: true, count: findings.length });
    } catch (err) {
      // Bir aracın çökmesi tüm işi düşürmez.
      pluginResults.push({ plugin: plugin.name, ok: false, error: err.message });
    }
  }

  const deduped = dedupe(allFindings);
  const sorted = sortBySeverity(deduped);
  job.finished_at = new Date().toISOString();
  job.findings_count = sorted.length;
  job.severity_summary = severitySummary(sorted);
  job.status = pluginResults.every((r) => !r.ok) ? "failed" : "completed";
  if (job.status === "failed") {
    job.error = "Tüm plugin'ler başarısız oldu";
  }

  // Depolama
  store.saveJob(job);
  store.saveFindings(job.id, sorted);

  return { job, findings: sorted, pluginResults };
}

module.exports = { runScan };

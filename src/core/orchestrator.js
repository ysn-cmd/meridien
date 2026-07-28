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

  // --- Plugin zinciri ---
  // Keşifçi plugin'ler (feedsTo tanımlı) yeni host'lar bulmuş olabilir.
  // Bunları scope'tan geçirip hedef plugin'e (ör. httpx) liste olarak besle.
  const selectedNames = new Set(plugins.map((p) => p.name));
  for (const plugin of plugins) {
    if (!plugin.feedsTo) continue;
    const targetPlugin = registry.all().find((p) => p.name === plugin.feedsTo);
    // Hedef plugin bu taramada seçili değilse ya da liste modu yoksa atla.
    if (!selectedNames.has(plugin.feedsTo) || !targetPlugin || typeof targetPlugin.runList !== "function") {
      continue;
    }

    // Bu keşifçinin ürettiği host'ları topla (evidence.host).
    const discovered = allFindings
      .filter((f) => f.source_tool === plugin.name && f.evidence && f.evidence.host)
      .map((f) => f.evidence.host);

    // Scope filtresi: keşfedilen her host allowlist'e uymalı — dışındakiler atılır.
    const inScope = [];
    for (const host of [...new Set(discovered)]) {
      try {
        assertInScope(host, scope);
        inScope.push(host);
      } catch {
        // scope dışı keşif — sessizce atla (güvenlik sınırı)
      }
    }

    if (inScope.length === 0) continue;

    try {
      const chainFindings = (await targetPlugin.runList(inScope, { raw: target })) || [];
      for (const f of chainFindings) {
        if (f.category == null) f.category = targetPlugin.category || null;
        // Zincirden geldiğini işaretle (rapor/dashboard için).
        f.evidence = { ...(f.evidence || {}), zincir: `${plugin.name}→${plugin.feedsTo}` };
      }
      allFindings.push(...chainFindings);
      // pluginResults'ta zincir sonucunu ayrıca göster.
      const existing = pluginResults.find((r) => r.plugin === plugin.feedsTo);
      if (existing) existing.count += chainFindings.length;
      else pluginResults.push({ plugin: `${plugin.feedsTo} (zincir)`, ok: true, count: chainFindings.length });
    } catch (err) {
      pluginResults.push({ plugin: `${plugin.feedsTo} (zincir)`, ok: false, error: err.message });
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

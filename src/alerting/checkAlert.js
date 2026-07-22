const { diffFindings } = require("../core/diff");
const { SEVERITY_RANK } = require("../core/findings");
const { notify } = require("./notifier");

// Bir taramanın YENİ bulgularını (aynı-plugin-setli önceki taramaya göre)
// severity eşiğine göre süzer; eşiği geçen varsa e-posta atar.
// Hem scheduler hem CLI (--alert) bunu kullanır.
async function alertOnNewFindings({ job, findings, store, minSeverity = "medium" }) {
  const prev = store.getPreviousJob(job.target, job.started_at, job.plugins);
  const diff = prev ? diffFindings(findings, store.getFindings(prev.id)) : null;
  const added = diff ? diff.added : [];

  const min = SEVERITY_RANK[minSeverity] ?? 2;
  const alertable = added.filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= min);

  if (alertable.length) await notify(job, alertable);
  return { added, alertable };
}

module.exports = { alertOnNewFindings };

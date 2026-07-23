const path = require("path");
const Database = require("better-sqlite3");

// Basit veri erişim soyutlaması. Doğrudan SQL yalnızca burada bulunur;
// çekirdek ve plugin'ler bu fonksiyonlar üzerinden erişir.
function openDb(dbPath = path.join(__dirname, "..", "..", "data", "secscan.db")) {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL"); // yazma güvenliği + eşzamanlı okuma

  db.exec(`
    CREATE TABLE IF NOT EXISTS scan_jobs (
      id               TEXT PRIMARY KEY,
      target           TEXT NOT NULL,
      status           TEXT NOT NULL,
      plugins          TEXT,
      created_by       TEXT,
      started_at       TEXT,
      finished_at      TEXT,
      findings_count   INTEGER DEFAULT 0,
      severity_summary TEXT,
      error            TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
      id          TEXT PRIMARY KEY,
      job_id      TEXT NOT NULL,
      target      TEXT,
      type        TEXT,
      severity    TEXT,
      title       TEXT,
      description TEXT,
      evidence    TEXT,
      source_tool TEXT,
      category    TEXT,
      timestamp   TEXT,
      FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
    CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
  `);

  // Migration: eski findings tablosunda category kolonu yoksa ekle.
  const cols = db.prepare("PRAGMA table_info(findings)").all().map((c) => c.name);
  if (!cols.includes("category")) {
    db.exec("ALTER TABLE findings ADD COLUMN category TEXT");
  }

  const insertJob = db.prepare(`
    INSERT INTO scan_jobs
      (id, target, status, plugins, created_by, started_at, finished_at,
       findings_count, severity_summary, error)
    VALUES
      (@id, @target, @status, @plugins, @created_by, @started_at, @finished_at,
       @findings_count, @severity_summary, @error)
  `);

  const insertFinding = db.prepare(`
    INSERT INTO findings
      (id, job_id, target, type, severity, title, description, evidence,
       source_tool, category, timestamp)
    VALUES
      (@id, @job_id, @target, @type, @severity, @title, @description, @evidence,
       @source_tool, @category, @timestamp)
  `);

  // DB satırındaki JSON kolonlarını (plugins, severity_summary) nesneye çevirir.
  function parseJobRow(row) {
    if (!row) return row;
    let plugins = [];
    let severity_summary = {};
    try { plugins = JSON.parse(row.plugins || "[]"); } catch {}
    try { severity_summary = JSON.parse(row.severity_summary || "{}"); } catch {}
    return { ...row, plugins, severity_summary };
  }

  return {
    raw: db,

    saveJob(job) {
      insertJob.run({
        ...job,
        plugins: JSON.stringify(job.plugins || []),
        severity_summary: JSON.stringify(job.severity_summary || {}),
        error: job.error || null,
      });
    },

    saveFindings(jobId, findings) {
      const tx = db.transaction((rows) => {
        for (const f of rows) {
          insertFinding.run({
            ...f,
            job_id: jobId,
            evidence: JSON.stringify(f.evidence || {}),
            category: f.category ?? null,
          });
        }
      });
      tx(findings);
    },

    getJob(id) {
      return parseJobRow(db.prepare("SELECT * FROM scan_jobs WHERE id = ?").get(id));
    },

    // Tüm tarama işleri, en yeni üstte (dashboard listesi için).
    listJobs() {
      return db
        .prepare("SELECT * FROM scan_jobs ORDER BY started_at DESC")
        .all()
        .map(parseJobRow);
    },

    // Aynı hedefin, verilen zamandan ÖNCEKI en son tamamlanmış taraması.
    // plugins verilirse, yalnızca AYNI plugin setiyle yapılmış taramayı
    // seçer (elmayla elmayı kıyaslamak için) — böylece farklı plugin
    // setleri sahte "yeni/kapanan" gürültüsü üretmez.
    getPreviousJob(target, beforeStartedAt, plugins) {
      const rows = db
        .prepare(
          `SELECT * FROM scan_jobs
           WHERE target = ? AND status = 'completed' AND started_at < ?
           ORDER BY started_at DESC`
        )
        .all(target, beforeStartedAt)
        .map(parseJobRow);

      if (!plugins) return rows[0] || null; // geriye dönük uyumluluk
      const key = [...plugins].sort().join(",");
      return rows.find((r) => [...(r.plugins || [])].sort().join(",") === key) || null;
    },

    // Bir taramanın bulgularını döner; evidence JSON'u nesneye çözülür
    // (fingerprint karşılaştırması için gerekli).
    getFindings(jobId) {
      const rows = db.prepare("SELECT * FROM findings WHERE job_id = ?").all(jobId);
      return rows.map((r) => {
        let evidence = {};
        try {
          evidence = JSON.parse(r.evidence || "{}");
        } catch {}
        return { ...r, evidence };
      });
    },

    close() {
      db.close();
    },
  };
}

module.exports = { openDb };

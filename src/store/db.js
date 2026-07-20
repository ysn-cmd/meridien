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
      timestamp   TEXT,
      FOREIGN KEY (job_id) REFERENCES scan_jobs(id)
    );

    CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id);
    CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
  `);

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
       source_tool, timestamp)
    VALUES
      (@id, @job_id, @target, @type, @severity, @title, @description, @evidence,
       @source_tool, @timestamp)
  `);

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
          });
        }
      });
      tx(findings);
    },

    getJob(id) {
      return db.prepare("SELECT * FROM scan_jobs WHERE id = ?").get(id);
    },

    close() {
      db.close();
    },
  };
}

module.exports = { openDb };

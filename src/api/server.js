const path = require("path");
const express = require("express");
const { openDb } = require("../store/db");
const { diffFindings } = require("../core/diff");
const registry = require("../plugins/register");

// Meridien API sunucusu. SQLite'taki tarama verisini JSON olarak sunar ve
// statik dashboard'u servis eder. Dashboard aynı origin'den çektiği için
// CORS gerekmez.

const app = express();
const store = openDb();

// --- API ---

// Kayıtlı plugin'ler ve kategorileri. Dashboard'un kategori/plugin
// seçimini kurabilmesi için read-only liste.
app.get("/api/plugins", (req, res) => {
  try {
    const plugins = registry.all().map((p) => ({
      name: p.name,
      category: p.category || null,
    }));
    res.json({ categories: registry.categories(), plugins });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Tüm taramalar (liste) — en yeni üstte
app.get("/api/scans", (req, res) => {
  try {
    res.json(store.listJobs());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Tek tarama: iş + bulguları + önceki taramaya göre diff
app.get("/api/scans/:id", (req, res) => {
  try {
    const job = store.getJob(req.params.id);
    if (!job) return res.status(404).json({ error: "Tarama bulunamadı" });

    const findings = store.getFindings(job.id);

    let diff = null;
    const prev = store.getPreviousJob(job.target, job.started_at, job.plugins);
    if (prev) {
      diff = diffFindings(findings, store.getFindings(prev.id));
      diff = {
        previousJobId: prev.id,
        added: diff.added,
        removed: diff.removed,
      };
    }

    res.json({ job, findings, diff });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// --- Statik dashboard (public/index.html) ---
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
// Varsayılan olarak yalnızca localhost'a bağlan — tarama sonuçları hassas
// veridir, tüm ağa açılmamalı. Bilinçli olarak dışarı açmak için HOST=0.0.0.0.
const HOST = process.env.HOST || "127.0.0.1";
app.listen(PORT, HOST, () => {
  console.log(`Meridien API + dashboard: http://${HOST}:${PORT}`);
});

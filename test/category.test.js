const { test } = require("node:test");
const assert = require("node:assert");
const { makeFinding } = require("../src/core/findings");

// register.js tüm plugin'leri kaydeder; registry'yi onun üzerinden alıyoruz
// ki gerçek kayıtlı set üzerinde test edelim.
const registry = require("../src/plugins/register");

test("registry.categories() bilinen kategorileri sıralı döner", () => {
  const cats = registry.categories();
  for (const c of ["dast", "recon", "sast", "secrets"]) {
    assert.ok(cats.includes(c), `kategori eksik: ${c}`);
  }
  // sıralı olmalı
  assert.deepEqual(cats, [...cats].sort());
});

test("registry.namesByCategory('dast') doğru plugin'leri döner", () => {
  const names = registry.namesByCategory("dast");
  for (const n of ["nuclei", "nikto", "wapiti"]) {
    assert.ok(names.includes(n), `dast plugin eksik: ${n}`);
  }
  // recon plugin'i dast'ta olmamalı
  assert.ok(!names.includes("whatweb"));
});

test("registry.namesByCategory geçersiz kategori için boş dizi döner", () => {
  assert.deepEqual(registry.namesByCategory("saçmalık"), []);
});

test("makeFinding category alanını taşır, default null", () => {
  const withCat = makeFinding({ title: "t", source_tool: "x", category: "dast" });
  assert.equal(withCat.category, "dast");
  const without = makeFinding({ title: "t", source_tool: "x" });
  assert.equal(without.category, null);
});

// report.js'teki groupByCategory saf bir fonksiyon; dışa aktarılmışsa test et.
const report = require("../src/reporting/report");
if (typeof report.groupByCategory === "function") {
  test("groupByCategory kategoriye göre gruplar ve sırayı korur", () => {
    const findings = [
      { severity: "info", category: "recon" },
      { severity: "critical", category: "dast" },
      { severity: "low", category: "dast" },
      { severity: "high", category: "secrets" },
      { severity: "info", category: null },
    ];
    const groups = report.groupByCategory(findings);
    const order = groups.map(([cat]) => cat);
    // dast > secrets > recon > other sırası (CATEGORY_ORDER)
    assert.deepEqual(order, ["dast", "secrets", "recon", "other"]);
    // dast grubu severity sıralı: critical önce, low sonra
    const dast = groups.find(([c]) => c === "dast")[1];
    assert.equal(dast[0].severity, "critical");
    assert.equal(dast[1].severity, "low");
  });
}

// --- Yeni plugin parse testleri (dalfox, trivy) ---
const dalfox = require("../src/plugins/dalfox");
const trivy = require("../src/plugins/trivy");
const tgt = { raw: "http://x" };

test("dalfox parse: doğrulanmış (V) XSS high'a yükselir, CWE-79", () => {
  const raw = JSON.stringify([
    { type: "V", severity: "Medium", param: "q", payload: "<svg onload=alert(1)>", cwe: "CWE-79", method: "GET", data: "http://x?q=..." },
    {},
  ]);
  const out = dalfox.parse(raw, tgt);
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, "high");
  assert.equal(out[0].cwe, "CWE-79");
  assert.equal(out[0].source_tool, "dalfox");
});

test("dalfox parse: reflected (R) medium kalır", () => {
  const raw = JSON.stringify([{ type: "R", severity: "Medium", param: "q", cwe: "CWE-79" }]);
  const out = dalfox.parse(raw, tgt);
  assert.equal(out[0].severity, "medium");
});

test("trivy parse: CVE + severity + CWE eşlemesi", () => {
  const raw = JSON.stringify({
    Results: [{
      Target: "package-lock.json",
      Vulnerabilities: [
        { VulnerabilityID: "CVE-2019-10744", PkgName: "lodash", InstalledVersion: "4.17.4", FixedVersion: "4.17.12", Severity: "HIGH", Title: "prototype pollution", CweIDs: ["CWE-1321"] },
      ],
    }],
  });
  const out = trivy.parse(raw, tgt);
  assert.equal(out.length, 1);
  assert.equal(out[0].severity, "high");
  assert.equal(out[0].cve, "CVE-2019-10744");
  assert.equal(out[0].cwe, "CWE-1321");
  assert.equal(out[0].source_tool, "trivy");
});

test("trivy parse: zafiyet yoksa boş dizi", () => {
  const raw = JSON.stringify({ Results: [{ Target: "x", Packages: [] }] });
  assert.deepEqual(trivy.parse(raw, tgt), []);
});

// --- Yeni plugin parse testleri (dalfox, trivy) ---

// --- subfinder parse testi ---
const subfinderPlugin = require("../src/plugins/subfinder");

test("subfinder parse: JSONL satirlari, host birlestirme, hepsi info", () => {
  const raw = [
    '{"host":"a.example.com","input":"example.com","source":"crtsh"}',
    '{"host":"a.example.com","input":"example.com","source":"submd"}',
    '{"host":"b.example.com","input":"example.com","source":"thc"}',
    '',
    'bozuk-satir-atlanir',
  ].join("\n");
  const out = subfinderPlugin.parse(raw, { raw: "example.com" });
  assert.equal(out.length, 2); // a ve b, a iki kaynaktan tek finding
  assert.ok(out.every((f) => f.severity === "info"));
  assert.ok(out.every((f) => f.source_tool === "subfinder"));
  const a = out.find((f) => f.title.includes("a.example.com"));
  assert.equal(a.evidence.sources.length, 2); // crtsh + submd birlesti
});

// --- httpx parse testi ---
const httpxPlugin = require("../src/plugins/httpx");

test("httpx parse: JSONL, canli host info, failed atlanir", () => {
  const raw = [
    '{"url":"https://a.example.com","status_code":200,"title":"A","webserver":"nginx","tech":["nginx","PHP"],"host":"a.example.com","port":"443","scheme":"https","failed":false}',
    '{"url":"https://dead.example.com","failed":true}',
    '',
  ].join("\n");
  const out = httpxPlugin.parse(raw, { raw: "example.com" });
  assert.equal(out.length, 1); // failed olan atlandi
  assert.equal(out[0].severity, "info");
  assert.equal(out[0].source_tool, "httpx");
  assert.equal(out[0].evidence.status_code, 200);
  assert.deepEqual(out[0].evidence.tech, ["nginx", "PHP"]);
});

// --- npm-audit parse testi ---
const npmAuditPlugin = require("../src/plugins/npm-audit");

test("npm-audit parse: via[] her advisory ayri finding, moderate→medium", () => {
  const raw = JSON.stringify({
    vulnerabilities: {
      lodash: {
        name: "lodash", severity: "critical", isDirect: true, range: "<4.17.21",
        via: [
          { title: "Command Injection in lodash", url: "https://github.com/advisories/GHSA-35jh-r3h4-6jhm", severity: "high", cwe: ["CWE-77"], cvss: { score: 7.2 } },
          { title: "Prototype Pollution in lodash", url: "https://github.com/advisories/GHSA-fvqr-27wr-82fm", severity: "moderate", cwe: ["CWE-1321"], cvss: { score: 6.5 } },
          "minimist",
        ],
      },
    },
  });
  const out = npmAuditPlugin.parse(raw, { raw: "/tmp/x" });
  assert.equal(out.length, 2); // string via ("minimist") atlandi
  assert.equal(out[0].severity, "high");
  assert.equal(out[1].severity, "medium"); // moderate → medium
  assert.equal(out[1].cwe, "CWE-1321");
  assert.ok(out.every((f) => f.source_tool === "npm-audit"));
});

// --- Zincir mekanizması testi ---
const httpxForChain = require("../src/plugins/httpx");
const subfinderForChain = require("../src/plugins/subfinder");

test("zincir: subfinder feedsTo httpx, httpx runList mevcut", () => {
  assert.equal(subfinderForChain.feedsTo, "httpx");
  assert.equal(typeof httpxForChain.runList, "function");
});

test("zincir: base factory feedsTo alanini plugin objesine tasir", () => {
  // nmap gibi feedsTo tanimlamayan plugin null olmali (undefined degil)
  const nmap = require("../src/plugins/nmap");
  assert.equal(nmap.feedsTo, null);
});

// --- ffuf parse testi ---
const ffufPlugin = require("../src/plugins/ffuf");

test("ffuf parse: hassas path medium, 403 low, siradan info", () => {
  const raw = JSON.stringify({
    results: [
      { input: { FUZZ: ".htpasswd" }, status: 403, url: "http://x/.htpasswd", length: 10, "content-type": "text/html" },
      { input: { FUZZ: "phpinfo.php" }, status: 200, url: "http://x/phpinfo.php", length: 500 },
      { input: { FUZZ: ".hta" }, status: 403, url: "http://x/.hta", length: 10 },
      { input: { FUZZ: "robots.txt" }, status: 200, url: "http://x/robots.txt", length: 20 },
    ],
  });
  const out = ffufPlugin.parse(raw, { raw: "http://x" });
  assert.equal(out.length, 4);
  assert.equal(out[0].severity, "medium"); // .htpasswd (hassas)
  assert.equal(out[1].severity, "medium"); // phpinfo (hassas)
  assert.equal(out[2].severity, "low");    // .hta 403
  assert.equal(out[3].severity, "info");   // robots.txt sıradan
  assert.ok(out.every((f) => f.source_tool === "ffuf"));
});

// --- naabu parse testi ---
const naabuPlugin = require("../src/plugins/naabu");

test("naabu parse: JSONL portlar, dikkat cekici servis low, digeri info", () => {
  const raw = [
    '{"host":"x","ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}',
    '{"host":"x","ip":"1.2.3.4","port":6379,"protocol":"tcp","tls":false}',
    '{"host":"x","ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}',
    '',
  ].join("\n");
  const out = naabuPlugin.parse(raw, { raw: "x" });
  assert.equal(out.length, 2); // 22 tekrari birlesti
  const redis = out.find((f) => f.evidence.port === 6379);
  assert.equal(redis.severity, "low"); // Redis dikkat cekici
  const ssh = out.find((f) => f.evidence.port === 22);
  assert.equal(ssh.severity, "info"); // siradan
  assert.ok(out.every((f) => f.source_tool === "naabu"));
});

// --- katana parse testi ---
const katanaPlugin = require("../src/plugins/katana");

test("katana parse: JSONL nested, endpoint tekillestirme, riskli path low", () => {
  const raw = [
    '{"request":{"method":"GET","endpoint":"http://x/login.php"},"response":{"status_code":200}}',
    '{"request":{"method":"GET","endpoint":"http://x/login.php"},"response":{"status_code":200}}',
    '{"request":{"method":"GET","endpoint":"http://x/.git/config"},"response":{"status_code":200}}',
    '',
  ].join("\n");
  const out = katanaPlugin.parse(raw, { raw: "http://x" });
  assert.equal(out.length, 2); // login.php tekrari birlesti
  const git = out.find((f) => f.evidence.url.includes(".git"));
  assert.equal(git.severity, "low"); // .git riskli
  const login = out.find((f) => f.evidence.url.includes("login.php"));
  assert.equal(login.severity, "info"); // siradan
  assert.ok(out.every((f) => f.source_tool === "katana"));
});

// --- sqlmap parse testi ---
const sqlmapPlugin = require("../src/plugins/sqlmap");

test("sqlmap parse: injection point bloklarini high finding'e cevirir", () => {
  const raw = `
sqlmap identified the following injection point(s) with a total of 17 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 7933=7933

    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
    Payload: id=1 UNION ALL SELECT NULL,CHAR(113)-- x
---
[10:42:48] [INFO] testing SQLite
`;
  const out = sqlmapPlugin.parse(raw, { raw: "http://x/?id=1" });
  assert.equal(out.length, 1); // tek parametre (id)
  assert.equal(out[0].severity, "high");
  assert.equal(out[0].cwe, "CWE-89");
  assert.equal(out[0].source_tool, "sqlmap");
  assert.deepEqual(out[0].evidence.teknikler, ["boolean-based blind", "UNION query"]);
  assert.equal(out[0].evidence.parametre, "id");
});

test("sqlmap parse: injection yoksa bos dizi", () => {
  const raw = "[CRITICAL] all tested parameters do not appear to be injectable.";
  assert.deepEqual(sqlmapPlugin.parse(raw, { raw: "http://x" }), []);
});

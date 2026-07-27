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

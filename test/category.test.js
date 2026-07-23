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

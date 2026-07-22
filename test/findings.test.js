const { test } = require("node:test");
const assert = require("node:assert");
const {
  makeFinding,
  dedupe,
  fingerprint,
  severitySummary,
  sortBySeverity,
  classifyTarget,
} = require("../src/core/findings");

function f(overrides = {}) {
  return makeFinding({
    target: "example.com",
    type: "vuln",
    severity: "medium",
    title: "Test",
    evidence: { t: "x" },
    source_tool: "nuclei",
    ...overrides,
  });
}

test("makeFinding sets defaults and required fields", () => {
  const finding = f();
  assert.ok(finding.id, "id üretilmeli");
  assert.equal(finding.severity, "medium");
  assert.equal(finding.cve, null);
  assert.equal(finding.cwe, null);
  assert.ok(finding.timestamp);
});

test("makeFinding falls back to info for invalid severity", () => {
  assert.equal(f({ severity: "bogus" }).severity, "info");
});

test("classifyTarget detects target types", () => {
  assert.equal(classifyTarget("https://a.com").type, "url");
  assert.equal(classifyTarget("127.0.0.1").type, "ip");
  assert.equal(classifyTarget("example.com").type, "domain");
  assert.equal(classifyTarget("/home/user/repo").type, "repo");
});

test("fingerprint ignores occurrences (derived count)", () => {
  const a = f({ evidence: { t: "x" } });
  const b = f({ evidence: { t: "x", occurrences: 9 } });
  assert.equal(fingerprint(a), fingerprint(b));
});

test("dedupe collapses identical findings and counts occurrences", () => {
  const findings = [f(), f(), f(), f({ title: "Other" })];
  const deduped = dedupe(findings);
  assert.equal(deduped.length, 2, "3 aynı + 1 farklı → 2");
  const collapsed = deduped.find((x) => x.title === "Test");
  assert.equal(collapsed.evidence.occurrences, 3);
});

test("dedupe keeps distinct findings separate", () => {
  const findings = [f({ evidence: { port: 22 } }), f({ evidence: { port: 80 } })];
  assert.equal(dedupe(findings).length, 2);
});

test("severitySummary counts by severity", () => {
  const s = severitySummary([f({ severity: "high" }), f({ severity: "high" }), f({ severity: "low" })]);
  assert.deepEqual(s, { high: 2, low: 1 });
});

test("sortBySeverity orders critical-first", () => {
  const sorted = sortBySeverity([f({ severity: "info" }), f({ severity: "critical" }), f({ severity: "medium" })]);
  assert.deepEqual(sorted.map((x) => x.severity), ["critical", "medium", "info"]);
});

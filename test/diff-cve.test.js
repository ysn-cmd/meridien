const { test } = require("node:test");
const assert = require("node:assert");
const { makeFinding } = require("../src/core/findings");
const { diffFindings } = require("../src/core/diff");
const {
  isCve,
  extractCveFromNuclei,
  extractCveFromSemgrep,
  extractCweFromSemgrep,
} = require("../src/core/cve");

function f(title, extra = {}) {
  return makeFinding({
    target: "x.com",
    type: "vuln",
    severity: "medium",
    title,
    evidence: { t: title },
    source_tool: "nuclei",
    ...extra,
  });
}

test("diffFindings detects added and removed", () => {
  const previous = [f("A"), f("B")];
  const current = [f("B"), f("C")];
  const { added, removed } = diffFindings(current, previous);
  assert.deepEqual(added.map((x) => x.title), ["C"]);
  assert.deepEqual(removed.map((x) => x.title), ["A"]);
});

test("diffFindings returns empty when nothing changed", () => {
  const set = [f("A"), f("B")];
  const { added, removed } = diffFindings(set, set);
  assert.equal(added.length, 0);
  assert.equal(removed.length, 0);
});

test("isCve validates CVE identifiers", () => {
  assert.equal(isCve("CVE-2023-48795"), true);
  assert.equal(isCve("cve-2021-44228"), true);
  assert.equal(isCve("waf-detect"), false);
  assert.equal(isCve(null), false);
});

test("extractCveFromNuclei reads classification and template-id", () => {
  assert.equal(
    extractCveFromNuclei({ "template-id": "x", info: { classification: { "cve-id": ["CVE-2021-44228"] } } }),
    "CVE-2021-44228"
  );
  assert.equal(extractCveFromNuclei({ "template-id": "CVE-2023-48795", info: {} }), "CVE-2023-48795");
  assert.equal(extractCveFromNuclei({ "template-id": "waf-detect", info: {} }), null);
});

test("extractCweFromSemgrep pulls the CWE id", () => {
  const result = { extra: { metadata: { cwe: ["CWE-78: OS Command Injection"] } } };
  assert.equal(extractCweFromSemgrep(result), "CWE-78");
  assert.equal(extractCweFromSemgrep({ extra: { metadata: {} } }), null);
});

test("extractCveFromSemgrep returns null when no cve metadata", () => {
  assert.equal(extractCveFromSemgrep({ extra: { metadata: { cwe: ["CWE-79"] } } }), null);
});

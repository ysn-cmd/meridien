const { test } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { meetsMinSeverity } = require(path.join(__dirname, "..", "src", "reporting", "report"));

test("esik ve ustu gecer", () => {
  assert.equal(meetsMinSeverity("critical", "medium"), true);
  assert.equal(meetsMinSeverity("high", "medium"), true);
  assert.equal(meetsMinSeverity("medium", "medium"), true);
});
test("esik alti gecmez", () => {
  assert.equal(meetsMinSeverity("low", "medium"), false);
  assert.equal(meetsMinSeverity("info", "medium"), false);
});
test("esik yoksa hepsi gecer", () => {
  assert.equal(meetsMinSeverity("info", null), true);
});
test("taninmayan severity gizlenmez", () => {
  assert.equal(meetsMinSeverity("bilinmeyen", "medium"), true);
});

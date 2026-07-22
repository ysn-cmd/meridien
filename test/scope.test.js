const { test } = require("node:test");
const assert = require("node:assert");
const { matches, assertInScope } = require("../src/core/scope");
const { AppError } = require("../src/errors/AppError");

test("matches: exact and wildcard domains", () => {
  assert.equal(matches("example.com", "example.com"), true);
  assert.equal(matches("a.example.com", "*.example.com"), true);
  assert.equal(matches("evil.com", "*.example.com"), false);
});

test("matches: path boundary blocks sibling dir and traversal", () => {
  const base = "/home/user/repo";
  assert.equal(matches("/home/user/repo", base), true, "tam eşleşme");
  assert.equal(matches("/home/user/repo/src/app.js", base), true, "alt dizin");
  assert.equal(matches("/home/user/repo-secret", base), false, "kardeş dizin");
  assert.equal(matches("/home/user/repo/../../etc/passwd", base), false, "traversal");
});

test("assertInScope accepts allowlisted target", () => {
  const scope = { allowlist: ["example.com"], denylist: [] };
  assert.equal(assertInScope("example.com", scope), "example.com");
});

test("assertInScope rejects out-of-scope target with 403", () => {
  const scope = { allowlist: ["example.com"], denylist: [] };
  assert.throws(() => assertInScope("evil.com", scope), (e) => e instanceof AppError && e.code === 403);
});

test("assertInScope denylist takes priority", () => {
  const scope = { allowlist: ["*.example.com"], denylist: ["admin.example.com"] };
  assert.throws(() => assertInScope("admin.example.com", scope), (e) => e.code === 403);
});

test("assertInScope rejects argument-injection targets", () => {
  const scope = { allowlist: ["/home/user/repo"], denylist: [] };
  assert.throws(() => assertInScope("-oN /tmp/pwn", scope), (e) => e instanceof AppError && e.code === 400);
});

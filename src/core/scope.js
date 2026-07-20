const fs = require("fs");
const path = require("path");
const YAML = require("yaml");
const { z } = require("zod");
const { AppError } = require("../errors/AppError");

// Girdi doğrulama şeması (Zod) — Kademe 2.
const targetSchema = z
  .string()
  .min(1, "Hedef boş olamaz")
  .max(2048, "Hedef çok uzun");

// scope.yaml biçimi:
//   allowlist: [ "example.com", "*.example.com", "10.0.0.0/8", "/opt/repos/myapp" ]
//   denylist:  [ "admin.example.com" ]
function loadScope(scopePath) {
  if (!fs.existsSync(scopePath)) {
    throw new AppError(`Kapsam dosyası bulunamadı: ${scopePath}`, 500);
  }
  const parsed = YAML.parse(fs.readFileSync(scopePath, "utf8")) || {};
  return {
    allowlist: Array.isArray(parsed.allowlist) ? parsed.allowlist : [],
    denylist: Array.isArray(parsed.denylist) ? parsed.denylist : [],
  };
}

// Basit desen eşleşmesi: tam eşleşme veya "*.example.com" wildcard son ek eşleşmesi.
// (IP aralığı / CIDR eşleşmesi Faz 2'de genişletilebilir.)
function matches(value, pattern) {
  if (pattern === value) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return value.endsWith(suffix);
  }
  // yol tabanlı hedefler için ön ek eşleşmesi (repo)
  if (pattern.endsWith("/") || pattern.startsWith("/")) {
    return value.startsWith(pattern);
  }
  return false;
}

// Hedefi kapsam kurallarından geçirir. Geçemezse AppError fırlatır.
// Sıra: girdi doğrulama → denylist (öncelikli) → allowlist → fail-safe reddet.
function assertInScope(rawTarget, scope) {
  const parsed = targetSchema.safeParse(rawTarget);
  if (!parsed.success) {
    throw new AppError(`Geçersiz hedef: ${parsed.error.issues[0].message}`, 400);
  }
  const value = parsed.data.trim();

  // Kademe 3 — Denylist önceliklidir.
  if (scope.denylist.some((p) => matches(value, p))) {
    throw new AppError(`Hedef yasak listede: ${value}`, 403);
  }

  // Kademe 1 — Allowlist eşleşmesi zorunlu.
  const allowed = scope.allowlist.some((p) => matches(value, p));
  if (!allowed) {
    // Kademe 4 — Fail-safe: belirsizse reddet.
    throw new AppError(`Hedef kapsam dışı (allowlist eşleşmesi yok): ${value}`, 403);
  }

  return value;
}

module.exports = { loadScope, assertInScope, matches };

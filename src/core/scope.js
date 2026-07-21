const fs = require("fs");
const path = require("path");
const YAML = require("yaml");
const { z } = require("zod");
const { AppError } = require("../errors/AppError");

// Girdi doğrulama şeması (Zod) — Kademe 2.
// '-' ile başlayan hedefler reddedilir: spawn'a argüman olarak geçtiğinde
// harici araç (nmap/nuclei/semgrep) onu bayrak sanabilir (argüman enjeksiyonu).
const targetSchema = z
  .string()
  .min(1, "Hedef boş olamaz")
  .max(2048, "Hedef çok uzun")
  .refine((v) => !v.trim().startsWith("-"), "Hedef '-' ile başlayamaz");

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

// Desen eşleşmesi: tam eşleşme, "*.example.com" wildcard son ek, veya yol
// tabanlı hedefler için SINIRLI ön ek (kardeş dizin / path traversal atlatmasına
// karşı). (IP aralığı / CIDR eşleşmesi ileride genişletilebilir.)
function matches(value, pattern) {
  if (pattern === value) return true;

  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return value.endsWith(suffix);
  }

  // Yol tabanlı hedefler: gerçek yolları çöz (.. çökertilir) ve SINIR kontrolü
  // yap — hedef ya tam olarak izinli yol olmalı ya da onun ALTINDA olmalı.
  // Böylece "/base-evil" ve "/base/../.." gibi atlatmalar reddedilir.
  if (pattern.startsWith("/") || pattern.endsWith("/")) {
    const base = path.resolve(pattern);
    const target = path.resolve(value);
    return target === base || target.startsWith(base + path.sep);
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

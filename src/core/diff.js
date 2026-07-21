const { fingerprint } = require("./findings");

// İki bulgu kümesini karşılaştırır (mevcut vs önceki tarama).
//   added   → mevcutta var, öncekinde yok (yeni çıkan)
//   removed → öncekinde var, mevcutta yok (kapanan/düzeltilen)
// Karşılaştırma fingerprint (imza) üzerinden yapılır; occurrences sayacı
// imzaya dahil olmadığı için sayı değişimi sahte fark üretmez.
function diffFindings(current = [], previous = []) {
  const prevKeys = new Set(previous.map(fingerprint));
  const currKeys = new Set(current.map(fingerprint));

  const added = current.filter((f) => !prevKeys.has(fingerprint(f)));
  const removed = previous.filter((f) => !currKeys.has(fingerprint(f)));

  return { added, removed };
}

module.exports = { diffFindings };

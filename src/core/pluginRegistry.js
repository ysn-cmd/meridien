const { AppError } = require("../errors/AppError");

// Plugin sözleşmesi:
//   name: string
//   category: string                 // recon | dast | sast | secrets | ...
//   supports(target): boolean        // target = { raw, type }
//   run(target): Promise<Finding[]>
//
// Çekirdek plugin'in içinde hangi aracın çalıştığını bilmez; yalnızca bu
// sözleşmeye güvenir. Yeni araç eklemek = yeni plugin yazıp buraya kaydetmek.

const registry = new Map();

function register(plugin) {
  for (const fn of ["name", "supports", "run"]) {
    if (plugin[fn] === undefined) {
      throw new AppError(`Plugin sözleşmeyi ihlal ediyor, eksik: ${fn}`, 500);
    }
  }
  registry.set(plugin.name, plugin);
  return plugin;
}

function all() {
  return [...registry.values()];
}

// Verilen hedefi işleyebilen plugin'leri döner. İsteğe bağlı olarak
// yalnızca belirtilen isimlerle sınırlanır (CLI --plugins seçeneği).
function applicable(target, names = null) {
  return all().filter((p) => {
    if (names && !names.includes(p.name)) return false;
    try {
      return p.supports(target);
    } catch {
      return false;
    }
  });
}

// Kayıtlı tüm kategorilerin sıralı, tekil listesi.
function categories() {
  const set = new Set();
  for (const p of all()) {
    if (p.category) set.add(p.category);
  }
  return [...set].sort();
}

// Bir kategorideki plugin isimleri. Kategori yoksa boş dizi döner.
function namesByCategory(category) {
  return all()
    .filter((p) => p.category === category)
    .map((p) => p.name);
}

module.exports = { register, all, applicable, categories, namesByCategory };

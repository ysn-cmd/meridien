# secscan — Faz 1 iskelet

Plugin tabanlı otomatik güvenlik tarama platformunun çekirdeği. Uçtan uca
akış çalışır: kapsam kontrolü → plugin yürütme → normalizasyon → depolama.

## Kurulum

```bash
npm install
```

## Çalıştırma

```bash
# Mock plugin ile (gerçek araç gerektirmez, akışı test etmek için)
node bin/scan.js --target example.com --plugins mock

# Gerçek nuclei plugin'i ile (sistemde nuclei kurulu olmalı)
node bin/scan.js --target example.com --plugins nuclei

# Tüm uygun plugin'ler
node bin/scan.js --target example.com --user yasin
```

Kapsam dışı bir hedef reddedilir:

```bash
node bin/scan.js --target google.com   # [REDDEDİLDİ 403] kapsam dışı
```

## Kapsam

`scope.yaml` düzenlenerek izinli hedefler tanımlanır. Listede olmayan
hedef taranmaz (fail-safe). Denylist önceliklidir.

## Yapı

```
src/
├── core/
│   ├── findings.js       Ortak Finding şeması + severity yardımcıları
│   ├── scope.js          Kapsam + girdi doğrulama (Zod)
│   ├── pluginRegistry.js Plugin kayıt ve seçimi
│   └── orchestrator.js   Tarama işini uçtan uca yürüten çekirdek
├── plugins/
│   ├── mock/             Test plugin'i (örnek bulgular)
│   └── nuclei/           Gerçek DAST plugin'i
├── store/db.js           SQLite depolama
└── errors/AppError.js    Merkezi hata sınıfı
```

## Yeni plugin ekleme

1. `src/plugins/<ad>/index.js` içinde `{ name, supports(target), run(target) }` sözleşmesini uygula.
2. `run()` içinde aracı `child_process` ile çalıştır, çıktıyı `makeFinding()` ile normalize et.
3. `bin/scan.js` içinde `registry.register(require(...))` ile kaydet.

Çekirdek koduna dokunmak gerekmez.

## Sıradaki (Faz 2+)

- recon plugin (subfinder / httpx / nmap) ve SAST plugin (semgrep / npm audit)
- CIDR/IP aralığı kapsam eşleşmesi
- zamanlama + diff + alerting (Faz 3)
- dashboard + PDF rapor (Faz 4)
```

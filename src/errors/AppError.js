// Merkezi hata sınıfı. Tüm bilinçli hatalar bununla fırlatılır.
// Örn: throw new AppError("Kapsam dışı hedef", 403);
class AppError extends Error {
  constructor(message, code = 500) {
    super(message);
    this.name = "AppError";
    this.code = code; // HTTP benzeri kod (403 = yetkisiz, 400 = geçersiz girdi, ...)
  }
}

module.exports = { AppError };

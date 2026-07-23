// Tüm plugin'lerin tek yerden kaydı. Hem CLI (bin/scan.js) hem scheduler
// bunu kullanır — plugin listesi tek yerde tutulur, çoğaltılmaz.
const registry = require("../core/pluginRegistry");

// Çekirdek / test
registry.register(require("./mock"));

// Recon
registry.register(require("./nmap"));
registry.register(require("./whatweb"));

// DAST
registry.register(require("./nuclei"));
registry.register(require("./nikto"));
registry.register(require("./wapiti"));

// SAST
registry.register(require("./semgrep"));

// Secrets
registry.register(require("./gitleaks"));

module.exports = registry;

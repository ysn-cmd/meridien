// Tüm plugin'lerin tek yerden kaydı. Hem CLI (bin/scan.js) hem scheduler
// bunu kullanır — plugin listesi tek yerde tutulur, çoğaltılmaz.
const registry = require("../core/pluginRegistry");

// Çekirdek / test
registry.register(require("./mock"));

// Recon
registry.register(require("./nmap"));
registry.register(require("./whatweb"));
registry.register(require("./subfinder"));
registry.register(require("./httpx"));
registry.register(require("./naabu"));
registry.register(require("./katana"));

// DAST
registry.register(require("./nuclei"));
registry.register(require("./nikto"));
registry.register(require("./wapiti"));
registry.register(require("./dalfox"));
registry.register(require("./ffuf"));

// SAST
registry.register(require("./semgrep"));

// Secrets
registry.register(require("./gitleaks"));

// Dependency
registry.register(require("./trivy"));
registry.register(require("./npm-audit"));

module.exports = registry;

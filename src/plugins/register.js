// Tüm plugin'lerin tek yerden kaydı. Hem CLI (bin/scan.js) hem scheduler
// bunu kullanır — plugin listesi tek yerde tutulur, çoğaltılmaz.
const registry = require("../core/pluginRegistry");

registry.register(require("./mock"));
registry.register(require("./nuclei"));
registry.register(require("./nmap"));
registry.register(require("./semgrep"));

module.exports = registry;

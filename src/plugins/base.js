const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

function createProcessPlugin(spec) {
  const {
    name,
    category,
    defaultBin,
    binEnv,
    supports,
    buildArgs,
    parse,
    outputFile = false,
    timeoutMs = 180000,
    okExitCodes = [],
  } = spec;

  return {
    name,
    category,
    supports,
    async run(target) {
      const bin = (binEnv && process.env[binEnv]) || defaultBin;
      let outFile = null;
      if (outputFile) {
        outFile = path.join(
          os.tmpdir(),
          `meridien-${name}-${Date.now()}-${Math.random().toString(36).slice(2)}.out`
        );
      }

      const args = buildArgs(target, { outFile });
      const { stdout, stderr, code } = await runProcess(bin, args, timeoutMs);

      let raw = stdout;
      if (outputFile) {
        try {
          raw = fs.readFileSync(outFile, "utf8");
        } catch {
          raw = "";
        }
        try {
          fs.unlinkSync(outFile);
        } catch {}
      }

      if (!raw || !raw.trim()) {
        if (code !== 0 && !okExitCodes.includes(code)) {
          throw new Error(`${bin} hata (kod ${code}): ${stderr.trim().slice(0, 200)}`);
        }
        return [];
      }
      return parse(raw, target) || [];
    },
  };
}

function runProcess(bin, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    // detached: true => process kendi grubunu kurar, alt process'ler dahil
    // hepsini tek seferde öldürebilelim.
    const proc = spawn(bin, args, {
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let stdout = "";
    let stderr = "";
    let killed = false;

    // Tüm process grubunu öldür (parent + perl/python alt process'leri).
    const killGroup = (signal) => {
      try {
        process.kill(-proc.pid, signal);
      } catch {
        try {
          proc.kill(signal);
        } catch {}
      }
    };

    const timer = setTimeout(() => {
      killed = true;
      killGroup("SIGTERM");
      // 3 sn içinde ölmezse zorla.
      setTimeout(() => killGroup("SIGKILL"), 3000);
      reject(new Error(`${bin} zaman aşımı (${timeoutMs}ms)`));
    }, timeoutMs);

    proc.stdout.on("data", (d) => (stdout += d.toString()));
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("error", (e) => {
      clearTimeout(timer);
      reject(new Error(`${bin} çalıştırılamadı: ${e.message}`));
    });
    proc.on("close", (code) => {
      clearTimeout(timer);
      if (!killed) resolve({ stdout, stderr, code });
    });
  });
}

function ensureUrl(raw) {
  return /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
}

module.exports = { createProcessPlugin, ensureUrl };

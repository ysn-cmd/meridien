const nodemailer = require("nodemailer");

// Yeni bulgular için e-posta gönderir. SMTP ayarı .env'den okunur; yoksa
// Ethereal test hesabı kullanılır (gerçek e-posta gitmez, önizleme linki loglanır).

async function getTransport() {
  if (process.env.SMTP_HOST) {
    const port = Number(process.env.SMTP_PORT || 587);
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: port === 465, // 465 = SSL
      auth: process.env.SMTP_USER
        ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
        : undefined,
    });
  }
  // Fallback: Ethereal (test) — gerçek e-posta gitmez
  const acc = await nodemailer.createTestAccount();
  return nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: { user: acc.user, pass: acc.pass },
  });
}

function buildBody(job, findings) {
  const lines = findings.map((f) => {
    const tags = [f.cve, f.cwe].filter(Boolean).join(" ");
    return `- [${f.severity.toUpperCase()}] ${f.title} (${f.source_tool})${tags ? " " + tags : ""}`;
  });
  return [
    `Meridien — ${job.target} taramasında ${findings.length} yeni bulgu tespit edildi:`,
    "",
    ...lines,
    "",
    `Tarama ID: ${job.id}`,
    `Zaman: ${new Date(job.finished_at || job.started_at).toLocaleString("tr-TR")}`,
  ].join("\n");
}

async function notify(job, findings) {
  const transport = await getTransport();
  const info = await transport.sendMail({
    from: process.env.ALERT_FROM || "meridien@localhost",
    to: process.env.ALERT_TO || "admin@localhost",
    subject: `[Meridien] ${findings.length} yeni bulgu: ${job.target}`,
    text: buildBody(job, findings),
  });

  const preview = nodemailer.getTestMessageUrl(info);
  if (preview) console.log(`  E-posta önizleme (Ethereal): ${preview}`);
  return { messageId: info.messageId, preview };
}

module.exports = { notify, buildBody };

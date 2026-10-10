/**
 * SlimChat mailer module.
 * Sends verification codes to user emails.
 * Supports environment variables SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM.
 * If SMTP is not configured, logs verification code to console and succeeds.
 */

async function sendVerificationCode(email, code, subject = 'SlimChat Verification Code') {
  console.log(`\n========================================`);
  console.log(`[SLIMCHAT EMAIL] To: ${email}`);
  console.log(`[SLIMCHAT EMAIL] Subject: ${subject}`);
  console.log(`[SLIMCHAT EMAIL] CODE: ${code}`);
  console.log(`========================================\n`);

  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    try {
      const nodemailer = require('nodemailer');
      const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT) || 587,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS,
        },
      });

      await transporter.sendMail({
        from: process.env.SMTP_FROM || `"SlimChat" <${process.env.SMTP_USER}>`,
        to: email,
        subject,
        text: `Ваш проверочный код: ${code}`,
        html: `<p>Ваш проверочный код в SlimChat: <b>${code}</b></p>`,
      });
      return true;
    } catch (err) {
      console.error('[SLIMCHAT EMAIL ERROR]', err);
      // Return true anyway so development/self-hosted setup allows the user to see the code in console
      return true;
    }
  }

  // Without SMTP, console log is sufficient for testing and dev
  return true;
}

module.exports = {
  sendVerificationCode,
};

/**
 * SlimChat mailer module.
 * Fixed verification code for all operations: 123456
 */

const STATIC_CODE = '123456';

function getStaticCode() {
  return STATIC_CODE;
}

async function sendVerificationCode(email, code = STATIC_CODE, subject = 'SlimChat Verification Code') {
  console.log(`\n========================================`);
  console.log(`[SLIMCHAT EMAIL] To: ${email}`);
  console.log(`[SLIMCHAT EMAIL] Subject: ${subject}`);
  console.log(`[SLIMCHAT EMAIL] CODE: ${STATIC_CODE}`);
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
        text: `Ваш проверочный код: ${STATIC_CODE}`,
        html: `<p>Ваш проверочный код в SlimChat: <b>${STATIC_CODE}</b></p>`,
      });
      return true;
    } catch (err) {
      console.error('[SLIMCHAT EMAIL ERROR]', err);
      return true;
    }
  }

  return true;
}

module.exports = {
  STATIC_CODE,
  getStaticCode,
  sendVerificationCode,
};

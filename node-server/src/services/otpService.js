const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { redisClient } = require('../../config/db');

const REAUTH_TTL = parseInt(process.env.REAUTH_TTL) || 180;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  logger: false,  // 운영 환경 비활성화
  debug: false,   // 운영 환경 비활성화
});

function maskEmail(email) {
  const [local, domain] = email.split('@');
  return `${local.slice(0, 2)}***@${domain}`;
}

exports.generateAndSendOtp = async (userId, email) => {
  const otp = String(crypto.randomInt(100000, 1000000)); // 6자리

  await redisClient.set(`reauth:${userId}`, '1', { EX: REAUTH_TTL });
  await redisClient.set(`reauth:otp:${userId}`, otp, { EX: REAUTH_TTL });

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: '[MFA] 추가 인증 코드',
      text: `인증 코드: ${otp} (3분 내 입력)`,
    });
    console.log(`OTP 발송 완료: ${maskEmail(email)}`); // *원본 이메일 로깅 금지
  } catch (err) {
    console.error(`OTP 발송 실패: ${maskEmail(email)}`, err.message);
    throw err;
  }
};

exports.verifyOtp = async (userId, submittedOtp) => {
  const reauthExists = await redisClient.get(`reauth:${userId}`);
  const storedOtp = await redisClient.get(`reauth:otp:${userId}`);

  if (!reauthExists || !storedOtp) {
    return { valid: false, reason: 'REAUTH_EXPIRED' };
  }

  const failCount = parseInt(await redisClient.get(`reauth:fail:${userId}`)) || 0;
  if (failCount >= 5) {
    return { valid: false, reason: 'REAUTH_BLOCKED' };
  }

  const isMatch = crypto.timingSafeEqual(
      Buffer.from(storedOtp),
      Buffer.from(submittedOtp.padEnd(6, ' ').slice(0, 6))
  );

  if (!isMatch) {
    await redisClient.incr(`reauth:fail:${userId}`);
    await redisClient.expire(`reauth:fail:${userId}`, REAUTH_TTL);
    return { valid: false, reason: 'OTP_MISMATCH' };
  }

  await redisClient.del(`reauth:${userId}`);
  await redisClient.del(`reauth:otp:${userId}`);
  await redisClient.del(`reauth:fail:${userId}`);
  return { valid: true };
};
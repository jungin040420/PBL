const crypto = require("crypto");

// 랜덤 Salt 기반 SHA-256
const anonymizeRandom = (value) => {
  if (
      value === null ||
      value === undefined ||
      value === ""
  ) {
    return null;
  }

  const salt = crypto
      .randomBytes(32)
      .toString("hex");

  return crypto
      .createHash("sha256")
      .update(String(value) + salt)
      .digest("hex");
};


// USERID_SALT 기반 사용자 ID 해시
const hashUserId = (userId) => {
  if (
      userId === null ||
      userId === undefined ||
      userId === ""
  ) {
    throw new Error(
        "[F-08] hashUserId: userId가 비어 있습니다."
    );
  }

  const salt = process.env.USERID_SALT;

  if (!salt) {
    throw new Error(
        "[F-08] USERID_SALT 환경변수가 없습니다."
    );
  }

  if (salt.length < 64) {
    throw new Error(
        "[F-08] USERID_SALT는 hex 64자 이상이어야 합니다."
    );
  }

  return crypto
      .createHash("sha256")
      .update(String(userId) + salt)
      .digest("hex");
};


// COMPARE_SALT 기반 비교용 해시
const hashForCompare = (value) => {
  if (
      value === null ||
      value === undefined ||
      value === ""
  ) {
    return null;
  }

  const salt = process.env.COMPARE_SALT;

  if (!salt) {
    throw new Error(
        "[F-08] COMPARE_SALT 환경변수가 없습니다."
    );
  }

  if (salt.length < 64) {
    throw new Error(
        "[F-08] COMPARE_SALT는 hex 64자 이상이어야 합니다."
    );
  }

  if (salt === process.env.USERID_SALT) {
    throw new Error(
        "[F-08] COMPARE_SALT와 USERID_SALT는 서로 달라야 합니다."
    );
  }

  return crypto
      .createHash("sha256")
      .update(String(value) + salt)
      .digest("hex");
};


// User-Agent 비식별화
const anonymizeUserAgent = (userAgent) => {
  if (!userAgent) {
    return {
      hash: null,
      os: "unknown",
      browser: "unknown",
    };
  }

  const hash = anonymizeRandom(userAgent);

  let os = "unknown";

  if (/windows/i.test(userAgent)) {
    os = "Windows";
  } else if (/macintosh|mac os/i.test(userAgent)) {
    os = "macOS";
  } else if (/android/i.test(userAgent)) {
    os = "Android";
  } else if (/iphone|ipad|ipod/i.test(userAgent)) {
    os = "iOS";
  } else if (/linux/i.test(userAgent)) {
    os = "Linux";
  }

  let browser = "unknown";

  if (/edg\//i.test(userAgent)) {
    browser = "Edge";
  } else if (/opr\/|opera/i.test(userAgent)) {
    browser = "Opera";
  } else if (/chrome/i.test(userAgent)) {
    browser = "Chrome";
  } else if (/firefox/i.test(userAgent)) {
    browser = "Firefox";
  } else if (/safari/i.test(userAgent)) {
    browser = "Safari";
  }

  return {
    hash,
    os,
    browser,
  };
};


const generateFixedSalt = () => {
  return crypto
      .randomBytes(32)
      .toString("hex");
};


module.exports = {
  anonymizeRandom,
  hashUserId,
  hashForCompare,
  anonymizeUserAgent,
  generateFixedSalt,
};
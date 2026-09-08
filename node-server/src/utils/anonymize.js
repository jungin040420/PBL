const crypto = require("crypto");

/**
 * F-08 개인정보 비식별화 처리 규칙 정의서 v2.6 구현
 *
 * 규칙 1 : IP 주소     → SHA-256 + 랜덤 Salt (레코드마다 새 Salt)
 * 규칙 2 : 기기 ID     → SHA-256 + 랜덤 Salt (레코드마다 새 Salt)
 * 규칙 4 : User-Agent  → SHA-256 + 랜덤 Salt + OS/브라우저 종류 분리
 * 규칙 5 : userIdHash  → SHA-256 + 고정 Salt (USERID_SALT)
 * 규칙 6 : 비교·조회용 → SHA-256 + 고정 Salt (COMPARE_SALT)
 *
 * 고정 Salt는 용도별로 분리 관리하며 혼용하지 않는다 (규칙 5 주의사항).
 */


// ─────────────────────────────────────────────
// 규칙 1·2·4 : 랜덤 Salt 방식 (복원·재현 불가)
// ─────────────────────────────────────────────

/**
 * 랜덤 Salt 기반 SHA-256 해시
 * - Salt는 레코드마다 새로 생성, 어디에도 저장하지 않음 (F-08 §2)
 * - 동일 입력이라도 매번 다른 해시값 생성
 *
 * @param {string} value 원본 값 (IP, 기기 Fingerprint 등)
 * @returns {string|null} 64자리 hex 해시값
 */
const anonymizeRandom = (value) => {
  if (
      value === null ||
      value === undefined ||
      value === ""
  ) {
    return null;
  }

  // NIST SP 800-132: 최소 32바이트(256비트)
  // Math.random() 사용 금지 (NIST SP 800-90A)
  const salt = crypto
      .randomBytes(32)
      .toString("hex");

  return crypto
      .createHash("sha256")
      .update(String(value) + salt)
      .digest("hex");
};


// ─────────────────────────────────────────────
// 규칙 5 : 고정 Salt 방식 (그룹핑 목적, 재현 가능)
// ─────────────────────────────────────────────

/**
 * 사용자 식별자 해시 (userIdHash)
 * - F-08 §5 예외 조항: 고정 Salt 허용
 * - 목적: ML 피처 로그의 사용자별 그룹핑 (동일 입력 → 동일 해시)
 * - anonymizeRandom()과 혼용 금지 (F-08 규칙 5)
 *
 * @param {string} userId 사용자 식별자 (username)
 * @returns {string} 64자리 hex 해시값
 */
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
        "[F-08] USERID_SALT 환경변수가 설정되지 않았습니다. " +
        "규칙 5에 따라 고정 Salt는 환경변수로만 관리합니다."
    );
  }

  if (salt.length < 64) {
    throw new Error(
        "[F-08] USERID_SALT가 32바이트(hex 64자) 미만입니다. " +
        "NIST SP 800-132 권고 기준 미달."
    );
  }

  return crypto
      .createHash("sha256")
      .update(String(userId) + salt)
      .digest("hex");
};


// ─────────────────────────────────────────────
// 규칙 6 : 비교·조회 목적 고정 Salt (재현 가능)
// ─────────────────────────────────────────────

/**
 * 비교·조회 전용 해시 (ipChanged / userAgentChanged / regionChanged, ipHash)
 * - F-08 v2.6 규칙 6 / §5 예외 조항: 비교·조회 목적에 한해 고정 Salt 허용
 * - 저장 허용 위치: Redis lastcontext:{userIdHash}, blacklist:ip:{ipHash},
 *   Elasticsearch risk-logs 인덱스 한정
 * - ML 전달값은 비교 결과(0/1)만 — 해시값 자체는 전달하지 않음 (규칙 6)
 * - 고정 Salt 로테이션: 6개월 주기 또는 유출 시 즉시
 * - anonymizeRandom() / hashUserId()와 혼용 금지
 *
 * @param {string} value 비교 대상 원본 값 (IP, User-Agent 등)
 * @returns {string|null} 64자리 hex 해시값
 */
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
        "[F-08] COMPARE_SALT 환경변수가 설정되지 않았습니다. " +
        "비교 목적 고정 Salt는 환경변수로만 관리합니다."
    );
  }

  if (salt.length < 64) {
    throw new Error(
        "[F-08] COMPARE_SALT가 32바이트(hex 64자) 미만입니다. " +
        "NIST SP 800-132 권고 기준 미달."
    );
  }

  if (salt === process.env.USERID_SALT) {
    throw new Error(
        "[F-08] COMPARE_SALT와 USERID_SALT가 동일합니다. " +
        "규칙 5 혼용 금지 조항 위반."
    );
  }

  return crypto
      .createHash("sha256")
      .update(String(value) + salt)
      .digest("hex");
};


// ─────────────────────────────────────────────
// 규칙 4 : User-Agent 전용 처리
// ─────────────────────────────────────────────

/**
 * User-Agent 비식별화
 * - 원문 저장 금지, 해시값만 저장
 * - OS/브라우저 "종류"만 분리 저장 (버전 정보 제외)
 *
 * @param {string} userAgent
 * @returns {{hash: string|null, os: string, browser: string}}
 */
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

  // Edge/Opera는 UA에 Chrome을 포함하므로 먼저 판별
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


/**
 * 고정 Salt 신규 생성 유틸 (최초 1회 실행)
 * 출력값을 .env의 USERID_SALT(규칙 5) 또는 COMPARE_SALT(규칙 6)에 설정.
 * 두 값은 반드시 다른 값이어야 하며, 운영 중 재실행 금지.
 */
const generateFixedSalt = () => {
  return crypto
      .randomBytes(32)
      .toString("hex");
};


/**
 * 세션 바인딩 전용 고정 Salt 해시 (AiTM 세션 탈취 탐지용)
 * - 세션 발급 시점의 IP/UA/Fingerprint를 바인딩, 이후 요청마다 비교하여 탐지
 * - hashForCompare()(로그인 컨텍스트 비교용)와 용도가 달라 Salt 분리
 * - 저장 허용 위치: Redis session:{username}:{sessionId} 키 전용
 *
 * @param {string} value 해시할 원본 값 (IP, User-Agent, Fingerprint 등)
 * @returns {string} SHA-256 해시값 (hex)
 */
const hashForSessionBinding = (value) => {
  const salt = process.env.SESSION_SALT;

  if (!salt) {
    throw new Error(
        "[F-08] SESSION_SALT 환경변수가 설정되지 않았습니다. " +
        "세션 바인딩 목적 고정 Salt는 환경변수로만 관리합니다."
    );
  }

  if (salt.length < 64) {
    throw new Error(
        "[F-08] SESSION_SALT가 32바이트(hex 64자) 미만입니다. " +
        "NIST SP 800-132 권고 기준 미달."
    );
  }

  if (salt === process.env.COMPARE_SALT || salt === process.env.USERID_SALT) {
    throw new Error(
        "[F-08] SESSION_SALT가 COMPARE_SALT 또는 USERID_SALT와 동일합니다. " +
        "규칙 5 혼용 금지 조항 위반."
    );
  }

  return crypto
      .createHash("sha256")
      .update(String(value) + salt)
      .digest("hex");
};


module.exports = {
  anonymizeRandom,
  hashUserId,
  hashForCompare,
  anonymizeUserAgent,
  generateFixedSalt,
  hashForSessionBinding,
};
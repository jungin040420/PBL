const crypto = require('crypto');

/**
 * F-08 개인정보 비식별화 처리 규칙 정의서 v2.0 구현
 *
 * 규칙 1: IP 주소       → SHA-256 + 랜덤 Salt (레코드마다 새 Salt)
 * 규칙 2: 기기 ID       → SHA-256 + 랜덤 Salt (레코드마다 새 Salt)
 * 규칙 4: User-Agent    → SHA-256 해시 + OS/브라우저 종류 분리
 * 규칙 5: userIdHash    → SHA-256 + 고정 Salt (USERID_SALT)  ★ 별도 함수
 */

// ─────────────────────────────────────────────
// 규칙 1·2·4 : 랜덤 Salt 방식 (복원 불가, 재현 불가)
// ─────────────────────────────────────────────

/**
 * 랜덤 Salt 기반 SHA-256 해시
 * - Salt는 레코드마다 새로 생성하며 어디에도 저장하지 않는다 (F-08 §2)
 * - 동일 입력이라도 매번 다른 해시값이 나온다
 *
 * @param {string} value 원본 값 (IP, 기기 Fingerprint 등)
 * @returns {string|null} 64자리 hex 해시값
 */
const anonymizeRandom = (value) => {
  if (value === null || value === undefined || value === '') return null;

  // NIST SP 800-132 권고: 최소 32바이트(256비트)
  // Math.random() 사용 금지 (NIST SP 800-90A)
  const salt = crypto.randomBytes(32).toString('hex');

  const hash = crypto
    .createHash('sha256')
    .update(String(value) + salt)
    .digest('hex');

  // Salt는 반환하지 않으며 메모리 밖으로 나가지 않는다
  return hash;
};

// ─────────────────────────────────────────────
// 규칙 5 : 고정 Salt 방식 (그룹핑 목적, 재현 가능)
// ─────────────────────────────────────────────

/**
 * 사용자 식별자 해시 (userIdHash)
 * - F-08 §5 예외 조항: 고정 Salt 사용을 허용
 * - 목적: ML 피처 로그의 사용자별 그룹핑 (동일 입력 → 동일 해시 필요)
 * - anonymizeRandom()과 절대 혼용하지 않는다 (F-08 규칙 5 명시)
 *
 * @param {number|string} userId users.id (DB PK)
 * @returns {string} 64자리 hex 해시값
 */
const hashUserId = (userId) => {
  if (userId === null || userId === undefined || userId === '') {
    throw new Error('[F-08] hashUserId: userId가 비어 있습니다.');
  }

  const salt = process.env.USERID_SALT;

  if (!salt) {
    throw new Error(
      '[F-08] USERID_SALT 환경변수가 설정되지 않았습니다. ' +
      '규칙 5에 따라 고정 Salt는 환경변수로만 관리합니다.'
    );
  }

  // 32바이트(=hex 64자) 미만이면 규칙 위반
  if (salt.length < 64) {
    throw new Error(
      '[F-08] USERID_SALT가 32바이트(hex 64자) 미만입니다. ' +
      'NIST SP 800-132 권고 기준 미달.'
    );
  }

  return crypto
    .createHash('sha256')
    .update(String(userId) + salt)
    .digest('hex');
};

// ─────────────────────────────────────────────
// 규칙 1 예외 : 비교 목적 고정 Salt (재현 가능)
// ─────────────────────────────────────────────

/**
 * 비교 전용 해시 (ipChanged / userAgentChanged / regionChanged 계산용)
 * - F-08 v2.1 §5 예외 조항: 비교가 유일한 목적인 값에 고정 Salt를 허용
 * - 랜덤 Salt는 동일 입력도 매번 다른 해시가 나와 직전 값과 비교가 불가능하다
 * - 결과값은 Redis lastcontext:{userIdHash} 에만 저장하며 덮어쓰기로 관리한다
 * - ML에 전달하는 값은 비교 결과(0/1)뿐이며 해시 자체는 전달하지 않는다 (F-08 §9)
 * - anonymizeRandom() / hashUserId() 와 절대 혼용하지 않는다
 *
 * @param {string} value 비교 대상 원본 값 (IP, User-Agent 등)
 * @returns {string|null} 64자리 hex 해시값
 */
const hashForCompare = (value) => {
  if (value === null || value === undefined || value === '') return null;

  const salt = process.env.COMPARE_SALT;

  if (!salt) {
    throw new Error(
      '[F-08] COMPARE_SALT 환경변수가 설정되지 않았습니다. ' +
      '비교 목적 고정 Salt는 환경변수로만 관리합니다.'
    );
  }

  if (salt.length < 64) {
    throw new Error(
      '[F-08] COMPARE_SALT가 32바이트(hex 64자) 미만입니다. ' +
      'NIST SP 800-132 권고 기준 미달.'
    );
  }

  if (salt === process.env.USERID_SALT) {
    throw new Error(
      '[F-08] COMPARE_SALT와 USERID_SALT가 동일합니다. ' +
      '규칙 5 혼용 금지 조항 위반.'
    );
  }

  return crypto
    .createHash('sha256')
    .update(String(value) + salt)
    .digest('hex');
};

// ─────────────────────────────────────────────
// 규칙 4 : User-Agent 전용 처리
// ─────────────────────────────────────────────

/**
 * User-Agent 처리
 * - 원문은 저장하지 않고 해시값만 저장
 * - OS/브라우저 "종류"만 분리 저장 (버전 정보 제외)
 *
 * @param {string} userAgent
 * @returns {{hash: string|null, os: string, browser: string}}
 */
const anonymizeUserAgent = (userAgent) => {
  if (!userAgent) {
    return { hash: null, os: 'unknown', browser: 'unknown' };
  }

  const hash = anonymizeRandom(userAgent);

  let os = 'unknown';
  if (/windows/i.test(userAgent)) os = 'Windows';
  else if (/macintosh|mac os/i.test(userAgent)) os = 'macOS';
  else if (/android/i.test(userAgent)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(userAgent)) os = 'iOS';
  else if (/linux/i.test(userAgent)) os = 'Linux';

  // 순서 주의: Edge/Opera는 UA에 Chrome을 포함하므로 먼저 판별
  let browser = 'unknown';
  if (/edg\//i.test(userAgent)) browser = 'Edge';
  else if (/opr\/|opera/i.test(userAgent)) browser = 'Opera';
  else if (/chrome/i.test(userAgent)) browser = 'Chrome';
  else if (/firefox/i.test(userAgent)) browser = 'Firefox';
  else if (/safari/i.test(userAgent)) browser = 'Safari';

  return { hash, os, browser };
};

/**
 * 고정 Salt 신규 생성용 유틸 (최초 1회 실행)
 * 출력값을 .env의 USERID_SALT에 넣는다. 운영 중 재실행 금지.
 */
const generateFixedSalt = () => crypto.randomBytes(32).toString('hex');

module.exports = {
  anonymizeRandom,
  hashUserId,
  hashForCompare,
  anonymizeUserAgent,
  generateFixedSalt,
};
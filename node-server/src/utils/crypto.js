const nodeCrypto = require('crypto');

/**
 * F-08 개인정보 비식별화 처리 규칙 정의서 v2.1 - 규칙 3 구현
 *
 * 2등급(간접 식별 정보) AES-256-GCM 양방향 암호화
 * 적용 대상: 감사 로그(인증 이력), 세션 이벤트, 차단/해제 이력
 *
 * 저장 형태: IV(24자) + AuthTag(32자) + 암호문  → 하나의 문자열로 결합
 */

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // NIST SP 800-38D 권고 (96비트)
const KEY_LENGTH = 32;  // AES-256 = 32바이트. AES-128/192 사용 금지

/**
 * 환경변수에서 암호화 키 로드
 * - 코드·DB 하드코딩 금지 (F-08 §3, §5)
 * - 호출 시점마다 검증하여 잘못된 키로 조용히 동작하는 것을 방지
 */
const loadKey = () => {
  const keyHex = process.env.AES_KEY;

  if (!keyHex) {
    throw new Error(
      '[F-08] AES_KEY 환경변수가 설정되지 않았습니다. ' +
      '규칙 3에 따라 암호화 키는 환경변수로만 관리합니다.'
    );
  }

  const key = Buffer.from(keyHex, 'hex');

  if (key.length !== KEY_LENGTH) {
    throw new Error(
      `[F-08] AES_KEY 길이 오류: ${key.length}바이트. ` +
      'AES-256은 32바이트(hex 64자)여야 합니다.'
    );
  }

  return key;
};

/**
 * AES-256-GCM 암호화
 * - IV는 암호화마다 새로 생성 (재사용 시 GCM 보안 완전 붕괴, NIST SP 800-38D)
 *
 * @param {string} plaintext 평문
 * @returns {string|null} "IV(24자):AuthTag(32자):암호문" 형태
 */
const encrypt = (plaintext) => {
  if (plaintext === null || plaintext === undefined || plaintext === '') {
    return null;
  }

  const key = loadKey();

  // Math.random() 사용 금지 (NIST SP 800-90A)
  const iv = nodeCrypto.randomBytes(IV_LENGTH);

  const cipher = nodeCrypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(String(plaintext), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // 복호화 시 IV·AuthTag가 모두 필요하므로 함께 저장
  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
};

/**
 * AES-256-GCM 복호화
 * - 인증 태그 검증 필수. 불일치 = 데이터 변조 → 즉시 처리 중단 (F-08 §3)
 * - 관리자 전용. 일반 API 응답에 복호화 결과를 노출하지 않는다.
 *
 * @param {string} ciphertext encrypt()가 반환한 문자열
 * @returns {string|null} 복호화된 평문
 */
const decrypt = (ciphertext) => {
  if (!ciphertext) return null;

  const parts = String(ciphertext).split(':');

  if (parts.length !== 3) {
    throw new Error('[F-08] 암호문 형식 오류: IV:AuthTag:암호문 형태가 아닙니다.');
  }

  const [ivHex, authTagHex, encrypted] = parts;
  const key = loadKey();

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  if (iv.length !== IV_LENGTH) {
    throw new Error(`[F-08] IV 길이 오류: ${iv.length}바이트 (12바이트여야 함)`);
  }

  const decipher = nodeCrypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  try {
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');   // ← 여기서 인증 태그 검증됨
    return decrypted;
  } catch (error) {
    // 태그 불일치 = 변조 감지. 원본 에러를 그대로 노출하지 않는다.
    throw new Error('[F-08] 무결성 검증 실패: 데이터가 변조되었을 수 있습니다.');
  }
};

/**
 * 객체를 통째로 암호화 (감사 로그 meta 필드 등)
 */
const encryptObject = (obj) => {
  if (obj === null || obj === undefined) return null;
  return encrypt(JSON.stringify(obj));
};

const decryptObject = (ciphertext) => {
  const json = decrypt(ciphertext);
  return json ? JSON.parse(json) : null;
};

/**
 * AES 키 신규 생성용 유틸 (최초 1회 / 6개월 로테이션 시)
 * 출력값을 .env의 AES_KEY에 넣는다.
 */
const generateKey = () => nodeCrypto.randomBytes(KEY_LENGTH).toString('hex');

module.exports = {
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  generateKey,
};
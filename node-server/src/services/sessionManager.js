const { redisClient, db } = require('../../config/db');
const { hashForSessionBinding } = require('../utils/anonymize');

const {
  createSession,
  refreshSession,
  updateSessionStatus,
  deleteSession: _deleteSession
} = require('./session');


/**
 * ============================================================
 * 세션 생성
 * ============================================================
 *
 * token 형식:
 *   {userId}:{sessionId}
 *
 * 세션 바인딩:
 *   IP
 *   User-Agent
 *   Fingerprint
 *
 * initialStatus:
 *   ACTIVE
 *   RE_AUTH
 *   BLOCKED
 */
exports.createSession = async (
    userId,
    ip,
    userAgent,
    fingerprint,
    initialStatus = 'ACTIVE'
) => {
  const ipHash = hashForSessionBinding(ip || '');
  const uaHash = hashForSessionBinding(userAgent || '');
  const fpHash = hashForSessionBinding(fingerprint || '');

  // session.js:
  // createSession(
  //   userId,
  //   ipHash,
  //   deviceIdHash,
  //   fingerprintHash,
  //   initialStatus
  // )
  const sessionId = await createSession(
      userId,
      ipHash,
      uaHash,
      fpHash,
      initialStatus
  );

  const token = `${userId}:${sessionId}`;

  return { token };
};


/**
 * ============================================================
 * 세션 검증
 * ============================================================
 *
 * 1. blacklist 확인
 * 2. Redis 세션 조회
 * 3. BLOCKED 확인
 * 4. RE_AUTH Lazy Check
 * 5. ACTIVE 확인
 * 6. IP + User-Agent 세션 바인딩 확인
 * 7. 정상 세션이면 사용자 정보 반환
 */
exports.verifySession = async (
    token,
    currentIp,
    currentUserAgent
) => {
  console.log('verifySession 호출됨, token:', token);

  if (!token || typeof token !== 'string') {
    return {
      valid: false,
      reason: 'INVALID_SESSION_TOKEN'
    };
  }

  // ----------------------------------------------------------
  // 1. 명시적으로 폐기된 토큰 확인
  // ----------------------------------------------------------
  const isBlacklisted =
      await redisClient.get(`blacklist:${token}`);

  if (isBlacklisted) {
    return {
      valid: false,
      reason: 'BLACKLISTED_TOKEN'
    };
  }

  // ----------------------------------------------------------
  // 2. userId / sessionId 분리
  // ----------------------------------------------------------
  const [tokenUserId, tokenSessionId] =
      token.split(':');

  if (!tokenUserId || !tokenSessionId) {
    return {
      valid: false,
      reason: 'INVALID_SESSION_TOKEN'
    };
  }

  // ----------------------------------------------------------
  // 3. Redis 세션 조회
  // ----------------------------------------------------------
  const session =
      await refreshSession(
          tokenUserId,
          tokenSessionId
      );

  if (!session) {
    return {
      valid: false,
      reason: 'SESSION_NOT_FOUND'
    };
  }

  // ----------------------------------------------------------
  // 4. 이미 차단된 세션
  // ----------------------------------------------------------
  if (session.status === 'BLOCKED') {
    return {
      valid: false,
      reason: 'SESSION_BLOCKED'
    };
  }

  // ----------------------------------------------------------
  // 5. RE_AUTH Lazy Check
  //
  // reauth:{userId}가 존재하면 추가 인증 대기 상태.
  //
  // Redis TTL 만료로 reauth 키가 사라졌는데
  // 세션이 여전히 RE_AUTH라면 fail-secure 방식으로 BLOCKED.
  // ----------------------------------------------------------
  if (session.status === 'RE_AUTH') {
    const reauthState =
        await redisClient.get(
            `reauth:${tokenUserId}`
        );

    if (reauthState) {
      return {
        valid: false,
        reason: 'REAUTH_REQUIRED',
        requiresReauthentication: true,
        userId: tokenUserId
      };
    }

    // reauth TTL 만료
    await updateSessionStatus(
        tokenUserId,
        tokenSessionId,
        'BLOCKED'
    );

    return {
      valid: false,
      reason: 'REAUTH_EXPIRED'
    };
  }

  // ----------------------------------------------------------
  // 6. ACTIVE 이외의 알 수 없는 상태 차단
  // ----------------------------------------------------------
  if (session.status !== 'ACTIVE') {
    return {
      valid: false,
      reason: 'SESSION_NOT_ACTIVE'
    };
  }

  // ----------------------------------------------------------
  // 7. 현재 요청의 세션 바인딩 값 계산
  // ----------------------------------------------------------
  const currentIpHash =
      hashForSessionBinding(
          currentIp || ''
      );

  const currentUaHash =
      hashForSessionBinding(
          currentUserAgent || ''
      );

  let mismatchCount = 0;

  // session.js의 필드명:
  // ip       -> IP binding hash
  // deviceId -> User-Agent binding hash
  if (session.ip !== currentIpHash) {
    mismatchCount += 1;
  }

  if (session.deviceId !== currentUaHash) {
    mismatchCount += 1;
  }

  // ----------------------------------------------------------
  // 8. AiTM / 세션 탈취 의심
  //
  // IP + User-Agent가 둘 다 변경된 경우 즉시 세션 삭제.
  //
  // F-09 정책:
  // 이 경우 blacklist를 생성하지 않고 세션 자체를 제거.
  // ----------------------------------------------------------
  if (mismatchCount >= 2) {
    await _deleteSession(
        tokenUserId,
        tokenSessionId
    );

    console.warn(
        '[SESSION_HIJACK_SUSPECTED]',
        {
          userId: tokenUserId,
          sessionId: tokenSessionId
        }
    );

    return {
      valid: false,
      reason: 'SESSION_HIJACK_SUSPECTED'
    };
  }

  // ----------------------------------------------------------
  // 9. 사용자 정보 조회
  // ----------------------------------------------------------
  const [rows] =
      await db.query(
          'SELECT username FROM users WHERE id = ?',
          [tokenUserId]
      );

  const username =
      rows[0]?.username;

  if (!username) {
    return {
      valid: false,
      reason: 'USER_NOT_FOUND'
    };
  }

  return {
    valid: true,
    username,
    userId: tokenUserId
  };
};


/**
 * ============================================================
 * 일반 세션 삭제
 * ============================================================
 *
 * 로그아웃 등 명시적인 세션 폐기 시 사용.
 * 남은 세션 TTL 동안 blacklist 토큰을 유지한다.
 */
exports.deleteSession = async (token) => {
  if (!token || typeof token !== 'string') {
    return {
      success: false,
      reason: 'INVALID_SESSION_TOKEN'
    };
  }

  const [tokenUserId, tokenSessionId] =
      token.split(':');

  if (!tokenUserId || !tokenSessionId) {
    return {
      success: false,
      reason: 'INVALID_SESSION_TOKEN'
    };
  }

  const sessionKey =
      `session:${tokenUserId}:${tokenSessionId}`;

  const ttl =
      await redisClient.ttl(sessionKey);

  if (ttl > 0) {
    await redisClient.set(
        `blacklist:${token}`,
        '1',
        { EX: ttl }
    );
  }

  await _deleteSession(
      tokenUserId,
      tokenSessionId
  );

  return {
    success: true
  };
};


/**
 * session.js의 상태 변경 함수 외부 제공
 */
exports.updateSessionStatus =
    updateSessionStatus;
const { redisClient } = require('../../config/db');
const { anonymizeRandom } = require('../utils/anonymize');

const {
  createSession,
  refreshSession,
  updateSessionStatus,
  getReauthState,
  deleteSession: _deleteSession
} = require('./session');


// ============================================================
// Session 생성
// ============================================================

exports.createSession = async (
    username,
    ip,
    deviceId
) => {
  const ipHash =
      anonymizeRandom(ip);

  const deviceIdHash =
      anonymizeRandom(deviceId);

  const sessionId =
      await createSession(
          username,
          ipHash,
          deviceIdHash
      );

  const token =
      `${username}:${sessionId}`;

  return {
    token
  };
};


// ============================================================
// Session 검증
//
// RE-AUTH 상태에서는 Keyspace Notification을 사용하지 않고
// 세션 검증 시점에 reauth:{userId} 존재 여부를 확인한다.
//
// session.status === RE-AUTH
// + reauth:{userId} === PENDING
//   -> 재인증 대기
//
// session.status === RE-AUTH
// + reauth:{userId} 없음
//   -> TTL 만료로 판단
//   -> Session BLOCKED
// ============================================================

exports.verifySession = async (token) => {
  console.log(
      'verifySession 호출됨, token:',
      token
  );


  // ========================================================
  // 1. Token blacklist 확인
  // ========================================================

  const isBlacklisted =
      await redisClient.get(
          `blacklist:${token}`
      );

  if (isBlacklisted) {
    return {
      valid: false,
      reason: '블랙리스트 토큰'
    };
  }


  // ========================================================
  // 2. Token 파싱
  // ========================================================

  const [
    tokenUsername,
    tokenSessionId
  ] = token.split(':');


  if (
      !tokenUsername
      ||
      !tokenSessionId
  ) {
    return {
      valid: false,
      reason: 'INVALID_SESSION_TOKEN'
    };
  }


  // ========================================================
  // 3. Session 조회 + Sliding TTL 갱신
  // ========================================================

  const session =
      await refreshSession(
          tokenUsername,
          tokenSessionId
      );


  if (!session) {
    return {
      valid: false,
      reason: 'SESSION_EXPIRED'
    };
  }


  // ========================================================
  // 4. 이미 BLOCKED 상태
  // ========================================================

  if (
      session.status === 'BLOCKED'
  ) {
    console.log(
        '[SESSION][BLOCKED]',
        {
          username:
          tokenUsername,

          sessionId:
          tokenSessionId
        }
    );

    return {
      valid: false,
      reason: 'SESSION_BLOCKED'
    };
  }


  // ========================================================
  // 5. RE-AUTH 상태 확인
  //
  // Keyspace Notification 대신 Lazy Check
  // ========================================================

  if (
      session.status === 'RE-AUTH'
  ) {
    const reauthState =
        await getReauthState(
            tokenUsername
        );


    // ------------------------------------------------------
    // 아직 TTL 3분 이내
    // ------------------------------------------------------

    if (
        reauthState === 'PENDING'
    ) {
      console.log(
          '[REAUTH][PENDING]',
          {
            username:
            tokenUsername,

            sessionId:
            tokenSessionId
          }
      );

      return {
        valid: false,
        reason: 'REAUTH_REQUIRED',
        requiresReauthentication: true
      };
    }


    // ------------------------------------------------------
    // session은 RE-AUTH인데
    // reauth key가 없음
    //
    // => Redis TTL 만료로 판단
    // => Session BLOCKED
    // ------------------------------------------------------

    const blocked =
        await updateSessionStatus(
            tokenUsername,
            tokenSessionId,
            'BLOCKED'
        );


    console.log(
        '[REAUTH][EXPIRED]',
        {
          username:
          tokenUsername,

          sessionId:
          tokenSessionId,

          sessionBlocked:
          blocked
        }
    );


    return {
      valid: false,
      reason: 'REAUTH_EXPIRED',
      requiresReauthentication: false
    };
  }


  // ========================================================
  // 6. 정상 ACTIVE Session
  // ========================================================

  return {
    valid: true,
    username: tokenUsername,
    sessionId: tokenSessionId,
    status: session.status || 'ACTIVE'
  };
};


// ============================================================
// Session 삭제
// ============================================================

exports.deleteSession = async (token) => {
  const [
    tokenUsername,
    tokenSessionId
  ] = token.split(':');


  if (
      !tokenUsername
      ||
      !tokenSessionId
  ) {
    return {
      success: false,
      reason: 'INVALID_SESSION_TOKEN'
    };
  }


  const sessionKey =
      `session:${tokenUsername}:${tokenSessionId}`;


  const ttl =
      await redisClient.ttl(
          sessionKey
      );


  // ========================================================
  // 남은 Session TTL 동안 Token blacklist
  // ========================================================

  if (ttl > 0) {
    await redisClient.set(
        `blacklist:${token}`,
        '1',
        {
          EX: ttl
        }
    );
  }


  // ========================================================
  // Session 삭제
  // ========================================================

  await _deleteSession(
      tokenUsername,
      tokenSessionId
  );


  return {
    success: true
  };
};
const { redisClient } = require('../../config/db');

const TTL = {
  SESSION:          parseInt(process.env.SESSION_TTL, 10)          || 1800,
  SESSION_ABSOLUTE: parseInt(process.env.SESSION_ABSOLUTE_TTL, 10) || 28800,
  REAUTH:           parseInt(process.env.REAUTH_TTL, 10)           || 180,
  BLOCK:            parseInt(process.env.BLOCK_TTL, 10)            || 86400,
};


// ============================================================
// 세션 생성
// ============================================================

const createSession = async (userId, ipHash, deviceIdHash) => {
  const { v4: uuidv4 } = require('uuid');

  const sessionId = uuidv4();
  const key = `session:${userId}:${sessionId}`;
  const now = new Date().toISOString();

  const data = JSON.stringify({
    sessionId,
    issuedAt: now,
    lastActivity: now,
    status: 'ACTIVE',
    ip: ipHash,
    deviceId: deviceIdHash,
  });

  await redisClient.set(
      key,
      data,
      {
        EX: TTL.SESSION,
      }
  );

  return sessionId;
};


// ============================================================
// 슬라이딩 TTL 갱신
// ============================================================

const refreshSession = async (userId, sessionId) => {
  const key = `session:${userId}:${sessionId}`;

  const raw = await redisClient.get(key);

  if (!raw) {
    return null;
  }

  const session = JSON.parse(raw);

  // 절대 만료 체크
  const elapsed =
      Date.now()
      - new Date(session.issuedAt).getTime();

  if (
      elapsed
      > TTL.SESSION_ABSOLUTE * 1000
  ) {
    await redisClient.del(key);

    return null;
  }

  session.lastActivity =
      new Date().toISOString();

  await redisClient.set(
      key,
      JSON.stringify(session),
      {
        EX: TTL.SESSION,
      }
  );

  return session;
};


// ============================================================
// 세션 상태 변경
// ACTIVE / RE-AUTH / BLOCKED
// ============================================================

const updateSessionStatus = async (
    userId,
    sessionId,
    status
) => {
  const key =
      `session:${userId}:${sessionId}`;

  const raw =
      await redisClient.get(key);

  if (!raw) {
    return false;
  }

  const session =
      JSON.parse(raw);

  session.status =
      status;

  // 기존 TTL 유지
  const remainingTTL =
      await redisClient.ttl(key);

  if (remainingTTL === -2) {
    return false;
  }

  if (remainingTTL === -1) {
    console.warn(
        `세션에 TTL이 없는 비정상 상태 발견: ${key}`
    );

    await redisClient.del(key);

    return false;
  }

  if (remainingTTL <= 0) {
    await redisClient.del(key);

    return false;
  }

  await redisClient.set(
      key,
      JSON.stringify(session),
      {
        EX: remainingTTL,
      }
  );

  return true;
};


// ============================================================
// 재인증 대기 상태 생성
//
// key:
// reauth:{userId}
//
// value:
// PENDING
//
// TTL:
// REAUTH_TTL
// 기본 180초
// ============================================================

const createReauthState = async (userId) => {
  if (!userId) {
    return false;
  }

  const key =
      `reauth:${userId}`;

  await redisClient.set(
      key,
      'PENDING',
      {
        EX: TTL.REAUTH,
      }
  );

  console.log(
      '[REAUTH][PENDING]',
      {
        key,
        ttl: TTL.REAUTH,
      }
  );

  return true;
};


// ============================================================
// 재인증 상태 조회
// ============================================================

const getReauthState = async (userId) => {
  if (!userId) {
    return null;
  }

  const key =
      `reauth:${userId}`;

  return redisClient.get(key);
};


// ============================================================
// 재인증 완료
//
// Passkey 재인증 성공 시 reauth 키 삭제
// ============================================================

const completeReauth = async (userId) => {
  if (!userId) {
    return false;
  }

  const key =
      `reauth:${userId}`;

  const deleted =
      await redisClient.del(key);

  if (deleted > 0) {
    console.log(
        '[REAUTH][COMPLETED]',
        {
          key,
        }
    );
  }

  return deleted > 0;
};


// ============================================================
// 재인증 TTL 조회
// 테스트 / 상태 확인용
// ============================================================

const getReauthTTL = async (userId) => {
  if (!userId) {
    return -2;
  }

  return redisClient.ttl(
      `reauth:${userId}`
  );
};


// ============================================================
// 세션 삭제
// ============================================================

const deleteSession = async (
    userId,
    sessionId
) => {
  await redisClient.del(
      `session:${userId}:${sessionId}`
  );
};


module.exports = {
  createSession,
  refreshSession,
  updateSessionStatus,
  deleteSession,

  createReauthState,
  getReauthState,
  completeReauth,
  getReauthTTL,
};
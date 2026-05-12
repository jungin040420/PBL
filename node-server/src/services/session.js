const { redisClient } = require('../../config/db');

const TTL = {
  SESSION:          parseInt(process.env.SESSION_TTL)          || 1800,
  SESSION_ABSOLUTE: parseInt(process.env.SESSION_ABSOLUTE_TTL) || 28800,
  REAUTH:           parseInt(process.env.REAUTH_TTL)           || 180,
  BLOCK:            parseInt(process.env.BLOCK_TTL)            || 86400,
};

// 세션 생성 (로그인 성공 시 호출)
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
    ip: ipHash,           // F-08 비식별화 처리된 값
    deviceId: deviceIdHash,
  });

  await redisClient.set(key, data, { EX: TTL.SESSION });
  return sessionId;
};

// 슬라이딩 TTL 갱신 (API 호출, 페이지 이동, 버튼 클릭 시)
const refreshSession = async (userId, sessionId) => {
  const key = `session:${userId}:${sessionId}`;
  const raw = await redisClient.get(key);
  if (!raw) return null;

  const session = JSON.parse(raw);

  // 절대 만료 체크 (issuedAt 기준 8시간)
  const elapsed = Date.now() - new Date(session.issuedAt).getTime();
  if (elapsed > TTL.SESSION_ABSOLUTE * 1000) {
    await redisClient.del(key);
    return null;
  }

  session.lastActivity = new Date().toISOString();
  await redisClient.set(key, JSON.stringify(session), { EX: TTL.SESSION });
  return session;
};

// 세션 상태 변경 (ACTIVE / RE-AUTH / BLOCKED)
const updateSessionStatus = async (userId, sessionId, status) => {
  const key = `session:${userId}:${sessionId}`;
  const raw = await redisClient.get(key);
  if (!raw) return false;

  const session = JSON.parse(raw);
  session.status = status;

  // TTL 유지하면서 값만 업데이트
  const remainingTTL = await redisClient.ttl(key);
  await redisClient.set(key, JSON.stringify(session), { EX: remainingTTL });
  return true;
};

// 세션 삭제
const deleteSession = async (userId, sessionId) => {
  await redisClient.del(`session:${userId}:${sessionId}`);
};

module.exports = { createSession, refreshSession, updateSessionStatus, deleteSession };
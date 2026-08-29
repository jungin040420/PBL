const { redisClient, db } = require('../../config/db');
const { hashForSessionBinding } = require('../utils/anonymize');
const {
  createSession,
  refreshSession,
  updateSessionStatus,
  deleteSession: _deleteSession
} = require('./session');

exports.createSession = async (userId, ip, userAgent, fingerprint, initialStatus = 'ACTIVE') => {
  const ipHash = hashForSessionBinding(ip || '');
  const uaHash = hashForSessionBinding(userAgent || '');
  const fpHash = hashForSessionBinding(fingerprint || '');

  const sessionId = await createSession(userId, ipHash, uaHash, fpHash, initialStatus);
  const token = `${userId}:${sessionId}`;
  return { token };
};

exports.verifySession = async (token, currentIp, currentUserAgent) => {
  if (!token || typeof token !== 'string') {
    return { valid: false, reason: 'INVALID_SESSION_TOKEN' };
  }

  const isBlacklisted = await redisClient.get(`blacklist:${token}`);
  if (isBlacklisted) {
    return { valid: false, reason: 'BLACKLISTED_TOKEN' };
  }

  const [tokenUserId, tokenSessionId] = token.split(':');
  if (!tokenUserId || !tokenSessionId) {
    return { valid: false, reason: 'INVALID_SESSION_TOKEN' };
  }

  const session = await refreshSession(tokenUserId, tokenSessionId);
  if (!session) {
    return { valid: false, reason: 'SESSION_NOT_FOUND' };
  }

  if (session.status === 'BLOCKED') {
    return { valid: false, reason: 'SESSION_BLOCKED' };
  }

  // RE_AUTH lazy check
  if (session.status === 'RE_AUTH') {
    const stepupState = await redisClient.get(`stepup:${tokenUserId}`);

    if (stepupState) {
      return {
        valid: false,
        reason: 'REAUTH_REQUIRED',
        requiresReauthentication: true,
        userId: tokenUserId
      };
    }

    // stepup TTL 만료
    await updateSessionStatus(tokenUserId, tokenSessionId, 'BLOCKED');
    return { valid: false, reason: 'REAUTH_EXPIRED' };
  }

  // ACTIVE 이외의 알 수 없는 상태 차단
  if (session.status !== 'ACTIVE') {
    return { valid: false, reason: 'SESSION_NOT_ACTIVE' };
  }

  // 세션 바인딩 값 비교
  const currentIpHash = hashForSessionBinding(currentIp || '');
  const currentUaHash = hashForSessionBinding(currentUserAgent || '');

  let mismatchCount = 0;
  if (session.ip !== currentIpHash) mismatchCount += 1;
  if (session.deviceId !== currentUaHash) mismatchCount += 1;

  // IP + UA 둘 다 변경 시 세션 하이재킹 의심 → 즉시 삭제
  if (mismatchCount >= 2) {
    await _deleteSession(tokenUserId, tokenSessionId);
    console.warn('[SESSION_HIJACK_SUSPECTED]', { userId: tokenUserId, sessionId: tokenSessionId });
    return { valid: false, reason: 'SESSION_HIJACK_SUSPECTED' };
  }

  const [rows] = await db.query('SELECT username FROM users WHERE id = ?', [tokenUserId]);
  const username = rows[0]?.username;

  if (!username) {
    return { valid: false, reason: 'USER_NOT_FOUND' };
  }

  return { valid: true, username, userId: tokenUserId };
};

// 일반 세션 삭제
exports.deleteSession = async (token) => {
  if (!token || typeof token !== 'string') {
    return { success: false, reason: 'INVALID_SESSION_TOKEN' };
  }

  const [tokenUserId, tokenSessionId] = token.split(':');
  if (!tokenUserId || !tokenSessionId) {
    return { success: false, reason: 'INVALID_SESSION_TOKEN' };
  }

  const sessionKey = `session:${tokenUserId}:${tokenSessionId}`;
  const ttl = await redisClient.ttl(sessionKey);
  if (ttl > 0) {
    await redisClient.set(`blacklist:${token}`, '1', { EX: ttl });
  }

  await _deleteSession(tokenUserId, tokenSessionId);
  return { success: true };
};

exports.updateSessionStatus = updateSessionStatus;
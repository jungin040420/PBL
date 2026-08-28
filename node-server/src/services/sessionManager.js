const { redisClient, db } = require('../../config/db');
const { hashForSessionBinding } = require('../utils/anonymize'); 
const {
  createSession,
  refreshSession,
  updateSessionStatus,
  deleteSession: _deleteSession
} = require('./session');

exports.createSession = async (userId, ip, userAgent, fingerprint, initialStatus = 'ACTIVE') => {
  const ipHash = hashForSessionBinding(ip);
  const uaHash = hashForSessionBinding(userAgent);
  const fpHash = hashForSessionBinding(fingerprint || '')

  const sessionId = await createSession(userId, ipHash, uaHash, initialStatus);
  const token = `${username}:${sessionId}`;
  return { token };
};

exports.verifySession = async (token, currentIp, currentUserAgent) => {
  console.log('verifySession 호출됨, token:', token);

  const isBlacklisted = await redisClient.get(`blacklist:${token}`);
  if (isBlacklisted) {
    return { valid: false, reason: '블랙리스트 토큰' };
  }

  const [tokenUserId, tokenSessionId] = token.split(':');
  
  if (!tokenUserId || !tokenSessionId) {
    return { valid: false };
  }

  const session = await refreshSession(tokenUserId, tokenSessionId);
  if (!session) {
    return { valid: false };
  }

  if (session.status !== 'ACTIVE') {
    return { valid: false, reason: 'SESSION_NOT_ACTIVE' };
  }

  const currentIpHash = hashForSessionBinding(currentIp || '');
  const currentUaHash = hashForSessionBinding(currentUserAgent || '');

  let mismatchCount = 0;
  if (session.ip !== currentIpHash) mismatchCount += 1;       // ← session.js 필드명: ip
  if (session.deviceId !== currentUaHash) mismatchCount += 1; // ← session.js 필드명: deviceId

  if (mismatchCount >= 2) {
    await exports.deleteSession(token);
    return { valid: false, reason: 'SESSION_HIJACK_SUSPECTED' };
  }

  const [rows] = await db.query('SELECT username FROM users WHERE id = ?', [tokenUserId]);
  const username = rows[0]?.username;

  return { valid: true, username, userId: tokenUserId };
};

exports.deleteSession = async (token) => {
  const [tokenUserId, tokenSessionId] = token.split(':');

  const ttl = await redisClient.ttl(`session:${tokenUserId}:${tokenSessionId}`);

  if (ttl > 0) {
    await redisClient.set(
      `blacklist:${token}`,
      '1',
      { EX: ttl }
    );
  }
  
  await _deleteSession(tokenUserId, tokenSessionId);

  return { success: true };
};

exports.updateSessionStatus = updateSessionStatus;
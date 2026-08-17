const { redisClient } = require('../../config/db');
const { anonymizeRandom } = require('../utils/anonymize'); 
const {
  createSession,
  refreshSession,
  updateSessionStatus,
  deleteSession: _deleteSession
} = require('./session');

exports.createSession = async (username, ip, deviceId) => {
  const ipHash = anonymizeRandom(ip);
  const deviceIdHash = anonymizeRandom(deviceId);

  const sessionId = await createSession(username, ipHash, deviceIdHash);
  const token = `${username}:${sessionId}`;
  return { token };
};

exports.verifySession = async (token) => {
  console.log('verifySession 호출됨, token:', token);

  const isBlacklisted = await redisClient.get(`blacklist:${token}`);
  if (isBlacklisted) {
    return { valid: false, reason: '블랙리스트 토큰' };
  }

  const [tokenUsername, tokenSessionId] = token.split(':');
  
  if (!tokenUsername || !tokenSessionId) {
    return { valid: false };
  }

  const session = await refreshSession(tokenUsername, tokenSessionId);
  if (!session) {
    return { valid: false };
  }

  return { valid: true, username: tokenUsername };
};

exports.deleteSession = async (token) => {
  const [tokenUsername, tokenSessionId] = token.split(':');

  const ttl = await redisClient.ttl(`session:${tokenUsername}:${tokenSessionId}`);

  if (ttl > 0) {
    await redisClient.set(
      `blacklist:${token}`,
      '1',
      { EX: ttl }
    );
  }
  
  await _deleteSession(tokenUsername, tokenSessionId);

  return { success: true };
};
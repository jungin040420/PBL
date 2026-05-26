const { redisClient } = require('../../config/db'); 
const {
  createSession,
  refreshSession,
  updateSessionStatus,
  deleteSession: _deleteSession
} = require('./session');

exports.createSession = async (username, ip, deviceId) => {
  const sessionId = await createSession(username, ip, deviceId);
  const token = `${username}:${sessionId}`;
  return { token };
};

exports.verifySession = async (token) => {

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
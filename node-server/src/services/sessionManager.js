const { redisClient } = require('../../config/db'); 
const {createSession,
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
  const decodedToken = decodeURIComponent(token);
  console.log('verifySession 호출됨, token:', token);

  const isBlacklisted = await redisClient.get(`blacklist:${decodedToken}`);
  if (isBlacklisted) {
    return { valid: false, reason: '블랙리스트 토큰' };
  }

  const [tokenUsername, ...rest] = decodedToken.split(':');
  const tokenSessionId = rest.join(':');
  
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
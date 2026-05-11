const crypto = require('crypto');
const { redisClient } = require('../../config/db');

exports.createSession = async (username) => {
  const sessionToken = crypto.randomBytes(32).toString('hex');
  const TTL = 60 * 60;

  await redisClient.set(
    `session:${sessionToken}`,
    JSON.stringify({ username, createdAt: new Date().toISOString() }),
    { EX: TTL }
  );

  return { token: sessionToken };
};

exports.verifySession = async (sessionToken) => {
  const isBlacklisted = await redisClient.get(`blacklist:${sessionToken}`);
  if (isBlacklisted) {
    return { valid: false, reason: '블랙리스트 토큰' };
  }

  const data = await redisClient.get(`session:${sessionToken}`);
  if (!data) {
    return { valid: false };
  }

  return { valid: true, username: JSON.parse(data).username };
};

exports.deleteSession = async (sessionToken) => {
  const ttl = await redisClient.ttl(`session:${sessionToken}`);
  
  if (ttl > 0) {
    await redisClient.set(
      `blacklist:${sessionToken}`,
      '1',
      { EX: ttl } 
    );
  }
  await redisClient.del(`session:${sessionToken}`);
  
  return { success: true };
};
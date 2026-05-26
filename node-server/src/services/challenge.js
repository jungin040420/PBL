const { redisClient } = require('../../config/db');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const CHALLENGE_TTL = parseInt(process.env.CHALLENGE_TTL) || 60;

// challenge 생성 및 Redis 저장
const storeChallenge = async (userId) => {
  const challengeId = uuidv4();
  const challengeValue = crypto.randomBytes(32).toString('base64url');
  const key = `challenge:${userId}:${challengeId}`;

  const data = JSON.stringify({
    challengeValue,
    createdAt: new Date().toISOString(),
    isUsed: false,
  });

  await redisClient.set(key, data, { EX: CHALLENGE_TTL });
  return { challengeId, challengeValue };
};

// challenge 검증 + 사용 처리 (재사용 공격 방지)
const verifyChallenge = async (userId, challengeId, submittedValue) => {
  const key = `challenge:${userId}:${challengeId}`;
  console.log('조회할 key:', key);

  const raw = await redisClient.get(key);
  console.log('Redis에서 조회된 값:', raw);

  if (!raw) return { valid: false, reason: 'EXPIRED_OR_NOT_FOUND' };

  const challenge = JSON.parse(raw);

  if (challenge.isUsed) return { valid: false, reason: 'ALREADY_USED' };
  if (challenge.challengeValue !== submittedValue) return { valid: false, reason: 'VALUE_MISMATCH' };

  // 사용 처리
  const remainingTTL = await redisClient.ttl(key);
  challenge.isUsed = true;
  await redisClient.set(key, JSON.stringify(challenge), { EX: remainingTTL });

  return { valid: true };
};

module.exports = { storeChallenge, verifyChallenge };
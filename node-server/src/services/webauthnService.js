const crypto = require('crypto');
const { db, redisClient } = require('../../config/db');
const { storeChallenge } = require('./challenge'); // ← 상단으로 이동
const rpId = process.env.RP_ID || 'localhost';

exports.generateRegistrationOptions = async (username, displayName) => {

  const { challengeId, challengeValue } = await storeChallenge(username);

  const userId = crypto.randomBytes(8).toString('base64url');

  

  return { 
    challenge: challengeValue,
    challengeId,
    userId,
    rpId,
  };
};

exports.generateLoginOptions = async (username) => {

  const storeResult = await storeChallenge(username);
  console.log('storeChallenge 반환값:', storeResult);

  const { challengeId, challengeValue } = await storeChallenge(username);
  console.log('challengeId:', challengeId);            // ← 추가
  console.log('challengeValue:', challengeValue);

  const [rows] = await db.query(
    `SELECT p.credential_id FROM passkeys p
     JOIN users u ON p.user_id = u.id
     WHERE u.username = ?
     AND p.is_active = 1`,
    [username]
  );

  const allowCredentials = rows.map(row => ({
    id: row.credential_id,
    type: 'public-key',
  }));

  console.log('반환할 challengeId:', challengeId);

  return { 
    challenge: challengeValue,
    challengeId,
    rpId,
    allowCredentials,
  };
};
// webauthnService.js
const crypto = require('crypto');
const { db, redisClient } = require('../../config/db');
const rpId = process.env.RP_ID || 'localhost';

exports.generateRegistrationOptions = async (username, displayName) => {
  // 랜덤 challenge 생성 후 base64로 변환
  const challenge = crypto.randomBytes(32)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  const setResult = await redisClient.set(`challenge:${username}`, challenge, {EX: 300});
  
  const saved = await redisClient.get(`challenge:${username}`);    

  const ttl = await redisClient.ttl(`challenge:${username}`);
  console.log('TTL:', ttl);
  
  const userId = crypto.randomBytes(8).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return { challenge, userId, rpId, };
};

exports.generateLoginOptions = async (username) => {
  const challenge = crypto.randomBytes(32).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  //challenge 저장
  const setResult = await redisClient.set(`challenge:${username}`, challenge, {EX: 300});

  const saved = await redisClient.get(`challenge:${username}`);

  const [rows] = await db.query(
    `SELECT p.credential_id FROM passkeys p
     JOIN users u ON p.user_id = u.id
     WHERE u.username = ?`,
    [username]
  ); 

  console.log('조회 결과 rows:', rows);

  const allowCredentials = rows.map(row => ({
    id: row.credential_id,
    type: 'public-key',
  })); 

  // 정상 실행 시 삭제
  console.log('DB에서 조회된 rows:', rows);
  console.log('allowCredentials:', allowCredentials);

  return { challenge, rpId, allowCredentials};
};
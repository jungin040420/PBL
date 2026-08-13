const crypto = require('crypto');
const { db } = require('../../config/db');
const { storeChallenge } = require('./challenge');

const rpId = process.env.RP_ID || 'localhost';


// ============================================================
// 등록 Challenge 생성
// ============================================================

exports.generateRegistrationOptions = async (
    username,
    displayName
) => {

  const {
    challengeId,
    challengeValue
  } = await storeChallenge(username);

  const userId =
      crypto.randomBytes(8).toString('base64url');

  return {
    challenge: challengeValue,
    challengeId,
    userId,
    rpId,
  };
};


// ============================================================
// 로그인 Challenge 생성
// ============================================================

exports.generateLoginOptions = async (
    username
) => {

  // 로그인 시작 1회당 Challenge 1개만 생성
  const {
    challengeId,
    challengeValue
  } = await storeChallenge(username);

  console.log(
      'challengeId:',
      challengeId
  );

  console.log(
      'challengeValue:',
      challengeValue
  );

  const [rows] = await db.query(
      `
      SELECT
        p.credential_id
      FROM passkeys p
      JOIN users u
        ON p.user_id = u.id
      WHERE u.username = ?
        AND p.is_active = 1
    `,
      [username]
  );

  const allowCredentials =
      rows.map(row => ({
        id: row.credential_id,
        type: 'public-key',
      }));

  console.log(
      '반환할 challengeId:',
      challengeId
  );

  return {
    challenge: challengeValue,
    challengeId,
    rpId,
    allowCredentials,
  };
};
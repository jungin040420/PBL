const crypto = require('crypto');
const { db } = require('../../config/db');
const { storeChallenge } = require('../services/challenge'); 
const rpId = process.env.RP_ID || 'localhost';

exports.generateRegistrationOptions = async (username, displayName) => {

  const { challengeId, challengeValue } = await storeChallenge();

  const userId = crypto.randomBytes(8).toString('base64url');

  return { 
    challenge: challengeValue,
    challengeId,
    userId,
    rpId,
    userVerification: 'required',
  };
};

exports.generateLoginOptions = async (username) => {

  const { challengeId, challengeValue } = await storeChallenge();
  
  //추후에 제거
  console.log('challengeId:', challengeId);            
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
    userVerification: 'required',
  };
};
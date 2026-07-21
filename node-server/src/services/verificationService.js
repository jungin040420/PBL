const { 
  verifyRegistrationResponse,
  verifyAuthenticationResponse 
} = require('@simplewebauthn/server');
const { db } = require('../../config/db');
const { verifyChallenge } = require('./challenge');

const rpID = process.env.RP_ID || 'localhost';

exports.verifyRegistration = async (username, email, challengeId, credential) => {

  const clientDataJSON = JSON.parse(
    Buffer.from(credential.response.clientDataJSON, 'base64url').toString('utf8')
  );
  const submittedChallenge = clientDataJSON.challenge;
  console.log('submittedChallenge:', submittedChallenge);

  const challengeResult = await verifyChallenge(
    username,
    challengeId,
    submittedChallenge
  );

  if (!challengeResult.valid) {
    throw new Error(`challenge 검증 실패: ${challengeResult.reason}`);
  }

  const expectedOrigin = process.env.ORIGIN || `http://${rpID}:3000`;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: submittedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false
    });
  } catch (error) {
    console.error('등록 서명 검증 오류:', error);
    console.error('오류 메시지:', error.message);
    throw new Error('서명 검증 실패');
  }

  if (!verification.verified) {
    return { verified: false };
  }

  const { registrationInfo } = verification;
  const {
    credential: {
      id: credentialID,
      publicKey: credentialPublicKey,
      counter,
    }
  } = registrationInfo;

  const [userRows] = await db.query(
    'SELECT id FROM users WHERE username = ?',
    [username]
  );

  let userId;
  if (userRows.length === 0) {
    const [result] = await db.query(
      'INSERT INTO users (username, display_name, email) VALUES (?, ?, ?)',
      [username, username, email || null]
    );
    userId = result.insertId;
  } else {
    userId = userRows[0].id;
  }

  await db.query(
    `INSERT INTO passkeys 
     (user_id, credential_id, public_key, counter)
     VALUES (?, ?, ?, ?)`,
    [
      userId,
      credentialID,
      Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
    ]
  );

  return { verified: true };
};

exports.verifyLogin = async (username, challengeId, credential) => {

  const clientDataJSON = JSON.parse(
    Buffer.from(credential.response.clientDataJSON, 'base64url').toString('utf8')
  );
  const submittedChallenge = clientDataJSON.challenge;
  console.log('submittedChallenge:', submittedChallenge);

  const challengeResult = await verifyChallenge(
    username,
    challengeId,
    submittedChallenge
  );

  if (!challengeResult.valid) {
    throw new Error(`challenge 검증 실패: ${challengeResult.reason}`);
  }

  const [rows] = await db.query(
    `SELECT p.* FROM passkeys p
     JOIN users u ON p.user_id = u.id
     WHERE u.username = ? AND p.credential_id = ?
     AND p.is_active = 1`,
    [username, credential.id]
  );

  if (rows.length === 0) {
    return { verified: false };
  }

  const passkey = rows[0];
  const expectedOrigin = process.env.ORIGIN || `http://${rpID}:3000`;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: submittedChallenge, 
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
      credential: {
        id: Buffer.from(passkey.credential_id, 'base64url'),
        publicKey: Buffer.from(passkey.public_key, 'base64url'),
        counter: passkey.counter,
      },
    });
  } catch (error) {
    console.error('로그인 서명 검증 오류:', error);
    console.error('오류 메시지:', error.message);
    throw new Error('서명 검증 실패');
  }

  if (!verification.verified) {
    return { verified: false };
  }

  const { authenticationInfo } = verification;
  const { newCounter } = authenticationInfo;

  // ⚠️ 직접 구현 권장 - signCount 이상 탐지
  if (passkey.counter > 0 && newCounter <= passkey.counter) {
    console.error('signCount 이상 탐지:', {
      username,
      expectedCounter: passkey.counter + 1,
      receivedCounter: newCounter,
      time: new Date().toISOString(),
    });

    await db.query(
      'UPDATE passkeys SET is_active = 0 WHERE id = ?',
      [passkey.id]
    );

    throw new Error('비정상적인 인증 시도 감지');
  }

  await db.query(
    'UPDATE passkeys SET counter = ? WHERE id = ?',
    [newCounter, passkey.id]
  );

  return { verified: true };
};
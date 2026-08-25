const { 
  verifyRegistrationResponse,
  verifyAuthenticationResponse 
} = require('@simplewebauthn/server');
const { db } = require('../../config/db');
const { verifyChallenge } = require('./challenge');

const rpID = process.env.RP_ID || 'localhost';

exports.verifyRegistration = async (username, email, challengeId, credential, authenticatorAttachment) => {

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
     (user_id, credential_id, public_key, counter, authenticator_type)
     VALUES (?, ?, ?, ?, ?)`,
    [
      userId,
      credentialID,
      Buffer.from(credentialPublicKey).toString('base64url'),
      counter,
      authenticatorAttachment || 'unknown',
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
     WHERE u.username = ? AND p.credential_id = ?`,
    [username, credential.id]
  );

  const credentialMismatch = rows.length===0;

  if(credentialMismatch) {
    return {verified: false, reason: 'CREDENTIAL_MISMATCH', credentialMismatch: true, signCountAbnormal: false};
  }

  const passkey = rows[0];

  if (passkey.is_active !== 1) {
    return { verified: false, reason: 'PASSKEY_INACTIVE', credentialMismatch: false, signCountAbnormal: false };
  }

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
    return { verified: false, credentialMismatch: false, signCountAbnormal: false };
  }

  const { authenticationInfo } = verification;
  const { newCounter } = authenticationInfo;

  const signCountAbnormal = passkey.counter > 0 && newCounter <= passkey.counter;

  if (signCountAbnormal) {
    console.error('signCount 이상 탐지:', {
      username,
      expectedCounter: passkey.counter + 1,
      receivedCounter: newCounter,
      time: new Date().toISOString(),
    });

    return { 
      verified: false, 
      reason: 'SIGN_COUNT_ABNORMAL',
      credentialMismatch: false,
      signCountAbnormal: true 
    };
  }

  await db.query(
    'UPDATE passkeys SET counter = ? WHERE id = ?',
    [newCounter, passkey.id]
  );

  return { verified: true, credentialMismatch:false, signCountAbnormal: false };
};
//MVP 단계
//추후 서명 검증(@simplewebauthn/server), counter 업데이트 구현
const { 
  verifyRegistrationResponse,
  verifyAuthenticationResponse 
} = require('@simplewebauthn/server');
const { db, redisClient } = require('../../config/db');
const { RootNodesUnavailableError } = require('redis');

const rpID = process.env.RP_ID || 'localhost';
const rpName = 'MFA 보안 시스템';
const origin = process.env.ORIGIN || 'http://localhost:3000';


// 등록 검증
exports.verifyRegistration = async (username, email, credential) => {

  // redis에서 challenge 조회
  const expectedChallenge = await redisClient.get(`challenge:${username}`);
  console.log('expectedChallenge:', expectedChallenge);

  if (!expectedChallenge) {
    throw new Error('challenge 만료 또는 없음');
  }

  // ** 코드 수정 필요**
  // 이유: origin 검증은 배포 환경에 따라 달라짐
  // 고려할 것:
  //   - ngrok 사용 시 origin이 달라짐
  //   - 운영환경에서는 실제 도메인으로 변경
  //   - 여러 origin 허용 시 배열로 전달 가능
  const expectedOrigin = process.env.ORIGIN || 
    `http://${rpID}:3000`;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
    });
  } catch (error) {
    // ** 코드 수정 **
    // 이유: 에러 종류별 처리 필요
    // 고려할 것:
    //   - 실패 횟수 기록 (brute force 방지)
    //   - 의심스러운 요청 로깅
    console.error('등록 서명 검증 오류:', error);
    console.error('오류 메시지:', error.message);
    console.error('오류 스택:', error.stack);
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

  // ** 코드 수정 필요**
  // 이유: 공개키 저장 방식은 보안 정책에 따라 다름
  // 고려할 것:
  //   - credentialID 중복 등록 방지
  //   - 공개키 암호화 저장 여부
  //   - 기기 이름 저장 여부 (예: "내 아이폰")
  //   - 등록 기기 수 제한 여부
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


  await redisClient.del(`challenge:${username}`);

  return { verified: true };
};


// 로그인 검증
exports.verifyLogin = async (username, credential) => {

  const expectedChallenge = await redisClient.get(`challenge:${username}`);
  if (!expectedChallenge) {
    throw new Error('challenge 만료 또는 없음');
  }

  // **코드 수정 필요**
  // 이유: credential 조회 방식은 DB 구조에 따라 다름
  // 고려할 것:
  //   - 비활성화된 기기 제외
  //   - 마지막 로그인 시간 기록
  const [rows] = await db.query(
    `SELECT p.* FROM passkeys p
     JOIN users u ON p.user_id = u.id
     WHERE u.username = ? AND p.credential_id = ?`,
    [username, credential.id]
  );

  if (rows.length === 0) {
    return { verified: false };
  }

  const passkey = rows[0];

  const expectedOrigin = process.env.ORIGIN ||
    `http://${rpID}:3000`;

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      credential: {
        id: Buffer.from(passkey.credential_id, 'base64url'),
        publicKey: Buffer.from(passkey.public_key, 'base64url'),
        counter: passkey.counter,
      },
    });
  } catch (error) {
    // ** 코드 수정 필요**
    // 이유: 로그인 실패 처리는 보안 정책에 따라 다름
    // 고려할 것:
    //   - 로그인 실패 횟수 제한
    //   - 실패 횟수 초과 시 계정 잠금
    //   - 실패 로그 저장 (대시보드 연동)
    console.error('로그인 서명 검증 오류:', error);
    throw new Error('서명 검증 실패');
  }

  if (!verification.verified) {
    return { verified: false };
  }

  const { authenticationInfo } = verification;
  const { newCounter } = authenticationInfo;

  // ** 코드 수정 필요 **
  // 이유: counter 검증은 Replay Attack 방지 핵심
  // 고려할 것:
  //   - newCounter가 기존보다 작으면 공격으로 간주
  //   - 공격 감지 시 해당 기기 비활성화
  //   - 보안 알림 발송
  if (newCounter <= passkey.counter) {
    // 직접 구현 권장 - 공격 감지 시 처리
    throw new Error('Replay Attack 감지');
  }

  await db.query(
    'UPDATE passkeys SET counter = ? WHERE id = ?',
    [newCounter, passkey.id]
  );

  await redisClient.del(`challenge:${username}`);

  return { verified: true };
};
const webauthnService = require('../services/webauthnService');
const verificationService = require('../services/verificationService');
const sessionManager = require('../services/sessionManager');
const crypto = require('crypto');
const axios = require('axios');
const { sendRiskData } = require('../services/riskService');
const { redisClient } = require('../../config/db');
const { db } = require('../../config/db');
const { hashForCompare, hashUserId } = require('../utils/anonymize');
const { encryptObject } = require('../utils/crypto');

console.log('sendRiskData 타입:', typeof sendRiskData);

// function hashData(data) {
//   return crypto
//     .createHash('sha256')
//     .update(String(data))
//     .digest('hex');
// }

// 등록 - 1단계: challenge 생성
exports.registerStart = async (req, res) => {
  try {
    const { username, displayName, email } = req.body;


    // **추후 코드 수정**
    //   - username 중복 체크
    //   - 이메일 형식 검증
    //   - 특수문자 제한 등
    if (!username || !displayName) {
      return res.status(400).json({ error: '필수 입력값 누락' });
    }

    const options = await webauthnService.generateRegistrationOptions(
      username, displayName
    );

    return res.status(200).json(options);

  } catch (error) {

    // **추후 코드 수정**
    //   - 에러 종류별 메시지 분리
    //   - 실제 에러는 서버 로그에만 기록
    console.error('registerStart 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


// 등록 - 서명 검증 및 공개키 저장

exports.registerFinish = async (req, res) => {
  const { username } = req.body;
  try {
    const { email, challengeId, credential } = req.body;
    // verificationService에서 서명 검증 및 DB 저장
    const result = await verificationService.verifyRegistration(
      username,
      email,
      challengeId,
      credential
    );

    if (!result.verified) {
      const failUserIdHash = hashUserId(username);

      await db.query(
        `INSERT INTO authdb.access_logs (user_id, auth_result, reason) VALUES (?, 'fail', ?)`,
        [failUserIdHash, 'REGISTER_FAIL']
      );
      try {
        await db.query(
          'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
          ['REGISTER_FAIL', encryptObject({
            userIdHash: failUserIdHash,
            result: 'fail',
            timestamp: new Date().toISOString(),
          })]
        );
      } catch (auditError) {
        console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패(등록 실패):', auditError.message);
      }

      return res.status(400).json({ error: '등록 검증 실패' });
    }

    const userIdHash = hashUserId(username);

    await db.query(
      `INSERT INTO authdb.access_logs (user_id, auth_result, reason) VALUES (?, 'success', ?)`,
      [userIdHash, 'REGISTER_SUCCESS']
    );

    try {
      await db.query(
        'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
        ['REGISTER_SUCCESS', encryptObject({
          userIdHash,
          result: 'success',
          timestamp: new Date().toISOString(),
        })]
      );
    } catch (auditError) {
      console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패(등록):', auditError.message);
    }

    // ** 추후 코드 수정**
    //   - 등록 완료 후 바로 로그인 처리할지 여부
    return res.status(200).json({ success: true, message: '등록 완료' });

  } catch (error) {
    console.error('registerFinish 오류:', error);

    if (username) {
      try {
        const throwUserIdHash = hashUserId(username);

        await db.query(
          `INSERT INTO authdb.access_logs (user_id, auth_result, reason) VALUES (?, 'fail', ?)`,
          [throwUserIdHash, 'REGISTER_FAIL']
        );

        await db.query(
          'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
          ['REGISTER_FAIL', encryptObject({
            userIdHash: throwUserIdHash,
            result: 'fail',
            reason: error.message || 'UNKNOWN_ERROR',
            timestamp: new Date().toISOString(),
          })]
        );
      } catch (logError) {
        console.error('[AUDIT_LOG_FAILURE] catch 블록 감사 로그 실패:', logError.message);
      }
    }
    return res.status(500).json({ error: '서버 오류' });
  }
};


// challenge 생성
exports.loginStart = async (req, res) => {
  try {
    const { username } = req.body;

    // **추후 코드 수정
    //   - 유저 존재 여부를 에러로 노출하면 계정 열거 공격에 취약
    //   - 존재하지 않아도 동일한 응답 시간 유지 필요 (타이밍 공격 방지)
    if (!username) {
      return res.status(400).json({ error: '아이디를 입력하세요' });
    }

    // loginStart에서 시작 시간 저장
    await redisClient.set(
      `challenge:time:${username}`,
      String(Date.now()),
      { EX: 300 }
    );

    const options = await webauthnService.generateLoginOptions(username);

    return res.status(200).json(options);

  } catch (error) {
    console.error('loginStart 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


//서명 검증 및 세션 발급
exports.loginFinish = async (req, res) => {
  const { username } = req.body;
  try {
    const { challengeId, credential } = req.body;
    const context = req.context || {};

    // loginFinish에서 시간 차이 계산
    const startTime = await redisClient.get(`challenge:time:${username}`);
    const challengeResponseTime = startTime ? Date.now() - parseInt(startTime) : null;

    context.challengeResponseTime = challengeResponseTime;
    await redisClient.del(`challenge:time:${username}`);

    context.loginRegion = context.country;

    const result = await verificationService.verifyLogin(
      username,
      challengeId,
      credential
    );

    console.log('verifyLogin 결과:', result);

    context.signCountAbnormal = result.signCountAbnormal || false;
    context.credentialMismatch = result.credentialMismatch || false;

    // 로그인 실패 시
    if (!result.verified) {
      const failUserIdHash = hashUserId(username);

      await db.query(
        `INSERT INTO authdb.access_logs 
        (user_id, auth_result, reason)
        VALUES (?, 'fail', ?)`,
        [failUserIdHash, result.reason || 'VERIFICATION_FAILED']
      );

      try {
        await db.query(
          'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
          [
            'LOGIN_FAIL',
            encryptObject({
              userIdHash: hashUserId(username),
              deviceType: context.deviceInfo?.deviceType || 'unknown',
              result: 'fail',
              reason: result.reason || 'VERIFICATION_FAILED',
              timestamp: new Date().toISOString(),
            }),
          ]
        );
      } catch (auditError) {
        console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패(실패 이벤트):', auditError.message);
      }

      await redisClient.incr(`login:fail:${username}`);
      await redisClient.expire(`login:fail:${username}`, 3600);

      try {
        await sendRiskData(username, context);
      } catch (riskError) {
        console.error('리스크 서버 전송 실패(실패 이벤트):', riskError.message);
      }

      return res.status(401).json({ error: '로그인 검증 실패', reason: result.reason });
    }

    // 사용자 존재 여부 확인
    const [rows] = await db.query(
      `SELECT id, username FROM users WHERE username = ? LIMIT 1`,
      [username]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    }

    const failedLoginCount = parseInt(await redisClient.get(`login:fail:${username}`)) || 0;
    context.failedLoginCount = failedLoginCount;
    await redisClient.del(`login:fail:${username}`);

    const userIdHash = hashUserId(username);
    const contextKey = `lastcontext:${userIdHash}`;
    const prevContext = await redisClient.hGetAll(contextKey);

    const currentDeviceHash = hashForCompare(JSON.stringify(context.deviceInfo || {}));
    const currentIpHash = hashForCompare(context.ip || '');
    const currentUaHash = hashForCompare(context.userAgent || '');
    const currentCountryHash = hashForCompare(context.country || 'KR');

    context.hasPreviousContext = Object.keys(prevContext).length > 0;

    context.deviceChanged = context.hasPreviousContext ? prevContext.deviceHash !== currentDeviceHash : false;
    context.ipChanged = context.hasPreviousContext ? prevContext.ipHash !== currentIpHash : false;
    context.userAgentChanged = context.hasPreviousContext ? prevContext.uaHash !== currentUaHash : false;
    context.locationChanged = context.hasPreviousContext ? prevContext.countryHash !== currentCountryHash : false;

    await redisClient.hSet(contextKey, {
      deviceHash: String(currentDeviceHash || ''),
      ipHash: String(currentIpHash || ''),
      uaHash: String(currentUaHash || ''),
      countryHash: String(currentCountryHash || ''),
    });
    await redisClient.expire(contextKey, 60 * 60 * 24 * 30);

    await db.query(
      `INSERT INTO authdb.access_logs 
      (user_id, auth_result, reason)
      VALUES (?, 'success', ?)`,
      [userIdHash, 'LOGIN_SUCCESS']
    );

    try {
      await db.query(
        'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
        [
          'LOGIN_SUCCESS',
          encryptObject({
            userIdHash: hashUserId(username),
            deviceType: context.deviceInfo?.deviceType || 'unknown',
            result: 'success',
            timestamp: new Date().toISOString(),
          }),
        ]
      );
    } catch (auditError) {
      console.error('[AUDIT_LOG_FAILURE] audit_logs 기록 실패:', auditError.message);
    }

    const loginFrequency = await redisClient.incr(`login:count:${username}`);
    await redisClient.expire(`login:count:${username}`, 3600);
    context.loginFrequency = loginFrequency;

    let riskScore = 0;
    let riskLevel = 'LOW';
    let riskAction = 'ACTIVE';
    let riskMessage = '리스크 분석 서버 응답 없음';
    let riskTriggers = [];
    let riskFeatureScores = {};

    //ML 결과
    let mlModelUsed = false;
    let mlModelType = null;
    let mlAnomalyScore = null;
    let mlIsAnomaly = null;

    try {
      const riskResult = await sendRiskData(username, context);
      riskScore = riskResult.score ?? 0;
      riskLevel = riskResult.level ?? 'LOW';
      riskAction = riskResult.action ?? 'ACTIVE';
      riskMessage = riskResult.message ?? '리스크 분석 완료';
      riskTriggers = riskResult.triggers ?? [];
      riskFeatureScores = riskResult.featureScores ?? {};

      mlModelUsed = riskResult.mlModelUsed ?? false;
      mlModelType = riskResult.mlModelType ?? null;
      mlAnomalyScore = riskResult.mlAnomalyScore ?? null;
      mlIsAnomaly = riskResult.mlIsAnomaly ?? null;

      console.log('리스크 스코어:', { riskScore, riskLevel, mlModelUsed, mlModelType, mlAnomalyScore, mlIsAnomaly });
    } catch (error) {
      console.error('리스크 스코어 요청 실패:', error.message);
      console.error(error.stack);
    }

    if (riskAction === 'BLOCKED') {
      return res.status(403).json({
        success: false,
        message: riskMessage || '위험도가 높아 로그인이 차단되었습니다.',
        riskScore, riskLevel, riskAction,
        triggers: riskTriggers,
        featureScores: riskFeatureScores,
        ml: { modelUsed: mlModelUsed, modelType: mlModelType, anomalyScore: mlAnomalyScore, isAnomaly: mlIsAnomaly },
      });
    }

    if (riskAction === 'RE_AUTH') {
      return res.status(200).json({
        success: false,
        requiresReauthentication: true,
        message: riskMessage || '추가 인증이 필요합니다.',
        riskScore, riskLevel, riskAction,
        triggers: riskTriggers,
        featureScores: riskFeatureScores,
        ml: { modelUsed: mlModelUsed, modelType: mlModelType, anomalyScore: mlAnomalyScore, isAnomaly: mlIsAnomaly },
      });
    }

    const session = await sessionManager.createSession(username, context.ip, context.userAgent);
    console.log('세션 생성 결과:', session);

    const isNgrok = req.headers.host?.includes('ngrok');

    res.cookie('session', session.token, {
      httpOnly: true,
      secure: isNgrok ? true : false,
      sameSite: isNgrok ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60,
    });

    return res.status(200).json({
      success: true,
      message: '로그인 성공',
      context: {
        deviceType: context.deviceInfo?.deviceType,
        os: context.deviceInfo?.os,
        isNightAccess: context.isNightAccess,
        country: context.country,
        signCountAbnormal: context.signCountAbnormal,
      },
      riskScore,
      riskLevel,
      riskAction,
      riskMessage,
      triggers: riskTriggers,
      featureScores: riskFeatureScores,
      ml: { modelUsed: mlModelUsed, modelType: mlModelType, anomalyScore: mlAnomalyScore, isAnomaly: mlIsAnomaly },
    });

  } catch (error) {
    console.error('loginFinish 오류:', error);

    if (username) {
      try {
        const throwUserIdHash = hashUserId(username);

        await db.query(
          `INSERT INTO authdb.access_logs (user_id, auth_result, reason) VALUES (?, 'fail', ?)`,
          [throwUserIdHash, 'LOGIN_FAIL']
        );

        await db.query(
          'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
          ['LOGIN_FAIL', encryptObject({
            userIdHash: throwUserIdHash,
            result: 'fail',
            reason: error.message || 'UNKNOWN_ERROR',
            timestamp: new Date().toISOString(),
          })]
        );
      } catch (logError) {
        console.error('[AUDIT_LOG_FAILURE] catch 블록 감사 로그 실패:', logError.message);
      }
    }

    return res.status(500).json({ error: '서버 오류' });
  }
};


//logout
exports.logout = async (req, res) => {
  try {
    const sessionToken = req.cookies.session;
    if (sessionToken) {
      await sessionManager.deleteSession(sessionToken);
    }
    res.clearCookie('session');
    return res.status(200).json({ success: true, message: '로그아웃 완료' });
  } catch (error) {
    console.error('logout 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


exports.verifySession = async (req, res) => {
  try {
    const sessionToken = req.cookies.session;
    if (!sessionToken) {
      return res.status(401).json({ error: '토큰 없음' });
    }

    const result = await sessionManager.verifySession(sessionToken);
    if (!result.valid) {
      return res.status(401).json({ error: result.reason || '세션 만료' });
    }

    return res.status(200).json({ success: true, username: result.username });
  } catch (error) {
    console.error('verifySession 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};
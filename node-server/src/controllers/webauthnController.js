const webauthnService = require('../services/webauthnService');
const verificationService = require('../services/verificationService');
const sessionManager = require('../services/sessionManager');
const crypto = require('crypto');
const axios = require('axios');
const { sendRiskData } = require('../services/riskService');
const { db, authdb, redisClient } = require('../../config/db');
const { hashForCompare, hashUserId } = require('../utils/anonymize');
const { encryptObject } = require('../utils/crypto');

console.log('sendRiskData 타입:', typeof sendRiskData);


// ============================================================
// access_logs 공통 저장 함수
// ============================================================

async function writeAccessLog(userIdHash, context, authResult, reason) {
  try {
    await authdb.query(
        `INSERT INTO access_logs
      (
        user_id,
        ip,
        device,
        user_agent,
        location,
        auth_result,
        reason
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          userIdHash || null,
          context?.ip || 'unknown',
          JSON.stringify(context?.deviceInfo || {}),
          context?.userAgent || 'unknown',
          context?.country || context?.loginRegion || 'KR',
          authResult,
          reason || null,
        ]
    );
  } catch (error) {
    console.error('[ACCESS_LOG_FAILURE]', error.message);
  }
}


// ============================================================
// 등록 시작
// ============================================================

exports.registerStart = async (req, res) => {
  try {
    const { username, displayName, email } = req.body;

    // 추후 코드 수정
    // - username 중복 체크
    // - 이메일 형식 검증
    // - 특수문자 제한 등
    if (!username || !displayName) {
      return res.status(400).json({
        error: '필수 입력값 누락',
      });
    }

    const options =
        await webauthnService.generateRegistrationOptions(
            username,
            displayName
        );

    return res.status(200).json(options);

  } catch (error) {

    console.error(
        'registerStart 오류:',
        error
    );

    return res.status(500).json({
      error: '서버 오류',
    });
  }
};


// ============================================================
// 등록 완료
// ============================================================

exports.registerFinish = async (req, res) => {
  const { username } = req.body;

  try {
    const {
      email,
      challengeId,
      credential,
    } = req.body;

    const context =
        req.context || {};

    const result =
        await verificationService.verifyRegistration(
            username,
            email,
            challengeId,
            credential
        );

    // --------------------------------------------------------
    // 등록 실패
    // --------------------------------------------------------

    if (!result.verified) {

      const failUserIdHash =
          hashUserId(username);

      await writeAccessLog(
          failUserIdHash,
          context,
          'fail',
          'REGISTER_FAIL'
      );

      try {
        await db.query(
            'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
            [
              'REGISTER_FAIL',

              encryptObject({
                userIdHash:
                failUserIdHash,

                deviceType:
                    context.deviceInfo?.deviceType
                    || 'unknown',

                result:
                    'fail',

                timestamp:
                    new Date().toISOString(),
              }),
            ]
        );

      } catch (auditError) {

        console.error(
            '[AUDIT_LOG_FAILURE] audit_logs 기록 실패(등록 실패):',
            auditError.message
        );
      }

      return res.status(400).json({
        error: '등록 검증 실패',
      });
    }


    // --------------------------------------------------------
    // 등록 성공
    // --------------------------------------------------------

    const userIdHash =
        hashUserId(username);

    await writeAccessLog(
        userIdHash,
        context,
        'success',
        'REGISTER_SUCCESS'
    );

    try {
      await db.query(
          'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
          [
            'REGISTER_SUCCESS',

            encryptObject({
              userIdHash,

              deviceType:
                  context.deviceInfo?.deviceType
                  || 'unknown',

              result:
                  'success',

              timestamp:
                  new Date().toISOString(),
            }),
          ]
      );

    } catch (auditError) {

      console.error(
          '[AUDIT_LOG_FAILURE] audit_logs 기록 실패(등록):',
          auditError.message
      );
    }


    return res.status(200).json({
      success: true,
      message: '등록 완료',
    });

  } catch (error) {

    console.error(
        'registerFinish 오류:',
        error
    );


    if (username) {

      try {

        const throwUserIdHash =
            hashUserId(username);

        await writeAccessLog(
            throwUserIdHash,
            req.context || {},
            'fail',
            'REGISTER_FAIL'
        );

        await db.query(
            'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
            [
              'REGISTER_FAIL',

              encryptObject({
                userIdHash:
                throwUserIdHash,

                result:
                    'fail',

                reason:
                    error.message
                    || 'UNKNOWN_ERROR',

                timestamp:
                    new Date().toISOString(),
              }),
            ]
        );

      } catch (logError) {

        console.error(
            '[AUDIT_LOG_FAILURE] catch 블록 감사 로그 실패:',
            logError.message
        );
      }
    }

    return res.status(500).json({
      error: '서버 오류',
    });
  }
};


// ============================================================
// 로그인 시작
// ============================================================

exports.loginStart = async (req, res) => {
  try {

    const {
      username,
    } = req.body;


    if (!username) {

      return res.status(400).json({
        error: '아이디를 입력하세요',
      });
    }


    // Challenge 응답시간 측정 시작
    await redisClient.set(
        `challenge:time:${username}`,
        String(
            Date.now()
        ),
        {
          EX: 300,
        }
    );


    const options =
        await webauthnService.generateLoginOptions(
            username
        );


    return res.status(200).json(
        options
    );

  } catch (error) {

    console.error(
        'loginStart 오류:',
        error
    );

    return res.status(500).json({
      error: '서버 오류',
    });
  }
};


// ============================================================
// 로그인 완료
// ============================================================

exports.loginFinish = async (req, res) => {

  const {
    username,
  } = req.body;


  try {

    const {
      challengeId,
      credential,
    } = req.body;


    const context =
        req.context || {};


    // --------------------------------------------------------
    // Challenge 응답시간 계산
    // --------------------------------------------------------

    const startTime =
        await redisClient.get(
            `challenge:time:${username}`
        );


    const challengeResponseTime =
        startTime
            ? Date.now()
            - parseInt(
                startTime,
                10
            )
            : null;


    context.challengeResponseTime =
        challengeResponseTime;


    await redisClient.del(
        `challenge:time:${username}`
    );


    context.loginRegion =
        context.country
        || 'KR';


    // --------------------------------------------------------
    // WebAuthn 검증
    // --------------------------------------------------------

    const result =
        await verificationService.verifyLogin(
            username,
            challengeId,
            credential
        );


    console.log(
        'verifyLogin 결과:',
        result
    );


    // ========================================================
    // 로그인 검증 실패
    // ========================================================

    if (!result.verified) {

      const failUserIdHash =
          hashUserId(username);


      // ------------------------------------------------------
      // access_logs
      // ------------------------------------------------------

      await writeAccessLog(
          failUserIdHash,
          context,
          'fail',
          result.reason
          || 'VERIFICATION_FAILED'
      );


      // ------------------------------------------------------
      // audit_logs
      // ------------------------------------------------------

      try {

        await db.query(
            'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
            [
              'LOGIN_FAIL',

              encryptObject({
                userIdHash:
                failUserIdHash,

                deviceType:
                    context.deviceInfo?.deviceType
                    || 'unknown',

                result:
                    'fail',

                reason:
                    result.reason
                    || 'VERIFICATION_FAILED',

                timestamp:
                    new Date().toISOString(),
              }),
            ]
        );

      } catch (auditError) {

        console.error(
            '[AUDIT_LOG_FAILURE] audit_logs 기록 실패(실패 이벤트):',
            auditError.message
        );
      }


      // ------------------------------------------------------
      // WebAuthn Feature
      // ------------------------------------------------------

      context.signCountAbnormal =
          result.signCountAbnormal
          || false;


      context.credentialMismatch =
          result.credentialMismatch
          || false;


      // ------------------------------------------------------
      // 실패 횟수
      // ------------------------------------------------------

      const consecutiveFailureCount =
          parseInt(
              await redisClient.get(
                  `login:fail:${username}`
              ),
              10
          )
          || 0;


      context.consecutiveFailureCount =
          consecutiveFailureCount;


      context.failedLoginCount =
          consecutiveFailureCount;


      // ------------------------------------------------------
      // Blacklist IP
      // ------------------------------------------------------

      const ipHash =
          hashForCompare(
              context.ip
              || ''
          );


      const isBlacklisted =
          await redisClient.get(
              `blacklist:ip:${ipHash}`
          );


      context.blacklistIpDetected =
          isBlacklisted === '1';


      if (
          consecutiveFailureCount
          >= 5
      ) {

        await redisClient.set(
            `blacklist:ip:${ipHash}`,
            '1',
            {
              EX:
                  60
                  * 60
                  * 24,
            }
        );


        context.blacklistIpDetected =
            true;
      }


      // ------------------------------------------------------
      // 인증 방법 변화
      // ------------------------------------------------------

      let registeredPasskey = null;


      try {

        const [
          passkeyRows,
        ] =
            await db.query(
                `
              SELECT
                p.id
              FROM passkeys p
              JOIN users u
                ON p.user_id = u.id
              WHERE
                u.username = ?
                AND
                p.credential_id = ?
              LIMIT 1
            `,
                [
                  username,
                  credential?.id
                  || '',
                ]
            );


        registeredPasskey =
            passkeyRows?.[0]
            || null;

      } catch (passkeyError) {

        console.error(
            '등록 Passkey 확인 실패:',
            passkeyError.message
        );
      }


      const currentType =
          credential?.authenticatorAttachment
          || 'unknown';


      context.authenticationMethodChanged =
          (
              !registeredPasskey
              ||
              currentType
              === 'unknown'
          );


      // ------------------------------------------------------
      // 실패 카운트 증가
      // ------------------------------------------------------

      await redisClient.incr(
          `login:fail:${username}`
      );


      await redisClient.expire(
          `login:fail:${username}`,
          3600
      );


      // ------------------------------------------------------
      // Risk Engine
      // ------------------------------------------------------

      try {

        await sendRiskData(
            username,
            context
        );

      } catch (riskError) {

        console.error(
            '리스크 서버 전송 실패(실패 이벤트):',
            riskError.message
        );
      }


      return res
          .status(401)
          .json({
            error:
                '로그인 검증 실패',

            reason:
            result.reason,
          });
    }


    // ========================================================
    // 로그인 성공
    // ========================================================

    // --------------------------------------------------------
    // 사용자 조회
    // --------------------------------------------------------

    const [
      rows,
    ] =
        await db.query(
            `
          SELECT
            id,
            username
          FROM users
          WHERE username = ?
          LIMIT 1
        `,
            [
              username,
            ]
        );


    if (
        !rows
        ||
        rows.length === 0
    ) {

      return res
          .status(404)
          .json({
            error:
                '사용자를 찾을 수 없습니다.',
          });
    }


    // --------------------------------------------------------
    // 실패 이력
    // --------------------------------------------------------

    const failedLoginCount =
        parseInt(
            await redisClient.get(
                `login:fail:${username}`
            ),
            10
        )
        || 0;


    context.failedLoginCount =
        failedLoginCount;


    context.consecutiveFailureCount =
        failedLoginCount;


    // --------------------------------------------------------
    // WebAuthn 정상 상태
    // --------------------------------------------------------

    context.signCountAbnormal =
        result.signCountAbnormal
        || false;


    context.credentialMismatch =
        result.credentialMismatch
        || false;


    context.authenticationMethodChanged =
        false;


    // --------------------------------------------------------
    // Blacklist 상태
    // --------------------------------------------------------

    const blacklistIpHash =
        hashForCompare(
            context.ip
            || ''
        );


    const blacklistStatus =
        await redisClient.get(
            `blacklist:ip:${blacklistIpHash}`
        );


    context.blacklistIpDetected =
        blacklistStatus
        === '1';


    await redisClient.del(
        `login:fail:${username}`
    );


    // --------------------------------------------------------
    // Previous Context 비교
    // --------------------------------------------------------

    const userIdHash =
        hashUserId(username);


    const contextKey =
        `lastcontext:${userIdHash}`;


    const prevContext =
        await redisClient.hGetAll(
            contextKey
        );


    const currentDeviceHash =
        hashForCompare(
            JSON.stringify(
                context.deviceInfo
                || {}
            )
        );


    const currentIpHash =
        hashForCompare(
            context.ip
            || ''
        );


    const currentUaHash =
        hashForCompare(
            context.userAgent
            || ''
        );


    const currentCountryHash =
        hashForCompare(
            context.country
            || 'KR'
        );


    context.hasPreviousContext =
        Object.keys(
            prevContext
        ).length > 0;


    context.deviceChanged =
        context.hasPreviousContext
            ? prevContext.deviceHash
            !== currentDeviceHash
            : false;


    context.ipChanged =
        context.hasPreviousContext
            ? prevContext.ipHash
            !== currentIpHash
            : false;


    context.userAgentChanged =
        context.hasPreviousContext
            ? prevContext.uaHash
            !== currentUaHash
            : false;


    context.locationChanged =
        context.hasPreviousContext
            ? prevContext.countryHash
            !== currentCountryHash
            : false;


    // --------------------------------------------------------
    // 현재 Context 저장
    // --------------------------------------------------------

    await redisClient.hSet(
        contextKey,
        {

          deviceHash:
              String(
                  currentDeviceHash
                  || ''
              ),

          ipHash:
              String(
                  currentIpHash
                  || ''
              ),

          uaHash:
              String(
                  currentUaHash
                  || ''
              ),

          countryHash:
              String(
                  currentCountryHash
                  || ''
              ),

        }
    );


    await redisClient.expire(
        contextKey,
        60
        * 60
        * 24
        * 30
    );


    // --------------------------------------------------------
    // access_logs 성공
    // --------------------------------------------------------

    await writeAccessLog(
        userIdHash,
        context,
        'success',
        'LOGIN_SUCCESS'
    );


    // --------------------------------------------------------
    // audit_logs 성공
    // --------------------------------------------------------

    try {

      await db.query(
          'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
          [
            'LOGIN_SUCCESS',

            encryptObject({
              userIdHash:
              userIdHash,

              deviceType:
                  context.deviceInfo?.deviceType
                  || 'unknown',

              result:
                  'success',

              timestamp:
                  new Date().toISOString(),
            }),
          ]
      );

    } catch (auditError) {

      console.error(
          '[AUDIT_LOG_FAILURE] audit_logs 기록 실패:',
          auditError.message
      );
    }


    // --------------------------------------------------------
    // 로그인 빈도
    // --------------------------------------------------------

    const loginFrequency =
        await redisClient.incr(
            `login:count:${username}`
        );


    await redisClient.expire(
        `login:count:${username}`,
        3600
    );


    context.loginFrequency =
        loginFrequency;


    // ========================================================
    // Risk Engine
    // ========================================================

    let riskScore = 0;

    let riskLevel =
        'LOW';

    let riskAction =
        'ACTIVE';

    let riskMessage =
        '리스크 분석 서버 응답 없음';

    let riskTriggers =
        [];

    let riskFeatureScores =
        {};


    let mlModelUsed =
        false;

    let mlModelType =
        null;

    let mlAnomalyScore =
        null;

    let mlIsAnomaly =
        null;


    try {

      const riskResult =
          await sendRiskData(
              username,
              context
          );


      riskScore =
          riskResult.score
          ?? 0;


      riskLevel =
          riskResult.level
          ?? 'LOW';


      riskAction =
          riskResult.action
          ?? 'ACTIVE';


      riskMessage =
          riskResult.message
          ?? '리스크 분석 완료';


      riskTriggers =
          riskResult.triggers
          ?? [];


      riskFeatureScores =
          riskResult.featureScores
          ?? {};


      mlModelUsed =
          riskResult.mlModelUsed
          ?? false;


      mlModelType =
          riskResult.mlModelType
          ?? null;


      mlAnomalyScore =
          riskResult.mlAnomalyScore
          ?? null;


      mlIsAnomaly =
          riskResult.mlIsAnomaly
          ?? null;


      console.log(
          '리스크 스코어:',
          {
            riskScore,
            riskLevel,
            mlModelUsed,
            mlModelType,
            mlAnomalyScore,
            mlIsAnomaly,
          }
      );

    } catch (error) {

      console.error(
          '리스크 스코어 요청 실패:',
          error.message
      );


      console.error(
          error.stack
      );
    }


    // ========================================================
    // BLOCKED
    // ========================================================

    if (
        riskAction
        === 'BLOCKED'
    ) {

      return res
          .status(403)
          .json({
            success:
                false,

            message:
                riskMessage
                || '위험도가 높아 로그인이 차단되었습니다.',

            riskScore,
            riskLevel,
            riskAction,

            triggers:
            riskTriggers,

            featureScores:
            riskFeatureScores,

            ml: {
              modelUsed:
              mlModelUsed,

              modelType:
              mlModelType,

              anomalyScore:
              mlAnomalyScore,

              isAnomaly:
              mlIsAnomaly,
            },
          });
    }


    // ========================================================
    // RE_AUTH
    // ========================================================

    if (
        riskAction
        === 'RE_AUTH'
    ) {

      return res
          .status(200)
          .json({
            success:
                false,

            requiresReauthentication:
                true,

            message:
                riskMessage
                || '추가 인증이 필요합니다.',

            riskScore,
            riskLevel,
            riskAction,

            triggers:
            riskTriggers,

            featureScores:
            riskFeatureScores,

            ml: {
              modelUsed:
              mlModelUsed,

              modelType:
              mlModelType,

              anomalyScore:
              mlAnomalyScore,

              isAnomaly:
              mlIsAnomaly,
            },
          });
    }


    // ========================================================
    // 세션 생성
    // ========================================================

    const session =
        await sessionManager.createSession(
            username,
            context.ip,
            context.userAgent
        );


    console.log(
        '세션 생성 결과:',
        session
    );


    const isNgrok =
        req.headers.host
            ?.includes(
                'ngrok'
            );


    res.cookie(
        'session',
        session.token,
        {

          httpOnly:
              true,

          secure:
              isNgrok
                  ? true
                  : false,

          sameSite:
              isNgrok
                  ? 'none'
                  : 'lax',

          maxAge:
              1000
              * 60
              * 60,

        }
    );


    return res
        .status(200)
        .json({

          success:
              true,

          message:
              '로그인 성공',

          context: {

            deviceType:
            context.deviceInfo?.deviceType,

            os:
            context.deviceInfo?.os,

            isNightAccess:
            context.isNightAccess,

            country:
            context.country,

            signCountAbnormal:
            context.signCountAbnormal,
          },

          riskScore,
          riskLevel,
          riskAction,
          riskMessage,

          triggers:
          riskTriggers,

          featureScores:
          riskFeatureScores,

          ml: {

            modelUsed:
            mlModelUsed,

            modelType:
            mlModelType,

            anomalyScore:
            mlAnomalyScore,

            isAnomaly:
            mlIsAnomaly,
          },
        });

  } catch (error) {

    console.error(
        'loginFinish 오류:',
        error
    );


    if (username) {

      try {

        const throwUserIdHash =
            hashUserId(
                username
            );


        await writeAccessLog(
            throwUserIdHash,
            req.context || {},
            'fail',
            'LOGIN_FAIL'
        );


        await db.query(
            'INSERT INTO mfa_db.audit_logs (event_type, payload) VALUES (?, ?)',
            [
              'LOGIN_FAIL',

              encryptObject({
                userIdHash:
                throwUserIdHash,

                result:
                    'fail',

                reason:
                    error.message
                    || 'UNKNOWN_ERROR',

                timestamp:
                    new Date().toISOString(),
              }),
            ]
        );

      } catch (logError) {

        console.error(
            '[AUDIT_LOG_FAILURE] catch 블록 감사 로그 실패:',
            logError.message
        );
      }
    }


    return res
        .status(500)
        .json({
          error:
              '서버 오류',
        });
  }
};


// ============================================================
// Logout
// ============================================================

exports.logout = async (req, res) => {

  try {

    const sessionToken =
        req.cookies.session;


    if (sessionToken) {

      await sessionManager.deleteSession(
          sessionToken
      );
    }


    res.clearCookie(
        'session'
    );


    return res
        .status(200)
        .json({
          success:
              true,

          message:
              '로그아웃 완료',
        });

  } catch (error) {

    console.error(
        'logout 오류:',
        error
    );


    return res
        .status(500)
        .json({
          error:
              '서버 오류',
        });
  }
};


// ============================================================
// Session 검증
// ============================================================

exports.verifySession = async (req, res) => {

  try {

    const sessionToken =
        req.cookies.session;


    if (!sessionToken) {

      return res
          .status(401)
          .json({
            error:
                '토큰 없음',
          });
    }


    const result =
        await sessionManager.verifySession(
            sessionToken
        );


    if (!result.valid) {

      return res
          .status(401)
          .json({
            error:
                result.reason
                || '세션 만료',
          });
    }


    return res
        .status(200)
        .json({
          success:
              true,

          username:
          result.username,
        });

  } catch (error) {

    console.error(
        'verifySession 오류:',
        error
    );


    return res
        .status(500)
        .json({
          error:
              '서버 오류',
        });
  }
};
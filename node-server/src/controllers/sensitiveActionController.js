const { redisClient } = require('../../config/db');
const { sendRiskData } = require('../services/riskService');

const {
  createReauthState,
  updateSessionStatus
} = require('../services/session');

const {
  hashUserId,
  hashForCompare
} = require('../utils/anonymize');


// ============================================================
// CASE 3
// 인증수단 변경 요청 → Risk Re-Evaluation
// ============================================================

exports.requestAuthMethodChange = async (req, res) => {
  try {
    const username = req.username;
    const context = req.context || {};

    if (!username) {
      return res.status(401).json({
        success: false,
        error: 'AUTHENTICATION_REQUIRED'
      });
    }


    // ========================================================
    // 1. Existing login/history state
    // ========================================================

    const failedLoginCount =
        parseInt(
            await redisClient.get(
                `login:fail:${username}`
            ),
            10
        ) || 0;

    context.failedLoginCount =
        failedLoginCount;

    context.consecutiveFailureCount =
        failedLoginCount;

    // No new Passkey challenge has occurred yet.
    context.challengeResponseTime = null;

    // Accessing the setting does not mean the method changed.
    context.authenticationMethodChanged = false;

    // No credential verification has occurred in this request.
    context.signCountAbnormal = false;
    context.credentialMismatch = false;


    // ========================================================
    // 2. Blacklist check
    // ========================================================

    const currentIpHash =
        hashForCompare(
            context.ip || ''
        );

    const blacklistStatus =
        await redisClient.get(
            `blacklist:ip:${currentIpHash}`
        );

    context.blacklistIpDetected =
        blacklistStatus === '1';


    // ========================================================
    // 3. Compare with previous context
    // ========================================================

    const userIdHash =
        hashUserId(username);

    const contextKey =
        `lastcontext:${userIdHash}`;

    const previousContext =
        await redisClient.hGetAll(
            contextKey
        );

    const currentDeviceHash =
        hashForCompare(
            JSON.stringify(
                context.deviceInfo || {}
            )
        );

    const currentUaHash =
        hashForCompare(
            context.userAgent || ''
        );

    const currentCountryHash =
        hashForCompare(
            context.country || 'KR'
        );


    context.hasPreviousContext =
        Object.keys(
            previousContext
        ).length > 0;


    context.deviceChanged =
        context.hasPreviousContext
            ? previousContext.deviceHash !== currentDeviceHash
            : false;


    context.ipChanged =
        context.hasPreviousContext
            ? previousContext.ipHash !== currentIpHash
            : false;


    context.userAgentChanged =
        context.hasPreviousContext
            ? previousContext.uaHash !== currentUaHash
            : false;


    context.locationChanged =
        context.hasPreviousContext
            ? previousContext.countryHash !== currentCountryHash
            : false;


    // Sensitive action is not a new login.
    context.loginFrequency =
        parseInt(
            await redisClient.get(
                `login:count:${username}`
            ),
            10
        ) || 0;


    console.log(
        '[CASE3][SENSITIVE_ACTION]',
        {
          username,
          action: 'AUTH_METHOD_CHANGE',
          hasPreviousContext:
          context.hasPreviousContext,
          deviceChanged:
          context.deviceChanged,
          ipChanged:
          context.ipChanged,
          userAgentChanged:
          context.userAgentChanged,
          locationChanged:
          context.locationChanged
        }
    );


    // ========================================================
    // 4. Existing REAL ML + Risk Engine
    // ========================================================

    const riskResult =
        await sendRiskData(
            username,
            context
        );


    const baseRiskAction =
        String(
            riskResult.action || 'ACTIVE'
        ).toUpperCase();


    const baseRiskLevel =
        String(
            riskResult.level || 'LOW'
        ).toUpperCase();


    // Existing BLOCKED decision wins.
    // Otherwise this sensitive operation requires
    // step-up Passkey authentication.
    const finalAction =
        baseRiskAction === 'BLOCKED'
            ? 'BLOCKED'
            : 'RE_AUTH';


    console.log(
        '[CASE3][RISK_RE_EVALUATION]',
        {
          sensitiveAction:
              'AUTH_METHOD_CHANGE',

          baseRiskScore:
          riskResult.score,

          baseRiskLevel,

          baseRiskAction,

          finalAction,

          mlModelUsed:
          riskResult.mlModelUsed,

          mlModelType:
          riskResult.mlModelType,

          mlAnomalyScore:
          riskResult.mlAnomalyScore,

          mlIsAnomaly:
          riskResult.mlIsAnomaly
        }
    );


    // ========================================================
    // 5. BLOCKED
    // ========================================================

    if (
        finalAction === 'BLOCKED'
    ) {
      return res
          .status(403)
          .json({
            success: false,

            sensitiveAction:
                'AUTH_METHOD_CHANGE',

            riskReevaluated: true,

            riskScore:
            riskResult.score,

            riskLevel:
            baseRiskLevel,

            baseRiskAction,

            finalAction:
                'BLOCKED',

            requiresReauthentication:
                false,

            message:
                'Sensitive action blocked due to high risk.',

            triggers:
                riskResult.triggers || [],

            featureScores:
                riskResult.featureScores || {},

            ml: {
              modelUsed:
              riskResult.mlModelUsed,

              modelType:
              riskResult.mlModelType,

              anomalyScore:
              riskResult.mlAnomalyScore,

              isAnomaly:
              riskResult.mlIsAnomaly
            }
          });
    }


    // ========================================================
    // 6. RE_AUTH
    //
    // Redis:
    // reauth:{userId} = PENDING
    // TTL = REAUTH_TTL (180 sec)
    // ========================================================

    await createReauthState(
        username
    );


    // ========================================================
    // 현재 로그인 Session 상태도 RE-AUTH로 변경
    //
    // session:{userId}:{sessionId}
    // status = RE-AUTH
    // ========================================================

    const sessionToken =
        req.cookies?.session;


    if (sessionToken) {
      const [
        tokenUsername,
        tokenSessionId
      ] = sessionToken.split(':');


      if (
          tokenUsername === username
          &&
          tokenSessionId
      ) {
        const updated =
            await updateSessionStatus(
                username,
                tokenSessionId,
                'RE-AUTH'
            );


        console.log(
            '[REAUTH][SESSION_STATUS]',
            {
              username,
              sessionId:
              tokenSessionId,
              status:
                  'RE-AUTH',
              updated
            }
        );
      }
    }


    console.log(
        '[REAUTH][REQUESTED]',
        {
          username,
          key:
              `reauth:${username}`,
          state:
              'PENDING'
        }
    );


    // ========================================================
    // 7. RE_AUTH response
    // ========================================================

    return res
        .status(200)
        .json({
          success: false,

          sensitiveAction:
              'AUTH_METHOD_CHANGE',

          riskReevaluated: true,

          riskScore:
          riskResult.score,

          riskLevel:
          baseRiskLevel,

          baseRiskAction,

          finalAction:
              'RE_AUTH',

          requiresReauthentication:
              true,

          message:
              'Additional Passkey authentication is required before this sensitive action.',

          triggers:
              riskResult.triggers || [],

          featureScores:
              riskResult.featureScores || {},

          ml: {
            modelUsed:
            riskResult.mlModelUsed,

            modelType:
            riskResult.mlModelType,

            anomalyScore:
            riskResult.mlAnomalyScore,

            isAnomaly:
            riskResult.mlIsAnomaly
          }
        });


  } catch (error) {
    console.error(
        '[CASE3][ERROR]',
        error
    );

    return res
        .status(500)
        .json({
          success: false,
          error:
              'RISK_RE_EVALUATION_FAILED',
          message:
          error.message
        });
  }
};


// ============================================================
// CASE 3
// RE_AUTH 전용 Context 조회
//
// 중요:
// 일반 authMiddleware는 RE-AUTH 상태의 세션을 차단한다.
//
// 따라서 Passkey 추가 인증을 시작할 때는
// 이 API에서 직접 아래 3가지를 확인한다.
//
// 1. session cookie 존재
// 2. session.status === RE-AUTH
// 3. reauth:{userId} === PENDING
//
// Keyspace Notification을 사용하지 않으므로
// reauth key가 사라졌다면 TTL 만료로 판단하고
// Session을 BLOCKED로 변경한다.
// ============================================================

exports.getReauthContext = async (req, res) => {
  try {

    // ========================================================
    // 1. Session cookie
    // ========================================================

    const sessionToken =
        req.cookies?.session;


    if (!sessionToken) {
      return res
          .status(401)
          .json({
            success: false,
            error:
                'SESSION_REQUIRED'
          });
    }


    // ========================================================
    // 2. Token parsing
    //
    // token:
    // username:sessionId
    // ========================================================

    const [
      username,
      sessionId
    ] = sessionToken.split(':');


    if (
        !username
        ||
        !sessionId
    ) {
      return res
          .status(401)
          .json({
            success: false,
            error:
                'INVALID_SESSION_TOKEN'
          });
    }


    // ========================================================
    // 3. Session 조회
    // ========================================================

    const sessionKey =
        `session:${username}:${sessionId}`;


    const rawSession =
        await redisClient.get(
            sessionKey
        );


    if (!rawSession) {
      return res
          .status(401)
          .json({
            success: false,
            error:
                'SESSION_EXPIRED'
          });
    }


    let session;

    try {
      session =
          JSON.parse(
              rawSession
          );
    } catch (parseError) {

      console.error(
          '[REAUTH][INVALID_SESSION_DATA]',
          {
            username,
            sessionId,
            error:
            parseError.message
          }
      );

      return res
          .status(500)
          .json({
            success: false,
            error:
                'INVALID_SESSION_DATA'
          });
    }


    // ========================================================
    // 4. 이미 BLOCKED 상태
    // ========================================================

    if (
        session.status === 'BLOCKED'
    ) {
      return res
          .status(403)
          .json({
            success: false,
            error:
                'SESSION_BLOCKED'
          });
    }


    // ========================================================
    // 5. RE-AUTH 상태 확인
    // ========================================================

    if (
        session.status !== 'RE-AUTH'
    ) {
      return res
          .status(409)
          .json({
            success: false,
            error:
                'REAUTH_NOT_REQUIRED',
            status:
                session.status || 'ACTIVE'
          });
    }


    // ========================================================
    // 6. reauth:{userId} 확인
    // ========================================================

    const reauthKey =
        `reauth:${username}`;


    const reauthState =
        await redisClient.get(
            reauthKey
        );


    // ========================================================
    // 7. PENDING이면 추가 Passkey 인증 허용
    // ========================================================

    if (
        reauthState === 'PENDING'
    ) {

      const remainingTTL =
          await redisClient.ttl(
              reauthKey
          );


      console.log(
          '[REAUTH][CONTEXT_OK]',
          {
            username,
            sessionId,
            state:
            reauthState,
            ttl:
            remainingTTL
          }
      );


      return res
          .status(200)
          .json({
            success: true,
            username,
            sessionId,
            reauthPending:
                true,
            remainingTTL
          });
    }


    // ========================================================
    // 8. RE-AUTH Session인데 reauth key가 없음
    //
    // => REAUTH_TTL 만료
    // => Lazy expiration detection
    // => Session BLOCKED
    // ========================================================

    const blocked =
        await updateSessionStatus(
            username,
            sessionId,
            'BLOCKED'
        );


    console.log(
        '[REAUTH][EXPIRED_CONTEXT]',
        {
          username,
          sessionId,
          reauthState,
          sessionBlocked:
          blocked
        }
    );


    return res
        .status(401)
        .json({
          success: false,
          error:
              'REAUTH_EXPIRED',
          requiresReauthentication:
              false
        });


  } catch (error) {

    console.error(
        '[REAUTH][CONTEXT_ERROR]',
        error
    );


    return res
        .status(500)
        .json({
          success: false,
          error:
              'REAUTH_CONTEXT_FAILED',
          message:
          error.message
        });
  }
};
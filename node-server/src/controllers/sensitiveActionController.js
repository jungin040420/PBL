const {
  redisClient,
  db
} = require('../../config/db');

const {
  sendRiskData
} = require('../services/riskService');

const {
  updateSessionStatus
} = require('../services/session');

const {
  hashUserId,
  hashForCompare
} = require('../utils/anonymize');

const verificationService =
    require('../services/verificationService');


// ============================================================
// Session Token Parser
//
// Cookie:
// {userId}:{sessionId}
// ============================================================

function parseSessionToken(sessionToken) {

  if (!sessionToken) {
    return null;
  }

  const separatorIndex =
      sessionToken.indexOf(':');

  if (separatorIndex <= 0) {
    return null;
  }

  const userId =
      sessionToken.slice(
          0,
          separatorIndex
      );

  const sessionId =
      sessionToken.slice(
          separatorIndex + 1
      );

  if (
      !userId ||
      !sessionId
  ) {
    return null;
  }

  return {
    userId,
    sessionId
  };
}


// ============================================================
// CASE 3
// 인증수단 변경 요청
//
// ACTIVE
//   ↓
// Sensitive Action
//   ↓
// Current Context Re-Collection
//   ↓
// Rule + Isolation Forest Risk Re-Evaluation
//   ↓
// RE_AUTH
//   ↓
// stepup:{userId} = PENDING
//   ↓
// Passkey Step-up
// ============================================================

exports.requestAuthMethodChange = async (req, res) => {

  try {

    const context =
        req.context || {};


    // ========================================================
    // 1. 현재 Session Cookie 확인
    //
    // 중요:
    // 클라이언트에서 username을 받지 않는다.
    // 세션에 포함된 DB PK userId를 사용한다.
    // ========================================================

    const sessionToken =
        req.cookies?.session;


    const parsedSession =
        parseSessionToken(
            sessionToken
        );


    if (!parsedSession) {

      return res
          .status(401)
          .json({
            success: false,
            error:
                'SESSION_REQUIRED',
            message:
                '유효한 로그인 세션이 필요합니다.'
          });
    }


    const {
      userId: tokenUserId,
      sessionId: tokenSessionId
    } = parsedSession;


    // ========================================================
    // 2. Redis Session 확인
    // ========================================================

    const sessionKey =
        `session:${tokenUserId}:${tokenSessionId}`;


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
                'SESSION_EXPIRED',
            message:
                '로그인 세션이 만료되었습니다.'
          });
    }


    let currentSession;


    try {

      currentSession =
          JSON.parse(
              rawSession
          );

    } catch (parseError) {

      console.error(
          '[CASE3][INVALID_SESSION_DATA]',
          parseError
      );


      return res
          .status(500)
          .json({
            success: false,
            error:
                'INVALID_SESSION_DATA'
          });
    }


    if (
        currentSession.status ===
        'BLOCKED'
    ) {

      return res
          .status(403)
          .json({
            success: false,
            error:
                'SESSION_BLOCKED',
            message:
                '차단된 세션입니다.'
          });
    }


    if (
        currentSession.status !==
        'ACTIVE'
    ) {

      return res
          .status(409)
          .json({
            success: false,
            error:
                'INVALID_SESSION_STATUS',
            status:
            currentSession.status,
            message:
                '민감 행위 요청은 ACTIVE 세션에서만 가능합니다.'
          });
    }


    // ========================================================
    // 3. Session DB PK userId → 실제 username 조회
    //
    // 기존:
    // req.body.username
    //
    // 수정:
    // Session userId 기준 DB 조회
    // ========================================================

    const [userRows] =
        await db.query(
            `
            SELECT
              id,
              username
            FROM users
            WHERE id = ?
            LIMIT 1
            `,
            [
              tokenUserId
            ]
        );


    if (
        !userRows ||
        userRows.length === 0
    ) {

      return res
          .status(404)
          .json({
            success: false,
            error:
                'USER_NOT_FOUND',
            message:
                '세션에 해당하는 사용자를 찾을 수 없습니다.'
          });
    }


    const userId =
        userRows[0].id;


    const username =
        userRows[0].username;


    if (
        String(userId) !==
        String(tokenUserId)
    ) {

      console.warn(
          '[CASE3][SESSION_USER_MISMATCH]',
          {
            dbUserId:
            userId,

            tokenUserId
          }
      );


      return res
          .status(401)
          .json({
            success: false,
            error:
                'SESSION_USER_MISMATCH'
          });
    }


    // ========================================================
    // 4. 로그인 실패 이력
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


    context.challengeResponseTime =
        null;


    context.authenticationMethodChanged =
        false;


    context.signCountAbnormal =
        false;


    context.credentialMismatch =
        false;


    // ========================================================
    // 5. IP Blacklist
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
    // 6. 이전 Context 비교
    // ========================================================

    const userIdHash =
        hashUserId(
            username
        );


    const contextKey =
        `lastcontext:${userIdHash}`;


    const previousContext =
        await redisClient.hGetAll(
            contextKey
        );


    const hasPreviousContext =
        previousContext &&
        Object.keys(
            previousContext
        ).length > 0;


    context.hasPreviousContext =
        hasPreviousContext;


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


    context.deviceChanged =
        hasPreviousContext
            ? previousContext.deviceHash !==
            currentDeviceHash
            : false;


    context.isNewDevice =
        context.deviceChanged;


    context.ipChanged =
        hasPreviousContext
            ? previousContext.ipHash !==
            currentIpHash
            : false;


    context.userAgentChanged =
        hasPreviousContext
            ? previousContext.uaHash !==
            currentUaHash
            : false;


    context.locationChanged =
        hasPreviousContext
            ? previousContext.countryHash !==
            currentCountryHash
            : false;


    context.regionChanged =
        context.locationChanged;


    context.loginRegion =
        context.country || 'KR';


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
          userId,

          sensitiveAction:
              'AUTH_METHOD_CHANGE',

          hasPreviousContext:
          context.hasPreviousContext,

          isNewDevice:
          context.isNewDevice,

          ipChanged:
          context.ipChanged,

          userAgentChanged:
          context.userAgentChanged,

          regionChanged:
          context.regionChanged
        }
    );


    // ========================================================
    // 7. Risk Re-Evaluation
    // ========================================================

    const riskResult =
        await sendRiskData(
            username,
            context
        );


    const baseRiskAction =
        String(
            riskResult.action ||
            'ACTIVE'
        ).toUpperCase();


    const baseRiskLevel =
        String(
            riskResult.level ||
            'LOW'
        ).toUpperCase();


    // ========================================================
    // 인증수단 변경은 Sensitive Action
    //
    // BLOCKED → 차단
    // 그 외 → Passkey Step-up 강제
    // ========================================================

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
    // 8. BLOCKED
    // ========================================================

    if (
        finalAction ===
        'BLOCKED'
    ) {

      await updateSessionStatus(
          userId,
          tokenSessionId,
          'BLOCKED'
      );


      console.warn(
          '[CASE3][BLOCKED]',
          {
            userId,
            sessionId:
            tokenSessionId,
            riskScore:
            riskResult.score
          }
      );


      return res
          .status(403)
          .json({

            success: false,

            sensitiveAction:
                'AUTH_METHOD_CHANGE',

            riskReevaluated:
                true,

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
    // 9. 기존 Session
    //
    // ACTIVE → RE_AUTH
    // ========================================================

    const updated =
        await updateSessionStatus(
            userId,
            tokenSessionId,
            'RE_AUTH'
        );


    if (!updated) {

      return res
          .status(500)
          .json({
            success: false,
            error:
                'SESSION_UPDATE_FAILED'
          });
    }


    console.log(
        '[STEPUP][SESSION_STATUS]',
        {
          userId,

          sessionId:
          tokenSessionId,

          status:
              'RE_AUTH',

          updated
        }
    );


    // ========================================================
    // 10. Step-up 상태 생성
    //
    // stepup:{DB PK userId}
    // value = PENDING
    // TTL = REAUTH_TTL (default 180)
    // ========================================================

    const stepupTTL =
        parseInt(
            process.env.REAUTH_TTL,
            10
        ) || 180;


    const stepupKey =
        `stepup:${userId}`;


    await redisClient.set(
        stepupKey,
        'PENDING',
        {
          EX:
          stepupTTL
        }
    );


    const remainingTTL =
        await redisClient.ttl(
            stepupKey
        );


    console.log(
        '[STEPUP][REQUESTED]',
        {
          userId,

          sessionId:
          tokenSessionId,

          key:
          stepupKey,

          state:
              'PENDING',

          ttl:
          remainingTTL
        }
    );


    // ========================================================
    // 11. Client Response
    // ========================================================

    return res
        .status(200)
        .json({

          success: false,

          sensitiveAction:
              'AUTH_METHOD_CHANGE',

          riskReevaluated:
              true,

          riskScore:
          riskResult.score,

          riskLevel:
          baseRiskLevel,

          baseRiskAction,

          finalAction:
              'RE_AUTH',

          requiresReauthentication:
              true,

          reauthenticationMethod:
              'PASSKEY',

          message:
              '민감 행위를 계속하려면 Passkey 추가 인증이 필요합니다.',

          stepupTTL:
          remainingTTL,

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
// Step-up Context 조회
//
// RE_AUTH 세션은 일반 authMiddleware에서
// 차단될 수 있으므로 Controller에서 직접 검증.
//
// RE_AUTH
// +
// stepup:{userId}=PENDING
//
// 일 때만 username을 반환한다.
// ============================================================

exports.getReauthContext = async (req, res) => {

  try {

    // ========================================================
    // 1. Session Cookie
    // ========================================================

    const parsedSession =
        parseSessionToken(
            req.cookies?.session
        );


    if (!parsedSession) {

      return res
          .status(401)
          .json({
            success: false,
            error:
                'SESSION_REQUIRED'
          });
    }


    const {
      userId,
      sessionId
    } = parsedSession;


    // ========================================================
    // 2. Redis Session
    // ========================================================

    const sessionKey =
        `session:${userId}:${sessionId}`;


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
          '[STEPUP][INVALID_SESSION_DATA]',
          {
            userId,
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
    // 3. Session 상태
    // ========================================================

    if (
        session.status ===
        'BLOCKED'
    ) {

      return res
          .status(403)
          .json({
            success: false,
            error:
                'SESSION_BLOCKED'
          });
    }


    if (
        session.status !==
        'RE_AUTH'
    ) {

      return res
          .status(409)
          .json({
            success: false,
            error:
                'STEPUP_NOT_REQUIRED',
            status:
                session.status ||
                'ACTIVE'
          });
    }


    // ========================================================
    // 4. stepup:{userId}
    // ========================================================

    const stepupKey =
        `stepup:${userId}`;


    const stepupState =
        await redisClient.get(
            stepupKey
        );


    if (
        stepupState ===
        'PENDING'
    ) {

      const remainingTTL =
          await redisClient.ttl(
              stepupKey
          );


      // ======================================================
      // DB PK userId → username
      // ======================================================

      const [userRows] =
          await db.query(
              `
              SELECT username
              FROM users
              WHERE id = ?
              LIMIT 1
              `,
              [
                userId
              ]
          );


      const username =
          userRows?.[0]?.username ||
          null;


      if (!username) {

        return res
            .status(404)
            .json({
              success: false,
              error:
                  'USER_NOT_FOUND'
            });
      }


      console.log(
          '[STEPUP][CONTEXT_OK]',
          {
            userId,
            sessionId,
            state:
            stepupState,
            ttl:
            remainingTTL
          }
      );


      return res
          .status(200)
          .json({

            success: true,

            userId,

            username,

            sessionId,

            stepupPending:
                true,

            stepupState,

            remainingTTL
          });
    }


    // ========================================================
    // 5. RE_AUTH Session인데 Step-up Key 없음
    //
    // TTL 만료 / 비정상 상태
    //
    // Fail Secure:
    // RE_AUTH → BLOCKED
    // ========================================================

    const blocked =
        await updateSessionStatus(
            userId,
            sessionId,
            'BLOCKED'
        );


    console.warn(
        '[STEPUP][EXPIRED_CONTEXT]',
        {
          userId,
          sessionId,
          stepupState:
              stepupState || null,
          sessionBlocked:
          blocked
        }
    );


    return res
        .status(401)
        .json({

          success: false,

          error:
              'STEPUP_EXPIRED',

          requiresReauthentication:
              false
        });


  } catch (error) {

    console.error(
        '[STEPUP][CONTEXT_ERROR]',
        error
    );


    return res
        .status(500)
        .json({

          success: false,

          error:
              'STEPUP_CONTEXT_FAILED',

          message:
          error.message
        });
  }
};


// ============================================================
// CASE 3
// Passkey Step-up 전용 검증
//
// 절대로 /auth/login/finish 사용하지 않는다.
//
// 이유:
// loginFinish는 로그인 전용 Endpoint라
// 새로운 Session을 생성하고 Cookie를 교체한다.
//
// 이 Endpoint는:
//
// 기존 RE_AUTH Session
// +
// stepup:{userId} = PENDING
// +
// Passkey Assertion
//
// 을 검증한다.
//
// 성공:
//
// RE_AUTH → ACTIVE
// DEL stepup:{userId}
// GRANTED
//
// 새 Session 생성 없음.
// Cookie 재발급 없음.
// ============================================================

exports.verifyStepUp = async (req, res) => {

  try {

    const {
      challengeId,
      credential
    } = req.body || {};


    // ========================================================
    // 1. 입력값 확인
    // ========================================================

    if (
        !challengeId ||
        !credential
    ) {

      return res
          .status(400)
          .json({

            success: false,

            error:
                'STEPUP_REQUIRED_FIELDS_MISSING'
          });
    }


    // ========================================================
    // 2. 기존 Session Cookie
    // ========================================================

    const parsedSession =
        parseSessionToken(
            req.cookies?.session
        );


    if (!parsedSession) {

      return res
          .status(401)
          .json({

            success: false,

            error:
                'SESSION_REQUIRED'
          });
    }


    const {
      userId,
      sessionId
    } = parsedSession;


    // ========================================================
    // 3. 기존 Redis Session
    // ========================================================

    const sessionKey =
        `session:${userId}:${sessionId}`;


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
          '[STEPUP][VERIFY_INVALID_SESSION]',
          parseError
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
    // 4. 반드시 RE_AUTH 상태
    // ========================================================

    if (
        session.status ===
        'BLOCKED'
    ) {

      return res
          .status(403)
          .json({

            success: false,

            error:
                'SESSION_BLOCKED'
          });
    }


    if (
        session.status !==
        'RE_AUTH'
    ) {

      return res
          .status(409)
          .json({

            success: false,

            error:
                'STEPUP_NOT_REQUIRED',

            status:
            session.status
          });
    }


    // ========================================================
    // 5. Step-up PENDING 확인
    // ========================================================

    const stepupKey =
        `stepup:${userId}`;


    const stepupState =
        await redisClient.get(
            stepupKey
        );


    if (
        stepupState !==
        'PENDING'
    ) {

      await updateSessionStatus(
          userId,
          sessionId,
          'BLOCKED'
      );


      console.warn(
          '[STEPUP][VERIFY_EXPIRED]',
          {
            userId,
            sessionId
          }
      );


      return res
          .status(401)
          .json({

            success: false,

            error:
                'STEPUP_EXPIRED'
          });
    }


    // ========================================================
    // 6. DB PK userId → username
    //
    // 클라이언트 username은 신뢰하지 않는다.
    // ========================================================

    const [userRows] =
        await db.query(
            `
            SELECT
              id,
              username
            FROM users
            WHERE id = ?
            LIMIT 1
            `,
            [
              userId
            ]
        );


    if (
        !userRows ||
        userRows.length === 0
    ) {

      return res
          .status(404)
          .json({

            success: false,

            error:
                'USER_NOT_FOUND'
          });
    }


    const username =
        userRows[0].username;


    // ========================================================
    // 7. Passkey Assertion 검증
    //
    // verificationService만 직접 호출.
    //
    // loginFinish Controller 호출 안 함.
    // Session 생성 안 함.
    // Cookie 변경 안 함.
    // ========================================================

    const verificationResult =
        await verificationService.verifyLogin(
            username,
            challengeId,
            credential
        );


    console.log(
        '[STEPUP][PASSKEY_VERIFY]',
        {
          userId,

          sessionId,

          verified:
          verificationResult.verified,

          credentialMismatch:
              verificationResult
                  .credentialMismatch ||
              false,

          signCountAbnormal:
              verificationResult
                  .signCountAbnormal ||
              false
        }
    );


    // ========================================================
    // 8. Passkey 실패
    // ========================================================

    if (
        !verificationResult.verified
    ) {

      return res
          .status(401)
          .json({

            success: false,

            error:
                'STEPUP_PASSKEY_VERIFICATION_FAILED',

            reason:
                verificationResult.reason ||
                'VERIFICATION_FAILED'
          });
    }


    // ========================================================
    // 9. Passkey 성공
    //
    // 같은 Session:
    //
    // RE_AUTH → ACTIVE
    // ========================================================

    const updated =
        await updateSessionStatus(
            userId,
            sessionId,
            'ACTIVE'
        );


    if (!updated) {

      return res
          .status(500)
          .json({

            success: false,

            error:
                'SESSION_UPDATE_FAILED'
          });
    }


    // ========================================================
    // 10. Step-up 일회성 Key 삭제
    // ========================================================

    const deleted =
        await redisClient.del(
            stepupKey
        );


    console.log(
        '[STEPUP][SUCCESS]',
        {
          userId,

          sessionId,

          previousStatus:
              'RE_AUTH',

          sessionStatus:
              'ACTIVE',

          stepupDeleted:
              deleted === 1,

          sensitiveAction:
              'AUTH_METHOD_CHANGE',

          access:
              'GRANTED'
        }
    );


    // ========================================================
    // 11. 성공
    // ========================================================

    return res
        .status(200)
        .json({

          success: true,

          reauthenticationMethod:
              'PASSKEY',

          sensitiveAction:
              'AUTH_METHOD_CHANGE',

          sessionStatus:
              'ACTIVE',

          access:
              'GRANTED'
        });


  } catch (error) {

    console.error(
        '[STEPUP][VERIFY_ERROR]',
        error
    );


    return res
        .status(500)
        .json({

          success: false,

          error:
              'STEPUP_VERIFY_FAILED',

          message:
          error.message
        });
  }
};
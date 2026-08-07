const webauthnService = require("../services/webauthnService");
const verificationService = require("../services/verificationService");
const sessionManager = require("../services/sessionManager");
const { sendRiskData } = require("../services/riskService");
const { redisClient, db } = require("../../config/db");

const {
  hashUserId,
  hashForCompare,
} = require("../utils/anonymize");

console.log("sendRiskData 타입:", typeof sendRiskData);


// ============================================================
// 등록 1단계: Challenge 생성
// ============================================================

exports.registerStart = async (req, res) => {
  try {
    const { username, displayName } = req.body;

    if (!username || !displayName) {
      return res.status(400).json({
        error: "필수 입력값 누락",
      });
    }

    const options =
        await webauthnService.generateRegistrationOptions(
            username,
            displayName
        );

    return res.status(200).json(options);

  } catch (error) {
    console.error("registerStart 오류:", error);

    return res.status(500).json({
      error: "서버 오류",
    });
  }
};


// ============================================================
// 등록 2단계: 서명 검증 및 공개키 저장
// ============================================================

exports.registerFinish = async (req, res) => {
  try {
    const {
      username,
      email,
      challengeId,
      credential,
    } = req.body;

    const result =
        await verificationService.verifyRegistration(
            username,
            email,
            challengeId,
            credential
        );

    if (!result.verified) {
      return res.status(400).json({
        error: "등록 검증 실패",
      });
    }

    return res.status(200).json({
      success: true,
      message: "등록 완료",
    });

  } catch (error) {
    console.error("registerFinish 오류:", error);

    return res.status(500).json({
      error: "서버 오류",
    });
  }
};


// ============================================================
// 로그인 1단계: Challenge 생성
// ============================================================

exports.loginStart = async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({
        error: "아이디를 입력하세요",
      });
    }

    /*
     * Challenge 응답시간 측정을 위한 시작시간 저장
     */
    await redisClient.set(
        `challenge:time:${username}`,
        Date.now(),
        {
          EX: 300,
        }
    );

    const options =
        await webauthnService.generateLoginOptions(
            username
        );

    return res.status(200).json(options);

  } catch (error) {
    console.error("loginStart 오류:", error);

    return res.status(500).json({
      error: "서버 오류",
    });
  }
};


// ============================================================
// 로그인 2단계: 서명 검증 + Risk 분석 + 세션 발급
// ============================================================

exports.loginFinish = async (req, res) => {
  try {
    const {
      username,
      challengeId,
      credential,
    } = req.body;

    const context = req.context || {};

    if (!username || !challengeId || !credential) {
      return res.status(400).json({
        error: "로그인 필수 입력값 누락",
      });
    }


    // --------------------------------------------------------
    // 1. Challenge 응답시간 계산
    // --------------------------------------------------------

    const startTime = await redisClient.get(
        `challenge:time:${username}`
    );

    const challengeResponseTime =
        startTime
            ? Date.now() - Number(startTime)
            : null;

    context.challengeResponseTime =
        challengeResponseTime;

    await redisClient.del(
        `challenge:time:${username}`
    );


    // --------------------------------------------------------
    // 2. WebAuthn 로그인 검증
    // --------------------------------------------------------

    const result =
        await verificationService.verifyLogin(
            username,
            challengeId,
            credential
        );

    console.log(
        "verifyLogin 결과:",
        result
    );


    // --------------------------------------------------------
    // 3. 로그인 검증 실패 처리
    // --------------------------------------------------------

    if (!result.verified) {
      const failKey =
          `login:fail:${username}`;

      await redisClient.incr(
          failKey
      );

      await redisClient.expire(
          failKey,
          3600
      );

      return res.status(401).json({
        error: "로그인 검증 실패",
      });
    }


    // --------------------------------------------------------
    // 4. 기존 로그인 실패 횟수 조회
    // --------------------------------------------------------

    const failedLoginCount =
        Number(
            await redisClient.get(
                `login:fail:${username}`
            )
        ) || 0;

    context.failedLoginCount =
        failedLoginCount;

    await redisClient.del(
        `login:fail:${username}`
    );


    // --------------------------------------------------------
    // 5. 사용자 DB PK 조회
    //
    // F-08:
    // 직전 IP / UA 등의 개인정보는 users 테이블에 저장하지 않는다.
    // --------------------------------------------------------

    const [rows] = await db.query(
        `
        SELECT
          id,
          username
        FROM users
        WHERE username = ?
        LIMIT 1
      `,
        [username]
    );

    if (!rows || rows.length === 0) {
      return res.status(404).json({
        error: "사용자를 찾을 수 없습니다.",
      });
    }

    const user = rows[0];


    // --------------------------------------------------------
    // 6. F-08 비교용 해시 생성
    // --------------------------------------------------------

    const userIdHash =
        hashUserId(user.id);

    const currentIpHash =
        hashForCompare(
            context.ip
        );

    const currentUserAgentHash =
        hashForCompare(
            context.userAgent
        );

    /*
     * 현재 별도의 device fingerprint가 없기 때문에
     * deviceType을 비교용 값으로 사용한다.
     *
     * 추후 실제 device fingerprint가 추가되면
     * 해당 값을 hashForCompare() 처리해서 교체 가능.
     */
    const currentDeviceHash =
        hashForCompare(
            context.deviceInfo?.deviceType ||
            "unknown"
        );

    const currentRegion =
        context.country || "KR";


    // --------------------------------------------------------
    // 7. Redis 직전 로그인 Context 조회
    // --------------------------------------------------------

    const lastContextKey =
        `lastcontext:${userIdHash}`;

    const previousContextRaw =
        await redisClient.get(
            lastContextKey
        );

    let previousContext = null;

    if (previousContextRaw) {
      try {
        previousContext =
            JSON.parse(
                previousContextRaw
            );
      } catch (error) {
        console.error(
            "직전 로그인 컨텍스트 JSON 파싱 실패:",
            error.message
        );
      }
    }


    // --------------------------------------------------------
    // 8. 이전 로그인과 현재 로그인 비교
    // --------------------------------------------------------

    if (previousContext) {

      context.ipChanged =
          previousContext.ipHash !==
          currentIpHash;

      context.userAgentChanged =
          previousContext.userAgentHash !==
          currentUserAgentHash;

      context.deviceChanged =
          previousContext.deviceHash !==
          currentDeviceHash;

      context.locationChanged =
          previousContext.region !==
          currentRegion;

    } else {

      /*
       * 이전 Context가 없으면 최초 로그인으로 판단.
       *
       * 비교 기준이 없기 때문에 변경 Feature는 false.
       */
      context.ipChanged = false;
      context.userAgentChanged = false;
      context.deviceChanged = false;
      context.locationChanged = false;
    }


    console.log(
        "로그인 Context 비교 결과:",
        {
          hasPreviousContext:
              Boolean(previousContext),

          ipChanged:
          context.ipChanged,

          userAgentChanged:
          context.userAgentChanged,

          deviceChanged:
          context.deviceChanged,

          locationChanged:
          context.locationChanged,
        }
    );


    // --------------------------------------------------------
    // 9. 현재 Context를 Redis에 저장
    //
    // 원본 IP / User-Agent는 저장하지 않는다.
    // --------------------------------------------------------

    const currentContext = {
      ipHash:
      currentIpHash,

      userAgentHash:
      currentUserAgentHash,

      deviceHash:
      currentDeviceHash,

      region:
      currentRegion,

      updatedAt:
          new Date().toISOString(),
    };

    await redisClient.set(
        lastContextKey,
        JSON.stringify(
            currentContext
        )
    );


    // --------------------------------------------------------
    // 10. 로그인 빈도 계산
    // --------------------------------------------------------

    const loginFrequencyKey =
        `login:count:${username}`;

    const loginFrequency =
        await redisClient.incr(
            loginFrequencyKey
        );

    await redisClient.expire(
        loginFrequencyKey,
        3600
    );

    context.loginFrequency =
        loginFrequency;


    // --------------------------------------------------------
    // 11. Python Risk API 호출
    // --------------------------------------------------------

    let riskScore = 0;
    let riskLevel = "low";
    let riskAction = "ACTIVE";

    let riskMessage =
        "리스크 분석 서버 응답 없음";

    let riskTriggers = [];
    let riskFeatureScores = {};


    try {

      /*
       * username이 아닌 users.id를 전달한다.
       *
       * riskService.js에서:
       *
       * hashUserId(user.id)
       * → userIdHash
       *
       * hashForCompare(context.ip)
       * → ipHash
       *
       * 로 변환해서 Python에 전달한다.
       */
      const riskResult =
          await sendRiskData(
              user.id,
              context
          );

      riskScore =
          riskResult.score ?? 0;

      riskLevel =
          riskResult.level ?? "low";

      riskAction =
          riskResult.action ?? "ACTIVE";

      riskMessage =
          riskResult.message ??
          "리스크 분석 완료";

      riskTriggers =
          riskResult.triggers ?? [];

      riskFeatureScores =
          riskResult.featureScores ?? {};


      console.log(
          "리스크 분석 완료:",
          {
            riskScore,
            riskLevel,
            riskAction,
          }
      );

    } catch (error) {

      console.error(
          "리스크 스코어 요청 실패:",
          error.message
      );

      /*
       * 현재 개발 단계에서는
       * Risk API 장애 시 로그인 흐름을 유지한다.
       *
       * 추후 fail-open / fail-closed 정책 확정 필요.
       */
    }


    // --------------------------------------------------------
    // 12. Risk Action 처리
    // --------------------------------------------------------

    if (riskAction === "BLOCKED") {

      return res.status(403).json({
        success: false,

        message:
            riskMessage ||
            "위험도가 높아 로그인이 차단되었습니다.",

        riskScore,
        riskLevel,
        riskAction,

        triggers:
        riskTriggers,
      });
    }


    if (riskAction === "RE_AUTH") {

      return res.status(200).json({
        success: false,

        requiresReauthentication:
            true,

        message:
            riskMessage ||
            "추가 인증이 필요합니다.",

        riskScore,
        riskLevel,
        riskAction,

        triggers:
        riskTriggers,

        featureScores:
        riskFeatureScores,
      });
    }


    // --------------------------------------------------------
    // 13. LOW Risk → 세션 생성
    // --------------------------------------------------------

    const session =
        await sessionManager.createSession(
            username,
            context.ip,
            context.userAgent
        );

    console.log(
        "세션 생성 완료:",
        Boolean(
            session?.token
        )
    );

    if (!session || !session.token) {
      throw new Error(
          "세션 토큰 생성 실패"
      );
    }


    // --------------------------------------------------------
    // 14. 세션 Cookie 저장
    // --------------------------------------------------------

    const isNgrok =
        req.headers.host?.includes(
            "ngrok"
        );

    res.cookie(
        "session",
        session.token,
        {
          httpOnly: true,

          secure:
              Boolean(isNgrok),

          sameSite:
              isNgrok
                  ? "none"
                  : "lax",

          maxAge:
              1000 * 60 * 60,
        }
    );


    // --------------------------------------------------------
    // 15. 로그인 성공 응답
    // --------------------------------------------------------

    return res.status(200).json({
      success: true,
      message: "로그인 성공",

      context: {

        deviceType:
            context.deviceInfo
                ?.deviceType ||
            "unknown",

        os:
            context.deviceInfo
                ?.os ||
            "unknown",

        isNightAccess:
            context.isNightAccess ??
            false,
      },

      riskScore,
      riskLevel,
      riskAction,
      riskMessage,

      triggers:
      riskTriggers,

      featureScores:
      riskFeatureScores,
    });

  } catch (error) {

    console.error(
        "loginFinish 오류:",
        error
    );

    return res.status(500).json({
      error: "서버 오류",
    });
  }
};


// ============================================================
// 로그아웃
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
        "session"
    );

    return res.status(200).json({
      success: true,
      message: "로그아웃 완료",
    });

  } catch (error) {

    console.error(
        "logout 오류:",
        error
    );

    return res.status(500).json({
      error: "서버 오류",
    });
  }
};


// ============================================================
// 세션 검증
// ============================================================

exports.verifySession = async (
    req,
    res
) => {
  try {

    const sessionToken =
        req.cookies.session;

    if (!sessionToken) {
      return res.status(401).json({
        error: "토큰 없음",
      });
    }

    const result =
        await sessionManager.verifySession(
            sessionToken
        );

    if (!result.valid) {
      return res.status(401).json({
        error:
            result.reason ||
            "세션 만료",
      });
    }

    return res.status(200).json({
      success: true,
      username:
      result.username,
    });

  } catch (error) {

    console.error(
        "verifySession 오류:",
        error
    );

    return res.status(500).json({
      error: "서버 오류",
    });
  }
};
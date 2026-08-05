const webauthnService = require("../services/webauthnService");
const verificationService = require("../services/verificationService");
const sessionManager = require("../services/sessionManager");
const { sendRiskData } = require("../services/riskService");
const { redisClient, db } = require("../../config/db");

console.log("sendRiskData 타입:", typeof sendRiskData);


// 등록 1단계: challenge 생성
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


// 등록 2단계: 서명 검증 및 공개키 저장
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


// 로그인 1단계: challenge 생성
exports.loginStart = async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({
        error: "아이디를 입력하세요",
      });
    }

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


// 로그인 2단계: 서명 검증 및 세션 발급
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

    /*
     * Challenge 응답시간 계산
     */
    const startTime = await redisClient.get(
        `challenge:time:${username}`
    );

    const challengeResponseTime = startTime
        ? Date.now() - Number(startTime)
        : null;

    context.challengeResponseTime =
        challengeResponseTime;

    await redisClient.del(
        `challenge:time:${username}`
    );

    /*
     * WebAuthn 로그인 검증
     */
    const result =
        await verificationService.verifyLogin(
            username,
            challengeId,
            credential
        );

    console.log("verifyLogin 결과:", result);

    /*
     * 로그인 실패 처리
     */
    if (!result.verified) {
      const failKey = `login:fail:${username}`;

      await redisClient.incr(failKey);
      await redisClient.expire(failKey, 3600);

      return res.status(401).json({
        error: "로그인 검증 실패",
      });
    }

    /*
     * 로그인 실패 횟수 조회
     */
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

    /*
     * 사용자 DB PK 및 직전 로그인 정보 조회
     */
    const [rows] = await db.query(
        `
        SELECT
          id,
          username,
          last_device,
          last_ip,
          last_user_agent,
          last_country
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

    /*
     * 최초 로그인 여부
     */
    const hasPreviousContext =
        user.last_device !== null ||
        user.last_ip !== null ||
        user.last_user_agent !== null ||
        user.last_country !== null;

    /*
     * 직전 로그인 정보와 현재 로그인 정보 비교
     *
     * 주의:
     * 현재는 기존 MySQL 컬럼을 이용한 임시 비교 구조다.
     * 추후 Redis lastcontext:{userIdHash} 구조로 이전해야 한다.
     */
    context.deviceChanged =
        hasPreviousContext &&
        user.last_device !== context.userAgent;

    context.ipChanged =
        hasPreviousContext &&
        user.last_ip !== context.ip;

    context.userAgentChanged =
        hasPreviousContext &&
        user.last_user_agent !==
        context.userAgent;

    context.locationChanged =
        hasPreviousContext &&
        user.last_country !== context.country;

    /*
     * 현재 로그인 정보를 DB에 갱신
     *
     * 주의:
     * 원본 IP와 User-Agent를 저장하는 구조는
     * 추후 Redis 비교용 해시 구조로 교체해야 한다.
     */
    await db.query(
        `
        UPDATE users
        SET
          last_device = ?,
          last_ip = ?,
          last_user_agent = ?,
          last_country = ?
        WHERE id = ?
      `,
        [
          context.userAgent || null,
          context.ip || null,
          context.userAgent || null,
          context.country || null,
          user.id,
        ]
    );

    /*
     * 로그인 빈도 계산
     */
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

    /*
     * Python Risk API 호출
     */
    let riskScore = 0;
    let riskLevel = "low";
    let riskAction = "ACTIVE";
    let riskMessage =
        "리스크 분석 서버 응답 없음";
    let riskTriggers = [];
    let riskFeatureScores = {};

    try {
      /*
       * username이 아니라 users.id를 전달한다.
       * riskService.js에서 hashUserId(user.id)를 호출한다.
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
       * 현재는 Rule API 실패 시 로그인 흐름 유지.
       * 추후 정책에 따라 fail-open 또는 fail-closed 확정 필요.
       */
    }

    /*
     * 위험도에 따른 인증 처리
     */
    if (riskAction === "BLOCKED") {
      return res.status(403).json({
        success: false,
        message:
            riskMessage ||
            "위험도가 높아 로그인이 차단되었습니다.",
        riskScore,
        riskLevel,
        riskAction,
        triggers: riskTriggers,
      });
    }

    if (riskAction === "RE_AUTH") {
      return res.status(200).json({
        success: false,
        requiresReauthentication: true,
        message:
            riskMessage ||
            "추가 인증이 필요합니다.",
        riskScore,
        riskLevel,
        riskAction,
        triggers: riskTriggers,
        featureScores:
        riskFeatureScores,
      });
    }

    /*
     * LOW 위험도일 경우 세션 생성
     */
    const session =
        await sessionManager.createSession(
            username,
            context.ip,
            context.userAgent
        );

    console.log(
        "세션 생성 완료:",
        Boolean(session?.token)
    );

    if (!session || !session.token) {
      throw new Error(
          "세션 토큰 생성 실패"
      );
    }

    const isNgrok =
        req.headers.host?.includes(
            "ngrok"
        );

    res.cookie(
        "session",
        session.token,
        {
          httpOnly: true,
          secure: Boolean(isNgrok),
          sameSite: isNgrok
              ? "none"
              : "lax",
          maxAge:
              1000 * 60 * 60,
        }
    );

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


// 로그아웃
exports.logout = async (req, res) => {
  try {
    const sessionToken =
        req.cookies.session;

    if (sessionToken) {
      await sessionManager.deleteSession(
          sessionToken
      );
    }

    res.clearCookie("session");

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


// 세션 검증
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
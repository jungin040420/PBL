const axios = require("axios");
const { hashUserId } = require("../utils/anonymize");

const sendRiskData = async (userId, context) => {
  const now = new Date();

  const userIdHash = hashUserId(userId);

  const payload = {
    userIdHash,

    deviceType:
        context.deviceInfo?.deviceType || "unknown",

    country:
        context.country || "KR",

    loginFrequency:
        context.loginFrequency ?? 0,

    failedLoginCount:
        context.failedLoginCount ?? 0,

    ipChanged:
        context.ipChanged ?? false,

    userAgentChanged:
        context.userAgentChanged ?? false,

    isNewDevice:
        context.deviceChanged ?? false,

    regionChanged:
        context.locationChanged ?? false,

    challengeResponseTime:
        context.challengeResponseTime ?? null,

    loginHour:
        now.getHours(),

    dayOfWeek:
        now.getDay(),
  };

  // 실제 식별자·IP는 출력하지 않고 필드 존재 여부만 확인
  console.log("리스크 전달 필드:", {
    hasUserIdHash: Boolean(payload.userIdHash),
    deviceType: payload.deviceType,
    country: payload.country,
    loginFrequency: payload.loginFrequency,
    failedLoginCount: payload.failedLoginCount,
    ipChanged: payload.ipChanged,
    userAgentChanged: payload.userAgentChanged,
    isNewDevice: payload.isNewDevice,
    regionChanged: payload.regionChanged,
    challengeResponseTime: payload.challengeResponseTime,
    loginHour: payload.loginHour,
    dayOfWeek: payload.dayOfWeek,
  });

  try {
    const response = await axios.post(
        process.env.RISK_API_URL ||
        "http://localhost:5000/analyze",
        payload,
        {
          timeout: 3000,
          headers: {
            "Content-Type": "application/json",
          },
        }
    );

    return {
      score: response.data.risk_score,
      level: response.data.risk_level,
      action: response.data.authentication_action,
      message: response.data.message,
      triggers: response.data.triggers,
      featureScores: response.data.feature_scores,
    };
  } catch (error) {
    console.error(
        "리스크 API 오류:",
        JSON.stringify(
            error.response?.data ?? error.message,
            null,
            2
        )
    );

    throw error;
  }
};

module.exports = { sendRiskData };
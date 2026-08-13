const axios = require("axios");

const {
    hashUserId,
    hashForCompare,
} = require("../utils/anonymize");


const sendRiskData = async (
    userId,
    context
) => {
    const now = new Date();

    const userIdHash =
        hashUserId(userId);

    const ipHash =
        hashForCompare(
            context.ip
        );

    const payload = {
        userIdHash,
        ipHash,

        deviceType:
            context.deviceInfo?.deviceType ??
            "unknown",

        country:
            context.country ??
            "KR",

        // 현재 로그인 지역 자체
        loginRegion:
            context.country ??
            "KR",

        loginFrequency:
            context.loginFrequency ??
            0,

        failedLoginCount:
            context.failedLoginCount ??
            0,

        ipChanged:
            context.ipChanged ??
            false,

        userAgentChanged:
            context.userAgentChanged ??
            false,

        isNewDevice:
            context.deviceChanged ??
            false,

        regionChanged:
            context.locationChanged ??
            false,

        // WebAuthn signCount 이상 여부
        signCountAbnormal:
            context.signCountAbnormal ??
            false,

        challengeResponseTime:
            context.challengeResponseTime ??
            null,

        loginHour:
            now.getHours(),

        dayOfWeek:
            now.getDay(),

        signCountAbnormal:
            context.signCountAbnormal ??
            false,

        credentialMismatch:
            context.credentialMismatch ??
            false,
    };


    console.log(
        "리스크 전달 필드:",
        {
            hasUserIdHash:
                Boolean(payload.userIdHash),

            hasIpHash:
                Boolean(payload.ipHash),

            deviceType:
            payload.deviceType,

            country:
            payload.country,

            loginRegion:
            payload.loginRegion,

            loginFrequency:
            payload.loginFrequency,

            failedLoginCount:
            payload.failedLoginCount,

            ipChanged:
            payload.ipChanged,

            userAgentChanged:
            payload.userAgentChanged,

            isNewDevice:
            payload.isNewDevice,

            regionChanged:
            payload.regionChanged,

            signCountAbnormal:
            payload.signCountAbnormal,

            challengeResponseTime:
            payload.challengeResponseTime,

            loginHour:
            payload.loginHour,

            dayOfWeek:
            payload.dayOfWeek,
        }
    );


    try {
        const response =
            await axios.post(
                process.env.RISK_API_URL ||
                "http://localhost:8000/analyze",

                payload,

                {
                    timeout: 3000,

                    headers: {
                        "Content-Type":
                            "application/json",
                    },
                }
            );


        return {
            score:
            response.data.risk_score,

            level:
            response.data.risk_level,

            action:
            response.data.authentication_action,

            message:
            response.data.message,

            triggers:
            response.data.triggers,

            featureScores:
            response.data.feature_scores,

            mlModelUsed:
                response.data.ml_model_used ??
                false,

            mlModelType:
                response.data.ml_model_type ??
                null,

            mlAnomalyScore:
                response.data.ml_anomaly_score ??
                null,

            mlIsAnomaly:
                response.data.ml_is_anomaly ??
                null,
        };

    } catch (error) {

        console.error(
            "리스크 API 오류:",
            JSON.stringify(
                error.response?.data ??
                error.message,
                null,
                2
            )
        );

        throw error;
    }
};


module.exports = {
    sendRiskData,
};
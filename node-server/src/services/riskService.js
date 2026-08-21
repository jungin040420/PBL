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

        // 현재 로그인 지역
        loginRegion:
            context.country ??
            "KR",

        // B - Behavior
        loginFrequency:
            context.loginFrequency ??
            0,

        failedLoginCount:
            context.failedLoginCount ??
            0,

        challengeResponseTime:
            context.challengeResponseTime ??
            null,

        authenticationMethodChanged:
            context.authenticationMethodChanged ??
            false,

        // N - Network
        ipChanged:
            context.ipChanged ??
            false,

        regionChanged:
            context.locationChanged ??
            false,

        // D - Device / Credential
        userAgentChanged:
            context.userAgentChanged ??
            false,

        isNewDevice:
            context.deviceChanged ??
            false,

        signCountAbnormal:
            context.signCountAbnormal ??
            false,

        credentialMismatch:
            context.credentialMismatch ??
            false,

        // T - Threat / History
        consecutiveFailureCount:
            context.consecutiveFailureCount ??
            0,

        blacklistIpDetected:
            context.blacklistIpDetected ??
            false,

        // Time
        loginHour:
            now.getHours(),

        dayOfWeek:
            now.getDay(),

        // Context
        hasPreviousContext:
            context.hasPreviousContext ??
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

            challengeResponseTime:
            payload.challengeResponseTime,

            authenticationMethodChanged:
            payload.authenticationMethodChanged,

            ipChanged:
            payload.ipChanged,

            regionChanged:
            payload.regionChanged,

            userAgentChanged:
            payload.userAgentChanged,

            isNewDevice:
            payload.isNewDevice,

            signCountAbnormal:
            payload.signCountAbnormal,

            credentialMismatch:
            payload.credentialMismatch,

            consecutiveFailureCount:
            payload.consecutiveFailureCount,

            blacklistIpDetected:
            payload.blacklistIpDetected,

            loginHour:
            payload.loginHour,

            dayOfWeek:
            payload.dayOfWeek,

            hasPreviousContext:
            payload.hasPreviousContext,
        }
    );


    try {
        const response =
            await axios.post(
                process.env.RISK_API_URL ||
                "http://python:8000/analyze",

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
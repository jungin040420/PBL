const { redisClient } = require('../../config/db');
const { sendRiskData } = require('../services/riskService');
const {
  hashUserId,
  hashForCompare
} = require('../utils/anonymize');

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

    // 1. Existing login/history state
    const failedLoginCount =
      parseInt(
        await redisClient.get(`login:fail:${username}`),
        10
      ) || 0;

    context.failedLoginCount = failedLoginCount;
    context.consecutiveFailureCount = failedLoginCount;

    // No new Passkey challenge has occurred yet.
    context.challengeResponseTime = null;

    // Accessing the setting does not mean the method changed.
    context.authenticationMethodChanged = false;

    // No credential verification has occurred in this request.
    context.signCountAbnormal = false;
    context.credentialMismatch = false;

    // 2. Blacklist check
    const currentIpHash =
      hashForCompare(context.ip || '');

    const blacklistStatus =
      await redisClient.get(
        `blacklist:ip:${currentIpHash}`
      );

    context.blacklistIpDetected =
      blacklistStatus === '1';

    // 3. Compare with previous context
    const userIdHash =
      hashUserId(username);

    const contextKey =
      `lastcontext:${userIdHash}`;

    const previousContext =
      await redisClient.hGetAll(contextKey);

    const currentDeviceHash =
      hashForCompare(
        JSON.stringify(context.deviceInfo || {})
      );

    const currentUaHash =
      hashForCompare(context.userAgent || '');

    const currentCountryHash =
      hashForCompare(context.country || 'KR');

    context.hasPreviousContext =
      Object.keys(previousContext).length > 0;

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

    console.log('[CASE3][SENSITIVE_ACTION]', {
      username,
      action: 'AUTH_METHOD_CHANGE',
      hasPreviousContext: context.hasPreviousContext,
      deviceChanged: context.deviceChanged,
      ipChanged: context.ipChanged,
      userAgentChanged: context.userAgentChanged,
      locationChanged: context.locationChanged
    });

    // 4. Existing REAL ML + Risk Engine
    const riskResult =
      await sendRiskData(username, context);

    const baseRiskAction =
      String(riskResult.action || 'ACTIVE').toUpperCase();

    const baseRiskLevel =
      String(riskResult.level || 'LOW').toUpperCase();

    // Existing BLOCKED decision wins.
    // Otherwise this sensitive operation requires step-up Passkey auth.
    const finalAction =
      baseRiskAction === 'BLOCKED'
        ? 'BLOCKED'
        : 'RE_AUTH';

    console.log('[CASE3][RISK_RE_EVALUATION]', {
      sensitiveAction: 'AUTH_METHOD_CHANGE',
      baseRiskScore: riskResult.score,
      baseRiskLevel,
      baseRiskAction,
      finalAction,
      mlModelUsed: riskResult.mlModelUsed,
      mlModelType: riskResult.mlModelType,
      mlAnomalyScore: riskResult.mlAnomalyScore,
      mlIsAnomaly: riskResult.mlIsAnomaly
    });

    if (finalAction === 'BLOCKED') {
      return res.status(403).json({
        success: false,
        sensitiveAction: 'AUTH_METHOD_CHANGE',
        riskReevaluated: true,
        riskScore: riskResult.score,
        riskLevel: baseRiskLevel,
        baseRiskAction,
        finalAction: 'BLOCKED',
        requiresReauthentication: false,
        message: 'Sensitive action blocked due to high risk.',
        triggers: riskResult.triggers || [],
        featureScores: riskResult.featureScores || {},
        ml: {
          modelUsed: riskResult.mlModelUsed,
          modelType: riskResult.mlModelType,
          anomalyScore: riskResult.mlAnomalyScore,
          isAnomaly: riskResult.mlIsAnomaly
        }
      });
    }

    return res.status(200).json({
      success: false,
      sensitiveAction: 'AUTH_METHOD_CHANGE',
      riskReevaluated: true,
      riskScore: riskResult.score,
      riskLevel: baseRiskLevel,
      baseRiskAction,
      finalAction: 'RE_AUTH',
      requiresReauthentication: true,
      message:
        'Additional Passkey authentication is required before this sensitive action.',
      triggers: riskResult.triggers || [],
      featureScores: riskResult.featureScores || {},
      ml: {
        modelUsed: riskResult.mlModelUsed,
        modelType: riskResult.mlModelType,
        anomalyScore: riskResult.mlAnomalyScore,
        isAnomaly: riskResult.mlIsAnomaly
      }
    });

  } catch (error) {
    console.error('[CASE3][ERROR]', error);

    return res.status(500).json({
      success: false,
      error: 'RISK_RE_EVALUATION_FAILED',
      message: error.message
    });
  }
};

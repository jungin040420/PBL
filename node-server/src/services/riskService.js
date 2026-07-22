const axios = require('axios');

const sendRiskData = async (username, context) => {
  const now = new Date();

  const payload = {
    user_id: username,                              // ← username → user_id
    ip: context.ip,
    deviceType: context.deviceInfo?.deviceType || 'unknown',
    country: context.country || 'KR',
    login_frequency: context.loginFrequency || 0,   // ← loginFrequency
    login_failures: context.failedLoginCount || 0,  // ← failedLoginCount
    ip_changed: context.ipChanged || false,          // ← ipChanged
    user_agent_changed: context.userAgentChanged || false,
    is_new_device: context.deviceChanged || false,   // ← deviceChanged
    location_changed: context.locationChanged || false,
    challenge_response_time: context.challengeResponseTime || null,
    login_hour: now.getHours(),                     // ← loginHour
    day_of_week: now.getDay(),                      // ← dayOfWeek
  };

  console.log('리스크 파트로 전달할 데이터:', payload);

  const response = await axios.post(
    process.env.RISK_API_URL || 'http://localhost:5000/risk', // ← /risk
    payload
  );

  return {
    score: response.data.risk_score,              // ← score → risk_score
    level: response.data.risk_level,              // ← level → risk_level
    action: response.data.authentication_action,  // ← action
  };
};

module.exports = { sendRiskData };
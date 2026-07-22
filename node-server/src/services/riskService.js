const axios = require('axios');

const sendRiskData = async (username, context) => {
  const now = new Date();

  const payload = {
    username: username,                                    // ← user_id → username
    ip: context.ip || '0.0.0.0',
    deviceType: context.deviceInfo?.deviceType || 'unknown', // ← 필수값
    country: context.country || 'KR',
    loginFrequency: context.loginFrequency || 0,
    failedLoginCount: context.failedLoginCount || 0,
    ipChanged: context.ipChanged || false,
    user_agent_changed: context.userAgentChanged || false,
    is_new_device: context.deviceChanged || false,
    location_changed: context.locationChanged || false,
    challenge_response_time: context.challengeResponseTime || null,
    login_hour: now.getHours(),
    day_of_week: now.getDay(),
  };

  console.log('리스크 파트로 전달할 데이터:', payload);

  try {
  const response = await axios.post(
    process.env.RISK_API_URL || 'http://localhost:5000/analyze',
    payload
  );

  return {
    score: response.data.risk_score,
    level: response.data.risk_level,
    action: response.data.authentication_action,
  };
}catch (error) {
    console.error('422 상세 오류:', JSON.stringify(error.response?.data, null, 2)); // ← 추가
    throw error;
  }
};

module.exports = { sendRiskData };
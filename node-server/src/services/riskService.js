const axios = require('axios');

// 데이터 전달
const sendRiskData = async (username, context) => {
  const payload = {
    user_id,
    ip: context.ip,
    userAgent: context.userAgent,
    deviceType: context.deviceInfo?.deviceType,
    os: context.deviceInfo?.os,
    accessTime: context.accessTime,
    isNightAccess: context.isNightAccess,
    loginFrequency: context.loginFrequency,
    failedLoginCount: context.failedLoginCount,
    ipChanged: context.ipChanged,
    userAgentChanged: context.userAgentChanged,
    deviceChanged: context.deviceChanged,
    challengeResponseTime: context.challengeResponseTime,
    country: context.country,                
    locationChanged: context.locationChanged, 
    loginHour: context.loginHour,             
    dayOfWeek: context.dayOfWeek
  };

  console.log('리스크 파트로 전달할 데이터:', payload);

  console.log('요청 보낼 주소:', process.env.RISK_API_URL || 'http://localhost:5000/analyze');
  
  // API 엔드포인트 확인
  const response = await axios.post(
    process.env.RISK_API_URL || 'http://localhost:5000/analyze',
    payload
  );

  return {
    score: response.data.score,
    level: response.data.level,
  };
};

module.exports = { sendRiskData };
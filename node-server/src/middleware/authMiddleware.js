const requestIp = require('request-ip');
const sessionManager = require('../services/sessionManager');

module.exports = async (req, res, next) => {
  try {
    const sessionToken = req.cookies.session;

    if (!sessionToken) {
      return res.status(401).json({ error: '로그인이 필요합니다' });
    }

    const context = req.context || {};
    const currentIp = context.ip;
    const currentUserAgent = req.headers['user-agent'] || 'unknown';

    const result = await sessionManager.verifySession(sessionToken, currentIp, currentUserAgent);

    if (!result.valid) {
      res.clearCookie('session');
      if (result.reason === 'SESSION_HIJACK_SUSPECTED') {
        return res.status(401).json({ error: '비정상적인 접근이 감지되어 로그아웃되었습니다' });
      }
      if (result.reason === 'SESSION_NOT_ACTIVE') {
        return res.status(401).json({ error: '추가 인증을 완료해주세요', reason: 'SESSION_NOT_ACTIVE' });
      }
      return res.status(401).json({ error: '세션이 만료됐습니다' });
    }

    req.username = result.username;
    next();

  } catch (error) {
    console.error('세션 검증 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};
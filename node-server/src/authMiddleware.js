const sessionManager = require('./services/sessionManager');

module.exports = async (req, res, next) => {
  try {
    const sessionToken = req.cookies.session;

    if (!sessionToken) {
      return res.status(401).json({ error: '로그인이 필요합니다' });
    }

    const result = await sessionManager.verifySession(sessionToken);

    if (!result.valid) {
      return res.status(401).json({ error: '세션이 만료됐습니다' });
    }

    req.username = result.username;
    next();

  } catch (error) {
    console.error('세션 검증 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};
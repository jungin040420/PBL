const webauthnService = require('../services/webauthnService');
const verificationService = require('../services/verificationService');
const sessionManager = require('../services/sessionManager');
const crypto = require('crypto');
const axios = require('axios');
function hashData(data) {
  return crypto
    .createHash('sha256')
    .update(String(data))
    .digest('hex');
}

function calculateRiskScore(ip, userAgent, time) {
  let score = 0;

  if (
    ip.includes('127.0.0.1') ||
    ip.includes('::1') ||
    ip.includes('172.') ||
    ip.includes('192.168')
  ) {
    score += 10;
  } else {
    score += 30;
  }

  const hour = time.getHours();

  if (hour >= 0 && hour < 6) {
    score += 30;
  } else if (hour >= 22) {
    score += 20;
  } else {
    score += 5;
  }

  if (userAgent.includes('Windows')) {
    score += 5;
  } else if (userAgent.includes('Mobile')) {
    score += 15;
  } else {
    score += 20;
  }

  return score;
}

function calculateRiskLevel(score) {
  if (score < 30) return 'LOW';
  if (score < 60) return 'MEDIUM';
  return 'HIGH';
}

async function sendLog(log) {
  try {
    await axios.post(
      'http://elasticsearch:9200/auth-logs/_doc',
      log
    );
    console.log('로그 전송 성공');
  } catch (e) {
    console.error('로그 전송 실패', e.message);
  }
}
// 등록 - 1단계: challenge 생성
exports.registerStart = async (req, res) => {
  try {
    const { username, displayName, email } = req.body;


    // **추후 코드 수정**
    //   - username 중복 체크
    //   - 이메일 형식 검증
    //   - 특수문자 제한 등
    if (!username || !displayName) {
      return res.status(400).json({ error: '필수 입력값 누락' });
    }

    const options = await webauthnService.generateRegistrationOptions(
      username,
      displayName
    );

    return res.status(200).json(options);

  } catch (error) {

    // **추후 코드 수정**
    //   - 에러 종류별 메시지 분리
    //   - 실제 에러는 서버 로그에만 기록
    console.error('registerStart 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


// 등록 - 서명 검증 및 공개키 저장

exports.registerFinish = async (req, res) => {
  try {
    const { username, email, challengeId, credential } = req.body;
    console.log('challengeId:', challengeId);
    // verificationService에서 서명 검증 및 DB 저장
    const result = await verificationService.verifyRegistration(
      username,
      email,
      challengeId,
      credential
    );

    if (!result.verified) {
      return res.status(400).json({ error: '등록 검증 실패' });
    }

    // ** 추후 코드 수정**
    //   - 등록 완료 후 바로 로그인 처리할지 여부
    //   - 등록 완료 이메일 발송 여부
    //   - 등록 기기 이름 저장 여부 (예: "내 아이폰")
    return res.status(200).json({ success: true, message: '등록 완료' });

  } catch (error) {
    console.error('registerFinish 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


// challenge 생성
exports.loginStart = async (req, res) => {
  try {
    const { username } = req.body;

    // **추후 코드 수정
    //   - 유저 존재 여부를 에러로 노출하면 계정 열거 공격에 취약
    //   - 존재하지 않아도 동일한 응답 시간 유지 필요 (타이밍 공격 방지)
    if (!username) {
      return res.status(400).json({ error: '아이디를 입력하세요' });
    }

    const options = await webauthnService.generateLoginOptions(username);

    return res.status(200).json(options);

  } catch (error) {
    console.error('loginStart 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


//서명 검증 및 세션 발급
exports.loginFinish = async (req, res) => {
  try {
    const { username, challengeId, credential } = req.body;
    console.log('challengeId:', challengeId);

    const context = req.context || {};
    console.log('로그인 콘텍스트: ', context);

    const result = await verificationService.verifyLogin(
      username,
      challengeId,
      credential
    );

    if (!result.verified) {
      return res.status(401).json({ error: '로그인 검증 실패' });
    }

    // **추후 코드 수정**
    //   - 리스크 점수 높으면 추가 인증 요구 (Step-up MFA)
    //   - JWT vs 서버 세션 방식 결정
    //   - 세션 만료 시간 설정
    //   - 로그인 성공 기록 저장 (대시보드 연동용)
    const session = await sessionManager.createSession(
      username, context.ip, context.userAgent
    );

    // **추후 코드 수정**
    //   - httpOnly, secure, sameSite 옵션 설정
    //   - HTTPS 환경에서는 secure: true 필수
        const ip = req.ip;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const time = new Date();

    const riskScore = calculateRiskScore(ip, userAgent, time);
    const riskLevel = calculateRiskLevel(riskScore);

    await sendLog({
      timestamp: time,
      expire_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
      user_id: hashData(username),
      event_type: 'real_login_attempt',
      ip_address: hashData(ip),
      user_agent: userAgent,
      risk_score: riskScore,
      risk_level: riskLevel,
      risk_reason: 'IP, 시간대, 기기 정보 기반 위험도 산출'
    });
    res.cookie('session', session.token, {
      httpOnly: true,   // JS에서 접근 불가
      secure: false,    //운영환경에서는 반드시 true로 변경
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60, // 1시간
    });

    return res.status(200).json({ success: true, message: '로그인 성공', 
      context: {
        deviceType: context.deviceInfo?.deviceType,
        os: context.deviceInfo?.os,
        isNightAccess: context.isNightAccess
      }
    });

  } catch (error) {
    console.error('loginFinish 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};

//logout
exports.logout = async (req, res) => {
  try {
    const sessionToken = req.cookies.session;
    if (sessionToken) {
      await sessionManager.deleteSession(sessionToken);
    }
    res.clearCookie('session');
    return res.status(200).json({ success: true, message: '로그아웃 완료' });
  } catch (error) {
    console.error('logout 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};


exports.verifySession = async (req, res) => {
  try {
    const sessionToken = req.cookies.session;
    if (!sessionToken) {
      return res.status(401).json({ error: '토큰 없음' });
    }

    const result = await sessionManager.verifySession(sessionToken);
    if (!result.valid) {
      return res.status(401).json({ error: result.reason || '세션 만료' });
    }

    return res.status(200).json({ success: true, username: result.username });
  } catch (error) {
    console.error('verifySession 오류:', error);
    return res.status(500).json({ error: '서버 오류' });
  }
};
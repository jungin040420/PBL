const webauthnService = require('../services/webauthnService');
const verificationService = require('../services/verificationService');
const sessionManager = require('../services/sessionManager');
const crypto = require('crypto');
const axios = require('axios');
const {sendRiskData} = require('../services/riskService');
const { redisClient } = require('../../config/db');
const { db } = require('../../config/db');

console.log('sendRiskData 타입:', typeof sendRiskData);

// function hashData(data) {
//   return crypto
//     .createHash('sha256')
//     .update(String(data))
//     .digest('hex');
// }

// function calculateRiskScore(ip, userAgent, time) {
//   let score = 0;

//   if (
//     ip.includes('127.0.0.1') ||
//     ip.includes('::1') ||
//     ip.includes('172.') ||
//     ip.includes('192.168')
//   ) {
//     score += 10;
//   } else {
//     score += 30;
//   }

//   const hour = time.getHours();

//   if (hour >= 0 && hour < 6) {
//     score += 30;
//   } else if (hour >= 22) {
//     score += 20;
//   } else {
//     score += 5;
//   }

//   if (userAgent.includes('Windows')) {
//     score += 5;
//   } else if (userAgent.includes('Mobile')) {
//     score += 15;
//   } else {
//     score += 20;
//   }

//   return score;
// }

// function calculateRiskLevel(score) {
//   if (score < 30) return 'LOW';
//   if (score < 60) return 'MEDIUM';
//   return 'HIGH';
// }

// async function sendLog(log) {
//   try {
//     await axios.post(
//       'http://elasticsearch:9200/auth-logs/_doc',
//       log
//     );
//     console.log('로그 전송 성공');
//   } catch (e) {
//     console.error('로그 전송 실패', e.message);
//   }
// }

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
      username, displayName
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

    // loginStart에서 시작 시간 저장
    await redisClient.set(
      `challenge:time:${username}`,
      Date.now(),
      { EX: 300 }
    );

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
    const context = req.context || {};

    // loginFinish에서 시간 차이 계산
    const startTime = await redisClient.get(`challenge:time:${username}`);
    const challengeResponseTime = startTime?Date.now() - parseInt(startTime): null;

    context.challengeResponseTime = challengeResponseTime;
    await redisClient.del(`challenge:time:${username}`);

    const result = await verificationService.verifyLogin(
      username,
      challengeId,
      credential
    );

    console.log('verifyLogin 결과:', result);

    // 로그인 실패 시
    if (!result.verified) {
      await redisClient.incr(`login:fail:${username}`);
      await redisClient.expire(`login:fail:${username}`, 3600);
      return res.status(401).json({ error: '로그인 검증 실패' });
    }

    //실패 횟수 조회
    const failedLoginCount = parseInt(
      await redisClient.get(`login:fail:${username}`)
    ) || 0;
    context.failedLoginCount = failedLoginCount;
    await redisClient.del(`login:fail:${username}`);

    // 기기 변경 여부 확인
    const [rows] = await db.query(
    'SELECT last_device, last_ip, last_user_agent, last_country FROM users WHERE username = ?',
    [username]
    );
    
    context.deviceChanged = rows[0]?.last_device !== context.userAgent;
    context.ipChanged = rows[0]?.last_ip !== context.ip;
    context.userAgentChanged = rows[0]?.last_user_agent !== context.userAgent;
    context.locationChanged = rows[0]?.last_country !== context.country;

    const deviceChanged = rows[0]?.last_device !== context.userAgent;
    context.deviceChanged = deviceChanged;

    // 현재 기기 정보 업데이트
    await db.query(
    'UPDATE users SET last_device = ?, last_ip = ?, last_user_agent=?, last_country = ? WHERE username = ?',
    [context.userAgent, context.ip, context.userAgent, context.country, username]
    );

    //로그인 빈도
    const loginFrequency = await redisClient.incr(`login:count:${username}`);
    await redisClient.expire(`login:count:${username}`, 3600);
    context.loginFrequency = loginFrequency;

    context.loginFrequency = loginFrequency;

    let riskScore = 0;
    let riskLevel = 'Low';
    let riskAction = 'ACTIVE';

    try {
      const riskResult = await sendRiskData(username, context);
      riskScore = riskResult.score;
      riskLevel = riskResult.level;
       riskAction = riskResult.action;
      console.log('리스크 스코어:', riskScore, riskLevel);
    } catch (error) {
      console.error('리스크 스코어 요청 실패:', error.message);
      console.error(error.stack);
    }

    // **추후 코드 수정**
    //   - 리스크 점수 높으면 추가 인증 요구 (Step-up MFA)
    //   - JWT vs 서버 세션 방식 결정
    //   - 세션 만료 시간 설정
    //   - 로그인 성공 기록 저장 (대시보드 연동용)
    const session = await sessionManager.createSession(
      username, context.ip, context.userAgent
    );
    console.log('세션 생성 결과:', session);

    // **추후 코드 수정**
    //   - httpOnly, secure, sameSite 옵션 설정
    //   - HTTPS 환경에서는 secure: true 필수
    const ip = req.ip;
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const time = new Date();

    // await sendLog({
    //   timestamp: time,
    //   expire_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
    //   user_id: hashData(username),
    //   event_type: 'real_login_attempt',
    //   ip_address: hashData(ip),
    //   user_agent: userAgent,
    //   risk_score: riskScore,
    //   risk_level: riskLevel,
    //   risk_reason: 'IP, 시간대, 기기 정보 기반 위험도 산출'
    // });

    const isNgrok = req.headers.host?.includes('ngrok');

    res.cookie('session', session.token, {
      httpOnly: true,   // JS에서 접근 불가
      secure: isNgrok ? true : false,    //운영환경에서는 반드시 true로 변경
      sameSite: isNgrok ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60, // 1시간
    });

    return res.status(200).json({ success: true, message: '로그인 성공', 
      context: {
        deviceType: context.deviceInfo?.deviceType,
        os: context.deviceInfo?.os,
        isNightAccess: context.isNightAccess
      },
      riskScore,
      riskLevel,
      riskAction: riskAction
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
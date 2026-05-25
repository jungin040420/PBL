const crypto = require('crypto');
const express = require('express');
const axios = require('axios');

const app = express();

app.use(express.json());

// SHA-256 해싱 함수
function hashData(data) {
  return crypto
    .createHash('sha256')
    .update(String(data))
    .digest('hex');
}

// 위험도 점수 계산 함수
function calculateRiskScore(ip, userAgent, time) {
  let score = 0;

  // 1. IP 기반 점수
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

  // 2. 시간대 기반 점수
  const hour = time.getHours();

  if (hour >= 0 && hour < 6) {
    score += 30;
  } else if (hour >= 22) {
    score += 20;
  } else {
    score += 5;
  }

  // 3. 기기 정보 기반 점수
  if (userAgent.includes('Windows')) {
    score += 5;
  } else if (userAgent.includes('Mobile')) {
    score += 15;
  } else {
    score += 20;
  }

  return score;
}

// 위험도 등급 계산 함수
function calculateRiskLevel(score) {
  if (score < 30) {
    return 'LOW';
  } else if (score < 60) {
    return 'MEDIUM';
  } else {
    return 'HIGH';
  }
}

// Elasticsearch 로그 전송 함수
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

// 기본 서버 확인 + 테스트 로그 생성
app.get('/', async (req, res) => {
  const time = new Date();
  const ip = '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown';

  const riskScore = calculateRiskScore(ip, userAgent, time);
  const riskLevel = calculateRiskLevel(riskScore);

  await sendLog({
    timestamp: time,
    expire_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
    user_id: hashData('test_user'),
    event_type: 'login_test',
    ip_address: hashData(ip),
    user_agent: userAgent,
    risk_score: riskScore,
    risk_level: riskLevel,
    risk_reason: 'IP, 시간대, 기기 정보 기반 테스트 로그'
  });

  res.json({
    status: 'Node.js 서버 실행중'
  });
});

// 실제 로그인 요청 로그 저장 API
app.post('/login', async (req, res) => {
  const ip = req.ip;
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const time = new Date();

  const riskScore = calculateRiskScore(ip, userAgent, time);
  const riskLevel = calculateRiskLevel(riskScore);

  const logData = {
    timestamp: time,
    expire_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
    user_id: hashData('real_user'),
    event_type: 'real_login_attempt',
    ip_address: hashData(ip),
    user_agent: userAgent,
    risk_score: riskScore,
    risk_level: riskLevel,
    risk_reason: 'IP, 시간대, 기기 정보 기반 위험도 산출'
  };

  console.log('로그인 요청:', logData);

  await sendLog(logData);

  res.json({
    message: '로그인 로그 저장 완료',
    logData
  });
});

// 서버 실행
app.listen(3000, () => {
  console.log('서버 실행중 → http://localhost:3000');
});
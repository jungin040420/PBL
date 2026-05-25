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
  await sendLog({
    timestamp: new Date(),
    expire_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
    user_id: hashData('test_user'),
    event_type: 'login_test',
    ip_address: hashData('127.0.0.1'),
    risk_score: 10,
    risk_level: 'LOW'
  });

  res.json({
    status: 'Node.js 서버 실행중'
  });
});

// 실제 로그인 요청 로그 저장 API
app.post('/login', async (req, res) => {
  const ip = req.ip;
  const ua = req.headers['user-agent'];
  const time = new Date();

  // 위험 점수 계산
  let riskScore = 70;

  if (
    ip.includes('127.0.0.1') ||
    ip.includes('172.') ||
    ip.includes('192.168')
  ) {
    riskScore = 10;
  }

  // 위험도 분류
  let riskLevel = 'HIGH';

  if (riskScore <= 30) {
    riskLevel = 'LOW';
  } else if (riskScore <= 70) {
    riskLevel = 'MEDIUM';
  }

  const logData = {
    timestamp: time,
    expire_at: new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)),
    user_id: hashData('real_user'),
    event_type: 'real_login_attempt',
    ip_address: hashData(ip),
    user_agent: ua,
    risk_score: riskScore,
    risk_level: riskLevel
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
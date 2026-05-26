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

  // IP 기반
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

  // 시간 기반
  const hour = time.getHours();

  if (hour >= 0 && hour < 6) {
    score += 30;
  } else if (hour >= 22) {
    score += 20;
  } else {
    score += 5;
  }

  // 기기 기반
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


const express = require('express');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const authMiddleware = require('../src/authMiddleware');

const app = express();
app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 10,           
  message: { error: '너무 많은 요청입니다. 잠시 후 시도해주세요.' }
});

app.use(express.static(path.join(__dirname, '../../client')));

app.get('/', (req, res) => {
  res.json({ status: 'Node.js 서버 실행중' });
});

// 라우터 연결
app.use('/auth', authLimiter)
app.use('/auth', require('../routes/authRoutes'));
/* // 로그인 필요한 라우트에만 적용
// 예: 대시보드, 마이페이지 등
app.use('/api/dashboard', authMiddleware, require('../routes/dashboardRoutes')); */
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ message: '세션 유효', username: req.username });
});
module.exports = app;
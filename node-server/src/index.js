<<<<<<< HEAD
//테스트용
const path = require('path');
const dotenv = require('dotenv');
dotenv.config({ 
  path: path.join(__dirname, '../../.env.dev')
});
=======
const crypto = require('crypto');
const express = require('express');
const axios = require('axios');

const app = express();
>>>>>>> feature/loginpage

console.log('RP_ID:', process.env.RP_ID);
console.log('ORIGIN:', process.env.ORIGIN);

const app = require('./app');

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});

/* const express = require('express');
const mysql = require('mysql2/promise');
const Redis = require('ioredis');
const axios = require('axios');

const app = express();
app.use(express.json());

<<<<<<< HEAD
// Redis 연결
const redis = new Redis({
    host: process.env.REDIS_HOST || 'redis',
    port: process.env.REDIS_PORT || 6379
});

// MySQL 연결
const db = mysql.createPool({
    host: process.env.MYSQL_HOST || 'mysql',
    port: process.env.MYSQL_PORT || 3306,
    user: process.env.MYSQL_USER || 'authuser',
    password: process.env.MYSQL_PASSWORD || 'authpass',
    database: process.env.MYSQL_DATABASE || 'authdb'
});

app.get('/', (req, res) => {
    res.json({ status: 'Node.js 서버 실행중' });
});

// F-22 멀티 소스 로그 수집
app.post('/login', async (req, res) => {
    const ip = req.ip;
    const ua = req.headers['user-agent'];
    const time = new Date();
    const userId = req.body.user_id || 'unknown';

    try {
        // 1. Redis에 임시 저장 (10분)
        await redis.setex(
            `login:${userId}`,
            600,
            JSON.stringify({ ip, ua, time })
        );

        // 2. Python 리스크 점수 계산
        const riskResponse = await axios.post(
            `${process.env.PYTHON_RISK_URL || 'http://python-risk:8000'}/risk`,
            {
                user_id: userId,
                ip: ip,
                device: ua,
                country: 'KR',
                login_failures: 0,
                is_phishing_url: false,
                is_new_device: true
            }
        );
        const riskData = riskResponse.data;

        // 3. MySQL에 영구 저장
        await db.execute(
            `INSERT INTO access_logs 
            (user_id, ip, device, user_agent, auth_result) 
            VALUES (?, ?, ?, ?, ?)`,
            [userId, ip, ua, ua, 'success']
        );

        // 4. 리스크 점수 MySQL에 저장
        await db.execute(
            `INSERT INTO risk_scores 
            (user_id, ip, device, score, reason) 
            VALUES (?, ?, ?, ?, ?)`,
            [userId, ip, ua, riskData.score,
             JSON.stringify(riskData.triggers)]
        );

        res.json({
            message: '로그인 시도 기록됨',
            ip,
            device: ua,
            time,
            risk: riskData
        });

    } catch (error) {
        console.error('오류:', error.message);
        res.status(500).json({ error: '서버 오류' });
    }
});

// F-23 로그 중앙 집중화
app.post('/logs', async (req, res) => {
    const { source, level, message, meta } = req.body;

    try {
        // MySQL에 영구 저장
        await db.execute(
            `INSERT INTO unified_logs 
            (source, level, message, meta) 
            VALUES (?, ?, ?, ?)`,
            [
                source || 'unknown',
                level || 'info',
                message || '',
                JSON.stringify(meta || {})
            ]
        );

        // Redis에 최근 로그 저장 (1시간)
        await redis.setex(
            `log:${source}:${Date.now()}`,
            3600,
            JSON.stringify({ source, level, message, meta })
        );

        res.json({
            status: '로그 저장 완료',
            source,
            level,
            message
        });

    } catch (error) {
        console.error('로그 저장 오류:', error.message);
        res.status(500).json({ error: '로그 저장 실패' });
    }
=======
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
>>>>>>> feature/loginpage
});

// 서버 실행
app.listen(3000, () => {
<<<<<<< HEAD
    console.log('서버 실행중 → http://localhost:3000');
}); */
=======
  console.log('서버 실행중 → http://localhost:3000');
});
>>>>>>> feature/loginpage

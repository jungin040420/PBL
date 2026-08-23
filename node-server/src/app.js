const express = require('express');
const cors = require('cors');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const authMiddleware = require('../src/middleware/authMiddleware');

const app = express();

app.set('trust proxy', 1);

app.use(cors());
app.use(express.json());
app.use(cookieParser());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    error: '너무 많은 요청입니다. 잠시 후 시도해주세요.'
  }
});

const clientPath = process.env.CLIENT_PATH || path.join(__dirname, '../../client');

console.log('__dirname:', __dirname);
console.log('client 경로:', clientPath);

app.use(express.static(clientPath));

// 기본 페이지
app.get('/', (req, res) => {
  res.sendFile(path.join(clientPath, 'login.html'));
});

// 로그인 페이지
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(clientPath, 'login.html'));
});

// 회원가입 페이지
app.get('/register.html', (req, res) => {
  res.sendFile(path.join(clientPath, 'register.html'));
});

// 인증 Rate Limit
app.use('/auth', authLimiter);

// 인증 라우터
app.use(
    '/auth',
    require('../routes/authRoutes')
);

// CASE 3 - 인증 성공 후 민감 행위 Risk Re-evaluation
app.use(
    '/api/sensitive',
    require('../routes/sensitiveActionRoutes')
);

// 세션 확인
app.get(
    '/api/me',
    authMiddleware,
    (req, res) => {
      res.json({
        message: '세션 유효',
        username: req.username
      });
    }
);

module.exports = app;
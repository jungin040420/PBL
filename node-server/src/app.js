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
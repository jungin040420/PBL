const express = require('express');
const cors = require('cors');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

console.log('__dirname:', __dirname);
console.log('client 경로:', path.join(__dirname, '../../client'));

// 라우터 연결
app.use(express.static(path.join(__dirname, '../../client')));

app.get('/', (req, res) => {
  res.json({ status: 'Node.js 서버 실행중' });
});

app.use('/auth', require('../routes/authRoutes'));

module.exports = app;
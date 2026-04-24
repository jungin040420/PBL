const express = require('express');
const app = express();

app.use(express.json());

app.get('/', (req, res) => {
    res.json({ status: 'Node.js 서버 실행중' });
});

app.post('/login', async (req, res) => {
    const ip = req.ip;
    const ua = req.headers['user-agent'];
    const time = new Date();

    console.log('로그인 요청:', { ip, ua, time });

    res.json({
        message: '로그인 시도 기록됨',
        ip,
        device: ua,
        time
    });
});

app.listen(3000, () => {
    console.log('서버 실행중 → http://localhost:3000');
});
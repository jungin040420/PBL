const express = require('express');
const router = express.Router();

const authController = require('../src/controllers/webauthnController');
const authMiddleware = require('../src/middleware/authMiddleware');
const { collectContext } = require('../src/middleware/contextCollector');

// 진단 로그 추가
console.log('authRoutes.js 실행됨');
router.use((req, res, next) => {
  console.log('요청 들어옴:', req.method, req.path);
  next();
});

router.post('/register/start', authController.registerStart);
router.post('/register/finish', authController.registerFinish);
router.post('/login/start', collectContext, authController.loginStart);
router.post('/login/finish', collectContext, authController.loginFinish);
router.post('/logout', authController.logout);
router.get('/verify', authController.verifySession);
router.get('/verify', authMiddleware, authController.verifySession);


module.exports = router;
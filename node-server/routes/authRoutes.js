const express = require('express');
const router = express.Router();

// 진단 로그 추가
console.log('authRoutes.js 실행됨');
router.use((req, res, next) => {
  console.log('요청 들어옴:', req.method, req.path);
  next();
});
router.post('/logout', authController.logout);

const authController = require('../src/controllers/webauthnController');

console.log('authController:', authController);
console.log('registerStart:', typeof authController.registerStart);
console.log('registerFinish:', typeof authController.registerFinish);
console.log('loginStart:', typeof authController.loginStart);
console.log('loginFinish:', typeof authController.loginFinish);

router.post('/register/start', authController.registerStart);
router.post('/register/finish', authController.registerFinish);
router.post('/login/start', authController.loginStart);
router.post('/login/finish', authController.loginFinish);

module.exports = router;
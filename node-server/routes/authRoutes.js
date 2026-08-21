const express = require('express');
const router = express.Router();

const authController = require('../src/controllers/webauthnController');
const authMiddleware = require('../src/middleware/authMiddleware');
const { collectContext } = require('../src/middleware/contextCollector');

router.post('/register/start', collectContext, authController.registerStart);
router.post('/register/finish', collectContext, authController.registerFinish);
router.post('/login/start', collectContext, authController.loginStart);
router.post('/login/finish', collectContext, authController.loginFinish);
router.post('/logout', authController.logout);
router.get('/verify', authMiddleware, authController.verifySession);


module.exports = router;
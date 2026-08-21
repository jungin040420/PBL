const express = require('express');

const router = express.Router();

const authController = require(
    '../src/controllers/webauthnController'
);

<<<<<<< HEAD
router.post('/register/start', authController.registerStart);
router.post('/register/finish', authController.registerFinish);
router.post('/login/start', collectContext, authController.loginStart);
router.post('/login/finish', collectContext, authController.loginFinish);
router.post('/logout', authController.logout);
router.get('/verify', authController.verifySession);
router.get('/verify', authMiddleware, authController.verifySession);
=======
const authMiddleware = require(
    '../src/middleware/authMiddleware'
);

const {
  collectContext,
} = require(
    '../src/middleware/contextCollector'
);


// ============================================================
// 진단 로그
// ============================================================

console.log(
    'authRoutes.js 실행됨'
);

console.log(
    '라우트 핸들러 확인:',
    {
      registerStart:
          typeof authController.registerStart,

      registerFinish:
          typeof authController.registerFinish,

      loginStart:
          typeof authController.loginStart,

      loginFinish:
          typeof authController.loginFinish,

      logout:
          typeof authController.logout,

      verifySession:
          typeof authController.verifySession,

      collectContext:
          typeof collectContext,

      authMiddleware:
          typeof authMiddleware,
    }
);


router.use(
    (
        req,
        res,
        next
    ) => {

      console.log(
          '요청 들어옴:',
          req.method,
          req.path
      );

      next();
    }
);


// ============================================================
// WebAuthn 등록
// ============================================================

router.post(
    '/register/start',
    authController.registerStart
);


router.post(
    '/register/finish',
    authController.registerFinish
);


// ============================================================
// WebAuthn 로그인
// ============================================================

router.post(
    '/login/start',
    collectContext,
    authController.loginStart
);


router.post(
    '/login/finish',
    collectContext,
    authController.loginFinish
);


// ============================================================
// 로그아웃
// ============================================================

router.post(
    '/logout',
    authController.logout
);


// ============================================================
// 세션 검증
// ============================================================

router.get(
    '/verify',
    authMiddleware,
    authController.verifySession
);
>>>>>>> cea1a248c8bd2d47d83e2ac17bb38af53fc7aff9


module.exports = router;
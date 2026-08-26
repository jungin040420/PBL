const express = require('express');

const router = express.Router();

const authMiddleware =
    require('../src/middleware/authMiddleware');

const {
  collectContext
} = require('../src/middleware/contextCollector');

const sensitiveActionController =
    require('../src/controllers/sensitiveActionController');


// ============================================================
// CASE 3
// 인증수단 변경 요청
//
// 현재 ACTIVE Session 검증
// → Context 수집
// → Risk Re-Evaluation
// → RE_AUTH 또는 BLOCKED
// ============================================================

router.post(
    '/auth-method-change',
    authMiddleware,
    collectContext,
    sensitiveActionController.requestAuthMethodChange
);


// ============================================================
// CASE 3
// RE_AUTH 전용 Context 조회
//
// 주의:
// authMiddleware를 사용하지 않는다.
//
// RE-AUTH 상태에서는 일반 authMiddleware가
// REAUTH_REQUIRED로 차단하기 때문이다.
//
// 대신 Controller 내부에서
// session + reauth PENDING 상태를 직접 검증한다.
// ============================================================

router.get(
    '/reauth-context',
    sensitiveActionController.getReauthContext
);


module.exports = router;
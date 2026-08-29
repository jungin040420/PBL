const express =
    require('express');

const router =
    express.Router();

const authMiddleware =
    require('../src/middleware/authMiddleware');

const {
  collectContext
} =
    require('../src/middleware/contextCollector');

const sensitiveActionController =
    require('../src/controllers/sensitiveActionController');


// ============================================================
// CASE3 민감 행위 요청
//
// 반드시:
// collectContext → authMiddleware
// ============================================================

router.post(
    '/auth-method-change',
    collectContext,
    authMiddleware,
    sensitiveActionController.requestAuthMethodChange
);


// ============================================================
// RE_AUTH Context 조회
//
// RE_AUTH 세션이므로 일반 authMiddleware 사용 안 함.
// Controller가 직접 세션 검증.
// ============================================================

router.get(
    '/reauth-context',
    sensitiveActionController.getReauthContext
);


// ============================================================
// CASE3 Passkey Step-up 검증
//
// 새 Session 생성하지 않음.
// 기존 RE_AUTH Session 복구.
// ============================================================

router.post(
    '/stepup/verify',
    sensitiveActionController.verifyStepUp
);


module.exports =
    router;
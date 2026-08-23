const express = require('express');

const router = express.Router();

const authMiddleware =
  require('../src/middleware/authMiddleware');

const {
  collectContext
} = require('../src/middleware/contextCollector');

const sensitiveActionController =
  require('../src/controllers/sensitiveActionController');

router.post(
  '/auth-method-change',
  authMiddleware,
  collectContext,
  sensitiveActionController.requestAuthMethodChange
);

module.exports = router;

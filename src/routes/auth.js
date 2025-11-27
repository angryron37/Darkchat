const express = require('express');
const rateLimit = require('express-rate-limit');
const AuthController = require('../controllers/AuthController');
const SecurityMiddleware = require('../middleware/security');
const AuthMiddleware = require('../middleware/auth');
const ValidationMiddleware = require('../middleware/validation');

const router = express.Router();
const authController = new AuthController();

// Enhanced rate limiting for authentication routes
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 auth requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});

// Apply auth rate limiting to all auth routes
router.use(authRateLimit);

/**
 * POST /auth/login
 * Create anonymous session for user
 */
router.post('/login',
  AuthMiddleware.deviceFingerprint(),
  AuthMiddleware.sessionCleanup(),
  authController.getValidationMiddleware().validateLogin,
  authController.login.bind(authController)
);

/**
 * POST /auth/logout
 * Destroy user session
 */
router.post('/logout',
  authController.logout.bind(authController)
);

/**
 * GET /auth/me
 * Get current user information
 */
router.get('/me',
  AuthMiddleware.requireAuth(),
  authController.getMe.bind(authController)
);

/**
 * POST /auth/register-device
 * Store device public key
 */
router.post('/register-device',
  AuthMiddleware.requireAuth(),
  AuthMiddleware.deviceFingerprint(),
  authController.getValidationMiddleware().validateRegisterDevice,
  authController.registerDevice.bind(authController)
);

/**
 * GET /auth/devices
 * Get user's registered devices
 */
router.get('/devices',
  AuthMiddleware.requireAuth(),
  authController.getMyDevices.bind(authController)
);

/**
 * POST /auth/revoke-device
 * Revoke a specific device
 */
router.post('/revoke-device',
  AuthMiddleware.requireAuth(),
  authController.getValidationMiddleware().validateRevokeDevice,
  authController.revokeDevice.bind(authController)
);

/**
 * POST /auth/revoke-all-devices
 * Revoke all devices for user
 */
router.post('/revoke-all-devices',
  AuthMiddleware.requireAuth(),
  authController.revokeAllDevices.bind(authController)
);

/**
 * PUT /auth/status
 * Update user status
 */
router.put('/status',
  AuthMiddleware.requireAuth(),
  authController.getValidationMiddleware().validateUpdateStatus,
  authController.updateStatus.bind(authController)
);

/**
 * POST /auth/generate-keys
 * Generate RSA key pair for client-side use
 */
router.post('/generate-keys',
  AuthMiddleware.requireAuth(),
  authController.generateKeyPair.bind(authController)
);

/**
 * GET /auth/stats
 * Get user statistics
 */
router.get('/stats',
  AuthMiddleware.requireAuth(),
  authController.getUserStats.bind(authController)
);

/**
 * GET /auth/export
 * Export user data (privacy compliant)
 */
router.get('/export',
  AuthMiddleware.requireAuth(),
  authController.exportUserData.bind(authController)
);

/**
 * DELETE /auth/account
 * Delete user account
 */
router.delete('/account',
  AuthMiddleware.requireAuth(),
  authController.getValidationMiddleware().validateDeleteAccount,
  authController.deleteAccount.bind(authController)
);

/**
 * GET /auth/session-check
 * Check if session is valid
 */
router.get('/session-check',
  AuthMiddleware.requireAuth(),
  (req, res) => {
    res.status(200).json({
      success: true,
      data: {
        valid: true,
        userId: req.session.userId,
        username: req.session.username,
        deviceFingerprint: req.deviceFingerprint
      }
    });
  }
);

/**
 * POST /auth/refresh-session
 * Refresh session activity timeout
 */
router.post('/refresh-session',
  AuthMiddleware.requireAuth(),
  AuthMiddleware.sessionCleanup(),
  (req, res) => {
    res.status(200).json({
      success: true,
      data: {
        refreshed: true,
        expiresAt: new Date(Date.now() + (24 * 60 * 60 * 1000)).toISOString()
      }
    });
  }
);

/**
 * GET /auth/csrf-token
 * Get CSRF token for forms
 */
router.get('/csrf-token',
  AuthMiddleware.generateCSRF(),
  (req, res) => {
    res.status(200).json({
      success: true,
      data: {
        csrfToken: req.session.csrfToken
      }
    });
  }
);

module.exports = router;
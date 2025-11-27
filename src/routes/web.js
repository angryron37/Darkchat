const express = require('express');
const path = require('path');
const ChatController = require('../controllers/ChatController');
const AuthMiddleware = require('../middleware/auth');
const SecurityMiddleware = require('../middleware/security');
const ValidationMiddleware = require('../middleware/validation');
const config = require('../config/app');

const router = express.Router();
const chatController = new ChatController();

// Apply security middleware to all web routes
router.use(SecurityMiddleware.csrfProtection());
router.use(AuthMiddleware.sessionCleanup());

/**
 * GET /
 * Login page (redirect if authenticated)
 */
router.get('/', (req, res) => {
  if (req.session?.userId) {
    return res.redirect('/chat-list');
  }
  return chatController.loginPage(req, res);
});

/**
 * GET /login
 * Login page
 */
router.get('/login', (req, res) => {
  if (req.session?.userId) {
    return res.redirect('/chat-list');
  }
  return chatController.loginPage(req, res);
});

/**
 * GET /chat-list
 * Contact list page (requires authentication)
 */
router.get('/chat-list',
  AuthMiddleware.requireAuth(),
  chatController.chatListPage.bind(chatController)
);

/**
 * GET /chat/:username
 * Chat room page (requires authentication)
 */
router.get('/chat/:username',
  AuthMiddleware.requireAuth(),
  ValidationMiddleware.validateUsernameParam(),
  ValidationMiddleware.handleValidationErrors(),
  chatController.chatRoomPage.bind(chatController)
);

/**
 * GET /generate-keys
 * Key generation page (requires authentication)
 */
router.get('/generate-keys',
  AuthMiddleware.requireAuth(),
  chatController.generateKeysPage.bind(chatController)
);

/**
 * GET /settings
 * User settings page (requires authentication)
 */
router.get('/settings',
  AuthMiddleware.requireAuth(),
  chatController.settingsPage.bind(chatController)
);

/**
 * GET /privacy
 * Privacy policy page
 */
router.get('/privacy', chatController.privacyPage.bind(chatController));

/**
 * GET /about
 * About page
 */
router.get('/about', chatController.aboutPage.bind(chatController));

/**
 * GET /error
 * Error page (for testing/error handling)
 */
router.get('/error', chatController.errorPage.bind(chatController));

/**
 * Static assets serving
 */
router.use('/static', express.static(
  path.join(__dirname, '../public'),
  {
    maxAge: config.isProduction() ? '1y' : '0',
    etag: true,
    lastModified: true,
    setHeaders: (res, filePath) => {
      // Set security headers for static assets
      if (filePath.endsWith('.js')) {
        res.setHeader('X-Content-Type-Options', 'nosnipp');
      }
    }
  }
));

/**
 * Development routes (only in development mode)
 */
if (config.isDevelopment()) {
  /**
   * GET /dev/tools
   * Development tools page
   */
  router.get('/dev/tools', AuthMiddleware.requireAuth(), async (req, res) => {
    try {
      const databaseConfig = require('../config/database');
      const [messageStats, redisStats] = await Promise.all([
        new (require('../models/Message'))().getSystemStats(),
        new (require('../services/MessageService'))().getRedisStats()
      ]);

      res.render('dev-tools', {
        title: 'DarkChat - Development Tools',
        user: {
          id: req.session.userId,
          username: req.session.username
        },
        stats: {
          messages: messageStats,
          redis: redisStats,
          uptime: process.uptime(),
          memory: process.memoryUsage()
        },
        csrfToken: req.session?.csrfToken || ''
      });
    } catch (error) {
      console.error('Dev tools error:', error);
      res.status(500).render('error', {
        title: 'Development Tools Error',
        message: 'Failed to load development tools',
        error: error.message
      });
    }
  });

  /**
   * POST /dev/cleanup
   * Cleanup development data
   */
  router.post('/dev/cleanup', AuthMiddleware.requireAuth(), async (req, res) => {
    try {
      const { type } = req.body;

      let result = {};
      switch (type) {
        case 'redis':
          result = await new (require('../services/MessageService'))().flushDarkChatKeys();
          break;
        case 'expired-messages':
          result = await new (require('../models/Message'))().markExpiredMessages();
          break;
        default:
          throw new Error('Invalid cleanup type');
      }

      res.json({
        success: true,
        data: result,
        message: `${type} cleanup completed`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });
}

/**
 * Security and monitoring routes
 */

/**
 * GET /security-check
 * Security configuration check (development only)
 */
if (config.isDevelopment()) {
  router.get('/security-check', async (req, res) => {
    try {
      const checks = {
        helmet: true,
        csrf: !!req.session?.csrfToken,
        session: !!req.session?.userId,
        https: req.protocol === 'https',
        headers: {
          'x-content-type-options': res.get('X-Content-Type-Options'),
          'x-frame-options': res.get('X-Frame-Options'),
          'x-xss-protection': res.get('X-XSS-Protection')
        }
      };

      res.json({
        success: true,
        data: checks,
        message: 'Security check completed'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
  });
}

/**
 * Health check endpoint
 */
router.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: config.get('environment')
    }
  });
});

/**
 * Route maintenance endpoints
 */

/**
 * GET /maintenance
 * Maintenance mode page
 */
router.get('/maintenance', (req, res) => {
  res.status(503).render('maintenance', {
    title: 'DarkChat - Under Maintenance',
    message: 'The system is currently under maintenance'
  });
});

/**
 * Error handling for web routes
 */
router.use((error, req, res, next) => {
  console.error('Web route error:', error);

  // Don't send error details in production
  const showError = config.isDevelopment();

  res.status(error.status || 500).render('error', {
    title: 'Server Error',
    message: error.message || 'An unexpected error occurred',
    error: showError ? error.stack : null,
    showHome: true
  });
});

/**
 * 404 handler for web routes
 */
router.use('*', chatController.notFound.bind(chatController));

/**
 * Security headers middleware
 */
router.use((req, res, next) => {
  // Additional security headers for web routes
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Content Security Policy for web pages
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'", // Required for crypto operations
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self' ws: wss:",
    "frame-src 'none'",
    "object-src 'none'",
    "media-src 'self'",
    "manifest-src 'self'"
  ].join('; '));

  next();
});

module.exports = router;
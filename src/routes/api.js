const express = require('express');
const AuthController = require('../controllers/AuthController');
const MessageController = require('../controllers/MessageController');
const ChatController = require('../controllers/ChatController');
const SecurityMiddleware = require('../middleware/security');
const AuthMiddleware = require('../middleware/auth');
const ValidationMiddleware = require('../middleware/validation');

const router = express.Router();

// Initialize controllers
const messageController = new MessageController();
const chatController = new ChatController();

// Apply security middleware to all API routes
router.use(SecurityMiddleware.validateJSONInput());
router.use(AuthMiddleware.sessionCleanup());

/**
 * Authentication required for all API routes except public endpoints
 */
router.use((req, res, next) => {
  // Skip auth for public endpoints
  const publicEndpoints = [
    '/users/active',
    '/users/:username/public-keys',
    '/websocket-config'
  ];

  const isPublic = publicEndpoints.some(endpoint => {
    const regex = new RegExp('^' + endpoint.replace(/:[^/]+/g, '[^/]+') + '$');
    return regex.test(req.path);
  });

  if (isPublic) {
    return next();
  }

  return AuthMiddleware.requireAuth()(req, res, next);
});

/**
 * Message Routes
 */

/**
 * POST /api/messages/send
 * Send encrypted message
 */
router.post('/messages/send',
  SecurityMiddleware.createMessageRateLimiter(),
  AuthMiddleware.requireDeviceKey(),
  messageController.getValidationMiddleware().validateSendMessage,
  messageController.sendMessage.bind(messageController)
);

/**
 * GET /api/messages/:messageId
 * Get encrypted message
 */
router.get('/messages/:messageId',
  messageController.getValidationMiddleware().validateGetMessage,
  messageController.getMessage.bind(messageController)
);

/**
 * DELETE /api/messages/:messageId
 * Delete/destroy message
 */
router.delete('/messages/:messageId',
  messageController.getValidationMiddleware().validateDeleteMessage,
  messageController.deleteMessage.bind(messageController)
);

/**
 * GET /api/messages/inbox
 * Get user's inbox (message metadata)
 */
router.get('/messages/inbox',
  messageController.getValidationMiddleware().validateGetInbox,
  messageController.getInbox.bind(messageController)
);

/**
 * GET /api/messages/conversation/:username
 * Get conversation between two users
 */
router.get('/messages/conversation/:username',
  messageController.getValidationMiddleware().validateGetConversation,
  messageController.getConversation.bind(messageController)
);

/**
 * GET /api/messages/stats
 * Get message statistics
 */
router.get('/messages/stats',
  messageController.getMessageStats.bind(messageController)
);

/**
 * User Routes
 */

/**
 * GET /api/users/active
 * Get active users list
 */
router.get('/users/active',
  ValidationMiddleware.validatePagination(),
  chatController.getActiveUsers.bind(chatController)
);

/**
 * GET /api/users/:username/public-keys
 * Get user's public keys
 */
router.get('/users/:username/public-keys',
  messageController.getValidationMiddleware().validateGetPublicKeys,
  messageController.getUserPublicKeys.bind(messageController)
);

/**
 * WebSocket Configuration
 */

/**
 * GET /api/websocket/config
 * Get WebSocket connection configuration
 */
router.get('/websocket/config',
  chatController.getWebSocketConfig.bind(chatController)
);

/**
 * System Routes
 */

/**
 * GET /api/system/health
 * Health check endpoint
 */
router.get('/system/health',
  async (req, res) => {
    try {
      const databaseConfig = require('../config/database');
      const redisStats = await databaseConfig.getRedis().ping();

      res.status(200).json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          redis: redisStats ? 'connected' : 'disconnected'
        }
      });
    } catch (error) {
      res.status(503).json({
        success: false,
        error: 'Service unhealthy',
        details: error.message
      });
    }
  }
);

/**
 * GET /api/system/stats
 * Get system statistics (admin only)
 */
router.get('/system/stats',
  // TODO: Add admin authentication check
  async (req, res) => {
    try {
      const databaseConfig = require('../config/database');
      const [redisStats, messageStats, userStats] = await Promise.all([
        new (require('../services/MessageService'))().getRedisStats(),
        new (require('../models/Message'))().getSystemStats(),
        new (require('../models/User'))().getTotalUsers()
      ]);

      res.status(200).json({
        success: true,
        data: {
          redis: redisStats,
          messages: messageStats,
          users: {
            total: userStats,
            timestamp: new Date().toISOString()
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Failed to get system stats'
      });
    }
  }
);

/**
 * Error handling for API routes
 */
router.use((error, req, res, next) => {
  console.error('API route error:', error);

  // Handle validation errors
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: error.details
    });
  }

  // Handle rate limiting errors
  if (error.status === 429) {
    return res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      retryAfter: error.retryAfter
    });
  }

  // Handle authentication errors
  if (error.status === 401) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }

  // Handle authorization errors
  if (error.status === 403) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }

  // Handle not found errors
  if (error.status === 404) {
    return res.status(404).json({
      success: false,
      error: 'Resource not found'
    });
  }

  // Handle all other errors
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: error.message })
  });
});

/**
 * 404 handler for API routes
 */
router.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'API endpoint not found',
    path: req.originalUrl
  });
});

module.exports = router;
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('../config/app');
const compression = require('compression');

class SecurityMiddleware {
  constructor() {
    this.config = config;
  }

  // Apply all security middleware
  applySecurity(app) {
    // Compression middleware
    if (this.config.get('performance.compressionEnabled')) {
      app.use(compression());
    }

    // Helmet for security headers
    app.use(helmet(this.config.get('helmet')));

    // CORS configuration
    app.use(cors(this.config.get('cors')));

    // General rate limiting
    app.use(this.createRateLimiter());

    // Custom security headers
    app.use(this.addCustomHeaders());

    // Request logging middleware (privacy-focused)
    if (this.config.isDevelopment()) {
      app.use(this.privacyAwareLogger());
    }

    // Request size limiting
    app.use(this.limitRequestSize());

    // Content type validation
    app.use(this.validateContentType());
  }

  // Create rate limiter with specific configuration
  createRateLimiter() {
    const rateLimitConfig = this.config.get('rateLimit');

    return rateLimit({
      windowMs: rateLimitConfig.windowMs,
      max: rateLimitConfig.max,
      message: rateLimitConfig.message,
      standardHeaders: rateLimitConfig.standardHeaders,
      legacyHeaders: rateLimitConfig.legacyHeaders,
      // Custom key generator for better rate limiting
      keyGenerator: (req) => {
        return req.ip + ':' + (req.session?.userId || 'anonymous');
      },
      // Skip successful requests if configured
      skipSuccessfulRequests: rateLimitConfig.skipSuccessfulRequests,
      // Custom handler for rate limit exceeded
      handler: (req, res) => {
        const isJsonRequest = req.xhr || req.headers.accept === 'application/json';

        if (isJsonRequest) {
          return res.status(429).json({
            success: false,
            error: 'Rate limit exceeded',
            retryAfter: Math.ceil(rateLimitConfig.windowMs / 1000)
          });
        } else {
          res.status(429);
          return res.render('error', {
            error: {
              title: 'Rate Limit Exceeded',
              message: rateLimitConfig.message,
              retryAfter: Math.ceil(rateLimitConfig.windowMs / 1000)
            }
          });
        }
      }
    });
  }

  // Message-specific rate limiting
  createMessageRateLimiter() {
    const config = this.config.get('messageRateLimit');

    return rateLimit({
      windowMs: config.windowMs,
      max: config.max,
      message: config.message,
      keyGenerator: (req) => {
        return req.session?.userId || req.ip;
      },
      handler: (req, res) => {
        return res.status(429).json({
          success: false,
          error: 'Message rate limit exceeded',
          retryAfter: Math.ceil(config.windowMs / 1000)
        });
      }
    });
  }

  // Add custom security headers
  addCustomHeaders() {
    return (req, res, next) => {
      // Additional security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

      // Privacy headers
      res.setHeader('Permissions-Policy',
        'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
      );

      // Cache control for sensitive pages
      if (req.path.includes('/auth/') || req.path.includes('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
      }

      // Service Worker header (disabled for security)
      res.setHeader('Service-Worker-Allowed', '/');

      next();
    };
  }

  // Privacy-aware logger (doesn't log sensitive data)
  privacyAwareLogger() {
    return (req, res, next) => {
      const timestamp = new Date().toISOString();
      const method = req.method;
      const path = req.path;
      const userAgent = req.get('User-Agent') || 'Unknown';

      // Only log non-sensitive information
      console.log(`${timestamp} ${method} ${path} - ${userAgent}`);

      // Don't log request bodies, session data, or IP addresses in production
      if (this.config.isDevelopment()) {
        console.log(`Debug: ${req.method} ${req.path} - Session: ${req.session?.userId ? 'authenticated' : 'anonymous'}`);
      }

      next();
    };
  }

  // Limit request size to prevent DOS attacks
  limitRequestSize() {
    return (req, res, next) => {
      const maxSize = this.config.get('limits.maxMessageLength') * 2; // Allow some overhead

      if (req.get('content-length') && parseInt(req.get('content-length')) > maxSize) {
        return res.status(413).json({
          success: false,
          error: 'Request too large'
        });
      }

      next();
    };
  }

  // Validate content type for API routes
  validateContentType() {
    return (req, res, next) => {
      // Only validate content type for POST/PUT/PATCH requests
      if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.path.startsWith('/api/')) {
        const contentType = req.get('Content-Type');

        if (!contentType || !contentType.includes('application/json')) {
          return res.status(415).json({
            success: false,
            error: 'Unsupported Media Type - JSON required'
          });
        }
      }

      next();
    };
  }

  // WebSocket security middleware
  applySocketSecurity(io) {
    io.use(this.socketAuthMiddleware());
    io.use(this.socketRateLimitMiddleware());
  }

  // Socket authentication middleware
  socketAuthMiddleware() {
    return async (socket, next) => {
      try {
        const session = socket.handshake.session;

        if (!session || !session.userId) {
          return next(new Error('Authentication required'));
        }

        socket.userId = session.userId;
        socket.username = session.username;

        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    };
  }

  // Socket rate limiting middleware
  socketRateLimitMiddleware() {
    const messageCounts = new Map();
    const connectionCounts = new Map();

    return (socket, next) => {
      const userId = socket.userId;

      // Check connection limit per user
      const currentConnections = connectionCounts.get(userId) || 0;
      const maxConnections = this.config.get('connectionLimit.maxConnections');

      if (currentConnections >= maxConnections) {
        return next(new Error('Connection limit exceeded'));
      }

      // Increment connection count
      connectionCounts.set(userId, currentConnections + 1);

      // Clean up on disconnect
      socket.on('disconnect', () => {
        const count = connectionCounts.get(userId) || 0;
        connectionCounts.set(userId, Math.max(0, count - 1));
        messageCounts.delete(userId);
      });

      // Rate limit messages
      socket.onAny((eventName, ...args) => {
        if (eventName === 'message' || eventName === 'send-message') {
          const count = messageCounts.get(userId) || 0;
          const maxMessages = this.config.get('connectionLimit.messageLimit');

          if (count >= maxMessages) {
            socket.emit('rate-limit', {
              error: 'Message rate limit exceeded',
              retryAfter: Math.ceil(this.config.get('connectionLimit.windowMs') / 1000)
            });
            return;
          }

          // Increment and set timeout for cleanup
          messageCounts.set(userId, count + 1);
          setTimeout(() => {
            const current = messageCounts.get(userId) || 0;
            messageCounts.set(userId, Math.max(0, current - 1));
          }, this.config.get('connectionLimit.windowMs'));
        }
      });

      next();
    };
  }

  // Validate origin for WebSocket connections
  validateSocketOrigin(origin) {
    const allowedOrigins = this.config.get('cors.origin');

    if (!origin) return false;

    return allowedOrigins.includes(origin) || allowedOrigins.includes('*');
  }

  // CSRF protection for state-changing requests
  csrfProtection() {
    const tokens = new Map();

    return (req, res, next) => {
      // Only apply CSRF protection to state-changing requests
      if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
      }

      const token = req.get('X-CSRF-Token') || req.body._csrf;
      const sessionToken = req.session?.csrfToken;

      if (!token || !sessionToken || token !== sessionToken) {
        return res.status(403).json({
          success: false,
          error: 'Invalid CSRF token'
        });
      }

      next();
    };
  }

  // Generate CSRF token
  generateCSRFToken() {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
  }
}

module.exports = new SecurityMiddleware();
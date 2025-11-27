const config = require('../config/app');
const { v4: uuidv4 } = require('uuid');

class AuthMiddleware {
  constructor() {
    this.config = config;
  }

  // Session configuration middleware
  sessionMiddleware() {
    const session = require('express-session');
    const RedisStore = require('connect-redis')(session);
    const databaseConfig = require('../config/database');

    const sessionConfig = this.config.get('session');

    // Configure Redis store if Redis is available
    let store;
    try {
      store = new RedisStore({
        client: databaseConfig.getRedis(),
        prefix: 'darkchat:sess:',
        ttl: sessionConfig.cookie.maxAge / 1000 // Convert to seconds
      });
    } catch (error) {
      console.warn('Redis not available for session storage, using memory store');
      store = session.MemoryStore;
    }

    return session({
      ...sessionConfig,
      store,
      name: sessionConfig.name,
      // Enhanced security settings
      resave: sessionConfig.resave,
      saveUninitialized: sessionConfig.saveUninitialized,
      rolling: sessionConfig.rolling,
      // Auto-remove expired sessions
      autoRemove: 'native',
      autoRemoveInterval: 24 * 60 // 24 hours in minutes
    });
  }

  // Check if user is authenticated
  requireAuth() {
    return (req, res, next) => {
      if (!req.session || !req.session.userId) {
        const isJsonRequest = req.xhr || req.headers.accept === 'application/json';

        if (isJsonRequest) {
          return res.status(401).json({
            success: false,
            error: 'Authentication required',
            redirect: '/login'
          });
        } else {
          return res.redirect('/login');
        }
      }

      // Update last activity timestamp
      req.session.lastActivity = Date.now();

      next();
    };
  }

  // Optional authentication - doesn't redirect if not authenticated
  optionalAuth() {
    return (req, res, next) => {
      if (req.session && req.session.userId) {
        req.session.lastActivity = Date.now();
      }
      next();
    };
  }

  // Check if user is the same as the target user (for self-access operations)
  requireSameUser() {
    return (req, res, next) => {
      const targetUserId = req.params.userId || req.params.id;
      const currentUserId = req.session?.userId;

      if (!currentUserId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      if (currentUserId !== targetUserId) {
        return res.status(403).json({
          success: false,
          error: 'Access denied - can only access your own resources'
        });
      }

      next();
    };
  }

  // Device fingerprinting middleware
  deviceFingerprint() {
    return (req, res, next) => {
      if (!req.session) {
        return next();
      }

      // Generate device fingerprint from various request attributes
      const fingerprintData = {
        userAgent: req.get('User-Agent') || '',
        acceptLanguage: req.get('Accept-Language') || '',
        acceptEncoding: req.get('Accept-Encoding') || '',
        ip: req.ip || req.connection.remoteAddress || ''
      };

      // Create hash for device fingerprint
      const crypto = require('crypto');
      const fingerprint = crypto
        .createHash('sha256')
        .update(JSON.stringify(fingerprintData))
        .digest('hex')
        .substring(0, 32);

      // Store or update device fingerprint in session
      if (!req.session.deviceFingerprint) {
        req.session.deviceFingerprint = fingerprint;
        req.session.deviceCreatedAt = Date.now();
      }

      req.deviceFingerprint = fingerprint;

      next();
    };
  }

  // Validate device session
  validateDeviceSession() {
    return async (req, res, next) => {
      if (!req.session?.userId || !req.deviceFingerprint) {
        return next();
      }

      try {
        const databaseConfig = require('../config/database');
        const knex = databaseConfig.getKnex();

        // Check if device session exists and is valid
        const deviceSession = await knex('device_sessions')
          .where({
            user_id: req.session.userId,
            device_fingerprint: req.deviceFingerprint
          })
          .first();

        if (!deviceSession) {
          // Device not registered - force logout
          req.session.destroy((err) => {
            if (err) {
              console.error('Session destroy error:', err);
            }
          });

          const isJsonRequest = req.xhr || req.headers.accept === 'application/json';

          if (isJsonRequest) {
            return res.status(401).json({
              success: false,
              error: 'Device not registered',
              redirect: '/login'
            });
          } else {
            return res.redirect('/login');
          }
        }

        // Update last active timestamp
        await knex('device_sessions')
          .where({ id: deviceSession.id })
          .update({
            last_active: new Date()
          });

        req.deviceSession = deviceSession;

        next();
      } catch (error) {
        console.error('Device validation error:', error);
        next(error);
      }
    };
  }

  // Session cleanup middleware
  sessionCleanup() {
    return async (req, res, next) => {
      // Check for session timeout
      const sessionTimeout = this.config.get('limits.sessionTimeoutHours') * 60 * 60 * 1000;
      const lastActivity = req.session?.lastActivity || req.session?.createdAt;

      if (lastActivity && (Date.now() - lastActivity) > sessionTimeout) {
        // Session expired
        req.session.destroy((err) => {
          if (err) {
            console.error('Session destroy error:', err);
          }
        });

        const isJsonRequest = req.xhr || req.headers.accept === 'application/json';

        if (isJsonRequest) {
          return res.status(401).json({
            success: false,
            error: 'Session expired',
            redirect: '/login'
          });
        } else {
          return res.redirect('/login?expired=true');
        }
      }

      next();
    };
  }

  // Add user info to request object
  loadUser() {
    return async (req, res, next) => {
      if (!req.session?.userId) {
        return next();
      }

      try {
        const databaseConfig = require('../config/database');
        const knex = databaseConfig.getKnex();

        // Load user data
        const user = await knex('users')
          .where({ id: req.session.userId })
          .first();

        if (!user) {
          // User not found - clear session
          req.session.destroy((err) => {
            if (err) {
              console.error('Session destroy error:', err);
            }
          });

          return next();
        }

        // Add user to request
        req.user = user;
        req.user.isAuthenticated = true;

        next();
      } catch (error) {
        console.error('Load user error:', error);
        next(error);
      }
    };
  }

  // Generate CSRF token for session
  generateCSRF() {
    return (req, res, next) => {
      if (!req.session.csrfToken) {
        const securityMiddleware = require('./security');
        req.session.csrfToken = securityMiddleware.generateCSRFToken();
      }
      next();
    };
  }

  // Check if user has device public key
  requireDeviceKey() {
    return (req, res, next) => {
      if (!req.session?.userId || !req.deviceSession?.public_key) {
        return res.status(400).json({
          success: false,
          error: 'Device public key required',
          requiresKeyRegistration: true
        });
      }

      next();
    };
  }

  // Middleware to register device in session
  registerDeviceSession(deviceId, publicKey) {
    return (req, res, next) => {
      if (req.session) {
        req.session.deviceId = deviceId;
        req.session.devicePublicKey = publicKey;
      }
      next();
    };
  }

  // Session hijacking detection
  hijackingDetection() {
    return (req, res, next) => {
      if (!req.session) {
        return next();
      }

      // Check for suspicious activity
      const suspicious = {
        rapidRequests: false,
        locationChange: false,
        deviceChange: false
      };

      // Check for rapid successive requests (possible bot)
      if (req.session.lastRequestTime) {
        const timeDiff = Date.now() - req.session.lastRequestTime;
        if (timeDiff < 100) { // Less than 100ms between requests
          suspicious.rapidRequests = true;
        }
      }

      // Update last request time
      req.session.lastRequestTime = Date.now();

      // If suspicious activity detected, log it (in development only)
      if (this.config.isDevelopment() && Object.values(suspicious).some(Boolean)) {
        console.log('Suspicious activity detected:', {
          userId: req.session.userId,
          ip: req.ip,
          suspicious
        });
      }

      next();
    };
  }
}

module.exports = new AuthMiddleware();
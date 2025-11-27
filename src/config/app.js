require('dotenv').config();

class AppConfig {
  constructor() {
    this.config = this.loadConfig();
  }

  loadConfig() {
    return {
      // Server configuration
      port: parseInt(process.env.PORT) || 3000,
      host: process.env.HOST || 'localhost',
      environment: process.env.NODE_ENV || 'development',

      // Session configuration
      session: {
        secret: process.env.SESSION_SECRET || this.generateSecureSecret(),
        resave: false,
        saveUninitialized: false,
        rolling: true,
        cookie: {
          secure: process.env.NODE_ENV === 'production',
          httpOnly: true,
          maxAge: 24 * 60 * 60 * 1000, // 24 hours
          sameSite: 'strict'
        },
        name: 'darkchat.sid'
      },

      // CORS configuration
      cors: {
        origin: process.env.CORS_ORIGIN || ['http://localhost:3000'],
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
      },

      // WebSocket CORS configuration
      socketCors: {
        origin: process.env.CORS_ORIGIN || ['http://localhost:3000'],
        methods: ['GET', 'POST'],
        credentials: true
      },

      // Rate limiting
      rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        standardHeaders: true,
        legacyHeaders: false,
        message: 'Too many requests from this IP, please try again later.',
        // Skip rate limiting for successful requests under threshold
        skipSuccessfulRequests: false
      },

      // Message rate limiting
      messageRateLimit: {
        windowMs: 60 * 1000, // 1 minute
        max: 10, // limit each user to 10 messages per minute
        message: 'Message rate limit exceeded. Please wait before sending more messages.'
      },

      // WebSocket rate limiting
      connectionLimit: {
        maxConnections: 5, // max 5 connections per user
        messageLimit: 30, // max 30 messages per minute per connection
        windowMs: 60 * 1000 // 1 minute window
      },

      // Security headers (Helmet)
      helmet: {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // Required for crypto operations in browser
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws:", "wss:"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            childSrc: ["'none'"],
            workerSrc: ["'self'"],
            manifestSrc: ["'self'"],
            upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
          }
        },
        crossOriginEmbedderPolicy: false,
        crossOriginResourcePolicy: { policy: "cross-origin" }
      },

      // Application limits
      limits: {
        maxUsernameLength: 50,
        minUsernameLength: 2,
        maxMessageLength: 10000,
        maxDeviceSessions: 10,
        messageRetentionDays: 7,
        sessionTimeoutHours: 24
      },

      // Privacy settings
      privacy: {
        logLevel: process.env.LOG_LEVEL || 'error',
        enableMetrics: process.env.ENABLE_METRICS === 'true',
        anonymizeLogs: true,
        disableUserTracking: true
      },

      // Performance settings
      performance: {
        compressionEnabled: true,
        staticCacheMaxAge: 24 * 60 * 60 * 1000, // 24 hours
        viewCache: process.env.NODE_ENV === 'production',
        trustProxy: process.env.TRUST_PROXY === 'true'
      }
    };
  }

  // Generate cryptographically secure secret for sessions
  generateSecureSecret() {
    const crypto = require('crypto');
    return crypto.randomBytes(64).toString('hex');
  }

  // Get configuration value
  get(path, defaultValue = undefined) {
    const keys = path.split('.');
    let current = this.config;

    for (const key of keys) {
      if (current[key] === undefined) {
        return defaultValue;
      }
      current = current[key];
    }

    return current;
  }

  // Check if in production mode
  isProduction() {
    return this.config.environment === 'production';
  }

  // Check if in development mode
  isDevelopment() {
    return this.config.environment === 'development';
  }

  // Get environment-specific value
  envSpecific(devValue, prodValue) {
    return this.isProduction() ? prodValue : devValue;
  }

  // Validate required environment variables
  validateEnvironment() {
    const required = [];
    const optional = [
      'PORT',
      'DATABASE_URL',
      'REDIS_URL',
      'SESSION_SECRET',
      'NODE_ENV',
      'CORS_ORIGIN'
    ];

    // Check for missing required variables
    const missing = required.filter(key => !process.env[key]);

    if (missing.length > 0) {
      throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }

    // Warn about unset optional variables
    const unset = optional.filter(key => !process.env[key]);
    if (unset.length > 0 && this.isDevelopment()) {
      console.log(`Using default values for: ${unset.join(', ')}`);
    }

    return true;
  }

  // Get complete configuration
  getAll() {
    return { ...this.config };
  }
}

module.exports = new AppConfig();
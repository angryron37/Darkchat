require('dotenv').config();

const express = require('express');
const http = require('http');
const session = require('express-session');
const path = require('path');

// Import configurations
const appConfig = require('./config/app');
const databaseConfig = require('./config/database');

// Import middleware
const SecurityMiddleware = require('./middleware/security');
const AuthMiddleware = require('./middleware/auth');

// Import controllers and services
const AuthController = require('./controllers/AuthController');
const MessageController = require('./controllers/MessageController');
const ChatController = require('./controllers/ChatController');
const NotificationController = require('./controllers/NotificationController');
const WebSocketService = require('./services/WebSocketService');
const MessageService = require('./services/MessageService');

// Import routes
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const webRoutes = require('./routes/web');

class DarkChatApp {
  constructor() {
    this.app = express();
    this.server = null;
    this.webSocketService = null;
    this.notificationController = null;
    this.messageService = null;
  }

  async initialize() {
    try {
      console.log('🚀 Initializing DarkChat...');

      // Validate environment
      appConfig.validateEnvironment();
      console.log('✅ Environment validated');

      // Test database connections
      await databaseConfig.testConnections();
      console.log('✅ Database connections tested');

      // Run database migrations
      await this.runMigrations();
      console.log('✅ Database migrations completed');

      // Initialize services
      await this.initializeServices();
      console.log('✅ Services initialized');

      // Setup middleware
      this.setupMiddleware();
      console.log('✅ Middleware configured');

      // Setup routes
      this.setupRoutes();
      console.log('✅ Routes configured');

      // Setup error handling
      this.setupErrorHandling();
      console.log('✅ Error handling configured');

      // Start background tasks
      this.startBackgroundTasks();
      console.log('✅ Background tasks started');

      console.log('🎉 DarkChat initialized successfully!');
    } catch (error) {
      console.error('❌ Failed to initialize DarkChat:', error);
      throw error;
    }
  }

  async runMigrations() {
    try {
      const knex = databaseConfig.getKnex();

      // Check if migrations table exists and run latest migrations
      await knex.migrate.latest();
    } catch (error) {
      console.error('Migration error:', error);
      throw error;
    }
  }

  async initializeServices() {
    // Initialize MessageService
    this.messageService = new MessageService();

    // Initialize WebSocketService (will be attached to HTTP server later)
    this.webSocketService = new WebSocketService();

    // Initialize NotificationController
    this.notificationController = new NotificationController();
  }

  setupMiddleware() {
    // Trust proxy if configured
    if (appConfig.get('performance.trustProxy')) {
      this.app.set('trust proxy', 1);
    }

    // View engine setup
    this.app.set('view engine', 'ejs');
    this.app.set('views', path.join(__dirname, 'views'));

    // Apply security middleware
    SecurityMiddleware.applySecurity(this.app);

    // Session middleware
    this.app.use(AuthMiddleware.sessionMiddleware());

    // Device fingerprinting
    this.app.use(AuthMiddleware.deviceFingerprint());

    // Session validation and cleanup
    this.app.use(AuthMiddleware.sessionCleanup());

    // Load user data
    this.app.use(AuthMiddleware.loadUser());

    // Generate CSRF tokens
    this.app.use(AuthMiddleware.generateCSRF());

    // JSON parsing middleware
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Request logging middleware
    this.app.use((req, res, next) => {
      const start = Date.now();

      res.on('finish', () => {
        const duration = Date.now() - start;
        console.log(`${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
      });

      next();
    });
  }

  setupRoutes() {
    // Health check endpoint
    this.app.get('/health', (req, res) => {
      res.status(200).json({
        success: true,
        data: {
          status: 'healthy',
          timestamp: new Date().toISOString(),
          uptime: process.uptime(),
          environment: appConfig.get('environment')
        }
      });
    });

    // Mount route handlers
    this.app.use('/auth', authRoutes);
    this.app.use('/api', apiRoutes);
    this.app.use('/', webRoutes);

    // Make services available to routes
    this.app.set('webSocketService', this.webSocketService);
    this.app.set('messageService', this.messageService);
    this.app.set('notificationController', this.notificationController);
  }

  setupErrorHandling() {
    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).render('error', {
        title: 'Page Not Found',
        message: 'The page you are looking for does not exist',
        showHome: true
      });
    });

    // Global error handler
    this.app.use((error, req, res, next) => {
      console.error('Global error handler:', error);

      // Don't leak error details in production
      const showError = appConfig.isDevelopment();

      res.status(error.status || 500).render('error', {
        title: error.status ? `Error ${error.status}` : 'Server Error',
        message: error.message || 'An unexpected error occurred',
        error: showError ? error.stack : null,
        showHome: true
      });
    });
  }

  async start() {
    try {
      const port = appConfig.get('port');
      const host = appConfig.get('host');

      // Create HTTP server
      this.server = http.createServer(this.app);

      // Initialize WebSocket service with HTTP server
      this.webSocketService.initialize(this.server);

      // Initialize notification controller event handlers
      this.notificationController.initializeWebSocketEventHandlers(this.webSocketService);

      // Make notification controller available globally
      global.notificationController = this.notificationController;

      // Start listening
      this.server.listen(port, host, () => {
        console.log(`🌐 DarkChat server running on http://${host}:${port}`);
        console.log(`🔗 Environment: ${appConfig.get('environment')}`);

        if (appConfig.isDevelopment()) {
          console.log(`🛠️  Development tools available at http://${host}:${port}/dev/tools`);
        }

        console.log(`📊 Health check: http://${host}:${port}/health`);
        console.log(`🔒 Privacy policy: http://${host}:${port}/privacy`);
      });

      // Graceful shutdown handling
      this.setupGracefulShutdown();

    } catch (error) {
      console.error('❌ Failed to start DarkChat server:', error);
      throw error;
    }
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);

      try {
        // Stop accepting new connections
        if (this.server) {
          this.server.close();
        }

        // Shutdown WebSocket service
        if (this.webSocketService) {
          await this.webSocketService.shutdown();
        }

        // Close database connections
        await databaseConfig.close();

        console.log('✅ Graceful shutdown completed');
        process.exit(0);
      } catch (error) {
        console.error('❌ Error during shutdown:', error);
        process.exit(1);
      }
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      console.error('💥 Uncaught Exception:', error);
      shutdown('uncaughtException');
    });

    // Handle unhandled rejections
    process.on('unhandledRejection', (reason, promise) => {
      console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
      shutdown('unhandledRejection');
    });
  }

  startBackgroundTasks() {
    // Message cleanup task (runs every 5 minutes)
    setInterval(async () => {
      try {
        await this.messageService.cleanupExpiredMessages();
      } catch (error) {
        console.error('Message cleanup error:', error);
      }
    }, 5 * 60 * 1000);

    // Device cleanup task (runs every hour)
    setInterval(async () => {
      try {
        const deviceSession = require('./models/DeviceSession');
        await new deviceSession().cleanupInactiveDevices();
      } catch (error) {
        console.error('Device cleanup error:', error);
      }
    }, 60 * 60 * 1000);

    // System metrics collection (runs every minute)
    setInterval(async () => {
      try {
        const memoryUsage = process.memoryUsage();
        const uptime = process.uptime();

        // Log memory usage (development only)
        if (appConfig.isDevelopment()) {
          console.log(`📊 Memory: ${(memoryUsage.heapUsed / 1024 / 1024).toFixed(2)}MB, Uptime: ${Math.floor(uptime)}s`);
        }
      } catch (error) {
        console.error('Metrics collection error:', error);
      }
    }, 60 * 1000);

    // Start notification controller periodic tasks
    if (this.notificationController) {
      this.notificationController.schedulePeriodicNotifications();
    }
  }

  getApp() {
    return this.app;
  }

  getServer() {
    return this.server;
  }

  getWebSocketService() {
    return this.webSocketService;
  }
}

// Create and initialize app instance
const darkChat = new DarkChatApp();

// Auto-start if not being required as a module
if (require.main === module) {
  darkChat.initialize()
    .then(() => darkChat.start())
    .catch((error) => {
      console.error('💥 Failed to start DarkChat:', error);
      process.exit(1);
    });
}

module.exports = darkChat;
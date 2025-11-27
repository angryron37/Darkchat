const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const MessageService = require('./MessageService');
const User = require('../models/User');
const config = require('../config/app');

class WebSocketService {
  constructor() {
    this.io = null;
    this.messageService = new MessageService();
    this.userModel = new User();
    this.connectedUsers = new Map(); // userId -> Set of socket IDs
    this.socketUsers = new Map(); // socketId -> userId
    this.userSockets = new Map(); // userId -> Map of socketId -> socket
  }

  /**
   * Initialize WebSocket server
   * @param {Object} httpServer - HTTP server instance
   */
  initialize(httpServer) {
    try {
      this.io = new Server(httpServer, {
        cors: config.get('socketCors'),
        transports: ['websocket', 'polling'],
        pingTimeout: 60000,
        pingInterval: 25000,
        maxHttpBufferSize: 1e6, // 1 MB
        compression: true
      });

      this.setupMiddleware();
      this.setupEventHandlers();
      this.setupCleanupInterval();

      console.log('WebSocket server initialized');
    } catch (error) {
      console.error('Failed to initialize WebSocket server:', error);
      throw error;
    }
  }

  /**
   * Setup WebSocket middleware for authentication and validation
   */
  setupMiddleware() {
    // Authentication middleware
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token || socket.handshake.headers.authorization;

        if (!token) {
          return next(new Error('Authentication required'));
        }

        // Validate session (simplified for this implementation)
        const session = socket.handshake.session;
        if (!session || !session.userId) {
          return next(new Error('Valid session required'));
        }

        socket.userId = session.userId;
        socket.username = session.username;

        next();
      } catch (error) {
        next(new Error('Authentication failed'));
      }
    });

    // Rate limiting middleware
    this.io.use((socket, next) => {
      const userId = socket.userId;
      const connectionCount = this.getSocketCountForUser(userId);
      const maxConnections = config.get('connectionLimit.maxConnections');

      if (connectionCount >= maxConnections) {
        return next(new Error('Connection limit exceeded'));
      }

      next();
    });
  }

  /**
   * Setup main WebSocket event handlers
   */
  setupEventHandlers() {
    this.io.on('connection', (socket) => {
      this.handleConnection(socket);
    });
  }

  /**
   * Handle new WebSocket connection
   * @param {Object} socket - Socket instance
   */
  async handleConnection(socket) {
    const userId = socket.userId;
    const username = socket.username;

    try {
      console.log(`User ${username} (${userId}) connected via WebSocket`);

      // Track user connection
      this.addUserConnection(userId, socket);

      // Update user status
      await this.userModel.updateStatus(userId, 'online');

      // Notify user's other devices about new connection
      this.notifyUserDevices(userId, 'device-connected', {
        socketId: socket.id,
        timestamp: new Date().toISOString()
      });

      // Setup socket event handlers
      this.setupSocketEventHandlers(socket);

      // Send initial data to user
      await this.sendInitialData(socket);

      // Broadcast user online status to others
      this.broadcastUserStatus(userId, 'online');

    } catch (error) {
      console.error('Error handling WebSocket connection:', error);
      socket.emit('error', { message: 'Connection setup failed' });
    }
  }

  /**
   * Setup event handlers for individual socket
   * @param {Object} socket - Socket instance
   */
  setupSocketEventHandlers(socket) {
    const userId = socket.userId;

    // Handle disconnect
    socket.on('disconnect', (reason) => {
      this.handleDisconnection(socket, reason);
    });

    // Handle typing indicators
    socket.on('typing-start', async (data) => {
      await this.handleTypingStart(socket, data);
    });

    socket.on('typing-stop', async (data) => {
      await this.handleTypingStop(socket, data);
    });

    // Handle message read receipt
    socket.on('message-read', async (data) => {
      await this.handleMessageRead(socket, data);
    });

    // Handle user status change
    socket.on('status-change', async (data) => {
      await this.handleStatusChange(socket, data);
    });

    // Handle ping for connection health
    socket.on('ping', () => {
      socket.emit('pong', { timestamp: Date.now() });
    });

    // Handle errors
    socket.on('error', (error) => {
      console.error(`Socket error for user ${userId}:`, error);
    });
  }

  /**
   * Handle user disconnection
   * @param {Object} socket - Socket instance
   * @param {string} reason - Disconnection reason
   */
  async handleDisconnection(socket, reason) {
    const userId = socket.userId;
    const username = socket.username;

    try {
      console.log(`User ${username} (${userId}) disconnected: ${reason}`);

      // Remove connection from tracking
      this.removeUserConnection(userId, socket);

      // Update user status if no more connections
      if (this.getSocketCountForUser(userId) === 0) {
        await this.userModel.updateStatus(userId, 'offline');
        this.broadcastUserStatus(userId, 'offline');
      }

      // Clean up typing indicators
      await this.cleanupTypingIndicators(userId);

      // Remove from Redis tracking
      await this.messageService.removeUserConnection(userId, socket.id);

    } catch (error) {
      console.error('Error handling WebSocket disconnection:', error);
    }
  }

  /**
   * Send message to specific user
   * @param {string} userId - Target user ID
   * @param {string} event - Event name
   * @param {Object} data - Event data
   * @returns {Promise<number>} Number of sockets message was sent to
   */
  async sendMessageToUser(userId, event, data) {
    try {
      const userSockets = this.userSockets.get(userId);
      if (!userSockets || userSockets.size === 0) {
        return 0;
      }

      let sentCount = 0;

      for (const [socketId, socket] of userSockets) {
        if (socket.connected) {
          socket.emit(event, data);
          sentCount++;
        }
      }

      return sentCount;
    } catch (error) {
      console.error('Error sending message to user:', error);
      return 0;
    }
  }

  /**
   * Broadcast message to all connected users
   * @param {string} event - Event name
   * @param {Object} data - Event data
   * @param {string} excludeUserId - User ID to exclude from broadcast
   */
  broadcastToAll(event, data, excludeUserId = null) {
    try {
      for (const [userId, userSockets] of this.userSockets) {
        if (excludeUserId && userId === excludeUserId) {
          continue;
        }

        for (const [socketId, socket] of userSockets) {
          if (socket.connected) {
            socket.emit(event, data);
          }
        }
      }
    } catch (error) {
      console.error('Error broadcasting message:', error);
    }
  }

  /**
   * Send new message notification
   * @param {Object} messageData - Message information
   */
  async notifyNewMessage(messageData) {
    try {
      const { receiverId, messageId, senderId, oneTimeView, anonymous, expiresIn } = messageData;

      // Get sender info for display
      const sender = await this.userModel.getById(senderId);

      // Send notification to receiver
      const notificationData = {
        messageId,
        sender: anonymous ? 'Anonymous' : (sender?.username || 'Unknown'),
        senderId,
        isAnonymous: anonymous,
        isOneTimeView: oneTimeView,
        expiresIn,
        timestamp: new Date().toISOString()
      };

      const sentCount = await this.sendMessageToUser(receiverId, 'new-message', notificationData);

      // Update sender's sent status
      if (sentCount > 0) {
        await this.sendMessageToUser(senderId, 'message-delivered', {
          messageId,
          receiverId,
          timestamp: new Date().toISOString()
        });
      }

    } catch (error) {
      console.error('Error notifying new message:', error);
    }
  }

  /**
   * Handle typing start indicator
   * @param {Object} socket - Socket instance
   * @param {Object} data - Typing data {receiverId}
   */
  async handleTypingStart(socket, data) {
    try {
      const { receiverId } = data;
      const userId = socket.userId;

      if (!receiverId || receiverId === userId) {
        return;
      }

      // Set typing indicator in Redis
      await this.messageService.setTypingIndicator(userId, receiverId, true);

      // Notify receiver
      await this.sendMessageToUser(receiverId, 'typing-start', {
        userId,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Error handling typing start:', error);
    }
  }

  /**
   * Handle typing stop indicator
   * @param {Object} socket - Socket instance
   * @param {Object} data - Typing data {receiverId}
   */
  async handleTypingStop(socket, data) {
    try {
      const { receiverId } = data;
      const userId = socket.userId;

      if (!receiverId || receiverId === userId) {
        return;
      }

      // Remove typing indicator from Redis
      await this.messageService.setTypingIndicator(userId, receiverId, false);

      // Notify receiver
      await this.sendMessageToUser(receiverId, 'typing-stop', {
        userId,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Error handling typing stop:', error);
    }
  }

  /**
   * Handle message read receipt
   * @param {Object} socket - Socket instance
   * @param {Object} data - Read receipt data {messageId}
   */
  async handleMessageRead(socket, data) {
    try {
      const { messageId } = data;
      const userId = socket.userId;

      if (!messageId) {
        return;
      }

      // Mark message as read
      const markedAsRead = await this.messageService.markAsRead(messageId, userId);

      if (markedAsRead) {
        // Get message metadata to find sender
        const message = await this.messageService.messageModel.getByMessageId(messageId);

        if (message && message.senderId !== userId) {
          // Notify sender that message was read
          await this.sendMessageToUser(message.senderId, 'message-read', {
            messageId,
            readerId: userId,
            timestamp: new Date().toISOString()
          });
        }
      }

    } catch (error) {
      console.error('Error handling message read:', error);
    }
  }

  /**
   * Handle user status change
   * @param {Object} socket - Socket instance
   * @param {Object} data - Status data {status}
   */
  async handleStatusChange(socket, data) {
    try {
      const { status } = data;
      const userId = socket.userId;

      const validStatuses = ['online', 'away', 'busy'];
      if (!validStatuses.includes(status)) {
        return;
      }

      // Update user status in database
      await this.userModel.updateStatus(userId, status);

      // Broadcast status change
      this.broadcastUserStatus(userId, status);

    } catch (error) {
      console.error('Error handling status change:', error);
    }
  }

  /**
   * Send initial data to newly connected socket
   * @param {Object} socket - Socket instance
   */
  async sendInitialData(socket) {
    try {
      const userId = socket.userId;

      // Get unread messages count
      const unreadMessages = await this.messageService.messageModel.getUnreadMessages(userId, 1000);

      // Get typing indicators
      const typingUsers = await this.messageService.getTypingIndicators(userId);

      // Get active users list
      const activeUsers = await this.userModel.getAllActive(50);

      const initialData = {
        unreadCount: unreadMessages.length,
        typingUsers: Array.from(typingUsers),
        activeUsers: activeUsers.map(user => ({
          id: user.id,
          username: user.username,
          status: user.status
        })),
        serverTime: new Date().toISOString()
      };

      socket.emit('initial-data', initialData);

    } catch (error) {
      console.error('Error sending initial data:', error);
    }
  }

  /**
   * Add user connection to tracking
   * @param {string} userId - User ID
   * @param {Object} socket - Socket instance
   */
  addUserConnection(userId, socket) {
    // Add to user sockets map
    if (!this.userSockets.has(userId)) {
      this.userSockets.set(userId, new Map());
    }
    this.userSockets.get(userId).set(socket.id, socket);

    // Add to socket users map
    this.socketUsers.set(socket.id, userId);

    // Track in Redis
    this.messageService.trackUserConnection(userId, socket.id);
  }

  /**
   * Remove user connection from tracking
   * @param {string} userId - User ID
   * @param {Object} socket - Socket instance
   */
  removeUserConnection(userId, socket) {
    // Remove from user sockets map
    const userSockets = this.userSockets.get(userId);
    if (userSockets) {
      userSockets.delete(socket.id);
      if (userSockets.size === 0) {
        this.userSockets.delete(userId);
      }
    }

    // Remove from socket users map
    this.socketUsers.delete(socket.id);

    // Remove from Redis tracking
    this.messageService.removeUserConnection(userId, socket.id);
  }

  /**
   * Get socket count for user
   * @param {string} userId - User ID
   * @returns {number} Number of active sockets
   */
  getSocketCountForUser(userId) {
    const userSockets = this.userSockets.get(userId);
    return userSockets ? userSockets.size : 0;
  }

  /**
   * Broadcast user status change
   * @param {string} userId - User ID
   * @param {string} status - New status
   */
  broadcastUserStatus(userId, status) {
    const statusData = {
      userId,
      status,
      timestamp: new Date().toISOString()
    };

    this.broadcastToAll('user-status', statusData, userId);
  }

  /**
   * Notify user's other devices
   * @param {string} userId - User ID
   * @param {string} event - Event name
   * @param {Object} data - Event data
   */
  notifyUserDevices(userId, event, data) {
    const userSockets = this.userSockets.get(userId);
    if (!userSockets) return;

    for (const [socketId, socket] of userSockets) {
      if (socket.connected) {
        socket.emit(event, data);
      }
    }
  }

  /**
   * Clean up typing indicators for user
   * @param {string} userId - User ID
   */
  async cleanupTypingIndicators(userId) {
    try {
      // This would need to be implemented in MessageService
      // to remove all typing indicators for a disconnected user
      console.log(`Cleaning up typing indicators for user ${userId}`);
    } catch (error) {
      console.error('Error cleaning up typing indicators:', error);
    }
  }

  /**
   * Setup periodic cleanup interval
   */
  setupCleanupInterval() {
    // Clean up disconnected sockets every 5 minutes
    setInterval(() => {
      this.cleanupDisconnectedSockets();
    }, 5 * 60 * 1000);
  }

  /**
   * Clean up disconnected sockets
   */
  cleanupDisconnectedSockets() {
    try {
      for (const [userId, userSockets] of this.userSockets) {
        for (const [socketId, socket] of userSockets) {
          if (!socket.connected) {
            this.removeUserConnection(userId, socket);
          }
        }
      }
    } catch (error) {
      console.error('Error cleaning up disconnected sockets:', error);
    }
  }

  /**
   * Get WebSocket statistics
   * @returns {Object} Statistics about WebSocket connections
   */
  getStats() {
    const totalSockets = this.io ? this.io.sockets.sockets.size : 0;
    const totalUsers = this.userSockets.size;

    const connectionDetails = [];
    for (const [userId, userSockets] of this.userSockets) {
      connectionDetails.push({
        userId,
        socketCount: userSockets.size
      });
    }

    return {
      totalSockets,
      totalUsers,
      connectionDetails,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Graceful shutdown
   */
  async shutdown() {
    try {
      if (this.io) {
        // Disconnect all clients
        this.io.disconnectSockets();
        this.io.close();
      }

      // Clear all tracking maps
      this.connectedUsers.clear();
      this.socketUsers.clear();
      this.userSockets.clear();

      console.log('WebSocket service shut down gracefully');
    } catch (error) {
      console.error('Error during WebSocket shutdown:', error);
    }
  }
}

module.exports = WebSocketService;
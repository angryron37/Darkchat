const User = require('../models/User');
const MessageService = require('../services/MessageService');
const WebSocketService = require('../services/WebSocketService');

class NotificationController {
  constructor() {
    this.userModel = new User();
    this.messageService = new MessageService();
    // Note: WebSocketService will be injected during app initialization
  }

  /**
   * Initialize WebSocket event handlers
   * This method should be called during app initialization
   */
  initializeWebSocketEventHandlers(webSocketService) {
    this.webSocketService = webSocketService;
    this.setupEventHandlers();
  }

  /**
   * Setup WebSocket event handlers
   */
  setupEventHandlers() {
    if (!this.webSocketService) {
      console.error('WebSocketService not initialized');
      return;
    }

    // Override the WebSocketService notifyNewMessage method
    const originalNotifyNewMessage = this.webSocketService.notifyNewMessage.bind(this.webSocketService);
    this.webSocketService.notifyNewMessage = async (messageData) => {
      await this.handleNewMessageNotification(messageData);
    };

    // Add custom event handlers
    this.webSocketService.on('connection', (socket) => {
      this.handleSocketConnection(socket);
    });
  }

  /**
   * Handle new WebSocket connection
   * @param {Object} socket - Socket instance
   */
  async handleSocketConnection(socket) {
    try {
      const userId = socket.userId;
      const username = socket.username;

      console.log(`Socket connected: ${username} (${userId})`);

      // Send welcome notification
      socket.emit('welcome', {
        message: 'Connected to DarkChat',
        timestamp: new Date().toISOString(),
        userId,
        username
      });

      // Setup socket-specific event handlers
      this.setupSocketEventHandlers(socket);

    } catch (error) {
      console.error('Socket connection error:', error);
      socket.emit('error', { message: 'Connection setup failed' });
    }
  }

  /**
   * Setup event handlers for individual socket
   * @param {Object} socket - Socket instance
   */
  setupSocketEventHandlers(socket) {
    // Handle custom notifications
    socket.on('request-notification', async (data) => {
      await this.handleNotificationRequest(socket, data);
    });

    // Handle message status updates
    socket.on('message-status', async (data) => {
      await this.handleMessageStatusUpdate(socket, data);
    });

    // Handle user status updates
    socket.on('user-status-update', async (data) => {
      await this.handleUserStatusUpdate(socket, data);
    });

    // Handle typing indicators (enhanced version)
    socket.on('typing-indicator', async (data) => {
      await this.handleTypingIndicator(socket, data);
    });

    // Handle connection quality feedback
    socket.on('connection-quality', (data) => {
      this.handleConnectionQuality(socket, data);
    });

    // Handle message delivery confirmation
    socket.on('delivery-confirmation', async (data) => {
      await this.handleDeliveryConfirmation(socket, data);
    });
  }

  /**
   * Handle new message notification
   * @param {Object} messageData - Message information
   */
  async handleNewMessageNotification(messageData) {
    try {
      const { receiverId, messageId, senderId, oneTimeView, anonymous, expiresIn } = messageData;

      // Get sender information
      const sender = await this.userModel.getById(senderId);

      // Create notification payload
      const notification = {
        type: 'new-message',
        messageId,
        sender: anonymous ? 'Anonymous' : (sender?.username || 'Unknown'),
        senderId,
        isAnonymous: anonymous,
        isOneTimeView: oneTimeView,
        expiresIn,
        priority: oneTimeView ? 'high' : 'normal',
        timestamp: new Date().toISOString()
      };

      // Send to specific user
      const sentCount = await this.webSocketService.sendMessageToUser(receiverId, 'notification', notification);

      // Update sender about delivery status
      if (sentCount > 0) {
        await this.webSocketService.sendMessageToUser(senderId, 'notification', {
          type: 'message-delivered',
          messageId,
          receiverId,
          timestamp: new Date().toISOString()
        });
      }

      console.log(`New message notification sent to ${sentCount} sockets for user ${receiverId}`);

    } catch (error) {
      console.error('New message notification error:', error);
    }
  }

  /**
   * Handle notification request from client
   * @param {Object} socket - Socket instance
   * @param {Object} data - Request data
   */
  async handleNotificationRequest(socket, data) {
    try {
      const { type, payload } = data;
      const userId = socket.userId;

      switch (type) {
        case 'unread-count':
          const unreadCount = await this.getUnreadCount(userId);
          socket.emit('notification-response', {
            type: 'unread-count',
            count: unreadCount
          });
          break;

        case 'active-users':
          const activeUsers = await this.userModel.getAllActive(20);
          socket.emit('notification-response', {
            type: 'active-users',
            users: activeUsers.map(user => ({
              id: user.id,
              username: user.username,
              status: user.status
            }))
          });
          break;

        case 'system-status':
          const systemStatus = await this.getSystemStatus();
          socket.emit('notification-response', {
            type: 'system-status',
            ...systemStatus
          });
          break;

        default:
          socket.emit('notification-response', {
            type: 'error',
            message: 'Unknown notification type'
          });
      }

    } catch (error) {
      console.error('Notification request error:', error);
      socket.emit('notification-response', {
        type: 'error',
        message: 'Failed to process notification request'
      });
    }
  }

  /**
   * Handle message status update
   * @param {Object} socket - Socket instance
   * @param {Object} data - Status update data
   */
  async handleMessageStatusUpdate(socket, data) {
    try {
      const { messageId, status, userId } = data;
      const currentUserId = socket.userId;

      if (!messageId || !status) {
        socket.emit('error', { message: 'Invalid message status update' });
        return;
      }

      // Update message status in database
      await this.messageService.messageModel.updateStatus(messageId, status);

      // Notify other party if they're online
      if (userId && userId !== currentUserId) {
        await this.webSocketService.sendMessageToUser(userId, 'message-status-update', {
          messageId,
          status,
          updatedBy: currentUserId,
          timestamp: new Date().toISOString()
        });
      }

    } catch (error) {
      console.error('Message status update error:', error);
      socket.emit('error', { message: 'Failed to update message status' });
    }
  }

  /**
   * Handle user status update
   * @param {Object} socket - Socket instance
   * @param {Object} data - Status data
   */
  async handleUserStatusUpdate(socket, data) {
    try {
      const { status } = data;
      const userId = socket.userId;

      if (!status) {
        socket.emit('error', { message: 'Status is required' });
        return;
      }

      // Update user status in database
      await this.userModel.updateStatus(userId, status);

      // Broadcast status change to all users
      this.webSocketService.broadcastToAll('user-status-changed', {
        userId,
        status,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('User status update error:', error);
      socket.emit('error', { message: 'Failed to update status' });
    }
  }

  /**
   * Handle typing indicator
   * @param {Object} socket - Socket instance
   * @param {Object} data - Typing data
   */
  async handleTypingIndicator(socket, data) {
    try {
      const { receiverId, isTyping } = data;
      const userId = socket.userId;

      if (!receiverId) {
        socket.emit('error', { message: 'Receiver ID is required' });
        return;
      }

      // Update typing indicator in Redis
      await this.messageService.setTypingIndicator(userId, receiverId, isTyping);

      // Notify receiver
      const notification = {
        type: 'typing-indicator',
        userId,
        isTyping,
        timestamp: new Date().toISOString()
      };

      await this.webSocketService.sendMessageToUser(receiverId, 'notification', notification);

    } catch (error) {
      console.error('Typing indicator error:', error);
      socket.emit('error', { message: 'Failed to update typing indicator' });
    }
  }

  /**
   * Handle connection quality feedback
   * @param {Object} socket - Socket instance
   * @param {Object} data - Quality data
   */
  handleConnectionQuality(socket, data) {
    try {
      const { latency, bandwidth, connectionType } = data;
      const userId = socket.userId;

      // Log connection quality metrics (for monitoring)
      console.log(`Connection quality for ${userId}:`, {
        latency,
        bandwidth,
        connectionType,
        timestamp: new Date().toISOString()
      });

      // Acknowledge receipt
      socket.emit('connection-quality-ack', {
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Connection quality error:', error);
    }
  }

  /**
   * Handle message delivery confirmation
   * @param {Object} socket - Socket instance
   * @param {Object} data - Delivery data
   */
  async handleDeliveryConfirmation(socket, data) {
    try {
      const { messageId, delivered, read } = data;
      const userId = socket.userId;

      if (!messageId) {
        socket.emit('error', { message: 'Message ID is required' });
        return;
      }

      // Get message metadata to find other party
      const message = await this.messageService.messageModel.getByMessageId(messageId);
      if (!message) {
        socket.emit('error', { message: 'Message not found' });
        return;
      }

      const otherUserId = message.senderId === userId ? message.receiverId : message.senderId;

      // Update message status
      if (delivered) {
        await this.messageService.messageModel.updateStatus(messageId, 'delivered');
      }

      if (read) {
        await this.messageService.messageModel.markAsRead(messageId, userId);
      }

      // Notify other party
      await this.webSocketService.sendMessageToUser(otherUserId, 'delivery-confirmation', {
        messageId,
        userId,
        delivered,
        read,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Delivery confirmation error:', error);
      socket.emit('error', { message: 'Failed to process delivery confirmation' });
    }
  }

  /**
   * Send system-wide notification
   * @param {string} type - Notification type
   * @param {Object} data - Notification data
   */
  async sendSystemNotification(type, data) {
    try {
      if (!this.webSocketService) {
        console.error('WebSocket service not available');
        return;
      }

      const notification = {
        type: 'system',
        subtype: type,
        ...data,
        timestamp: new Date().toISOString()
      };

      this.webSocketService.broadcastToAll('notification', notification);

      console.log(`System notification sent: ${type}`);

    } catch (error) {
      console.error('System notification error:', error);
    }
  }

  /**
   * Get unread message count for user
   * @param {string} userId - User ID
   * @returns {Promise<number>} Unread count
   */
  async getUnreadCount(userId) {
    try {
      const unreadMessages = await this.messageService.messageModel.getUnreadMessages(userId, 1000);
      return unreadMessages.length;
    } catch (error) {
      console.error('Get unread count error:', error);
      return 0;
    }
  }

  /**
   * Get system status
   * @returns {Promise<Object>} System status
   */
  async getSystemStatus() {
    try {
      const [redisStats, systemStats] = await Promise.all([
        this.messageService.getRedisStats(),
        this.messageService.messageModel.getSystemStats()
      ]);

      return {
        redis: redisStats,
        messages: systemStats,
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        timestamp: new Date().toISOString()
      };

    } catch (error) {
      console.error('Get system status error:', error);
      return {
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Schedule periodic notifications
   */
  schedulePeriodicNotifications() {
    // Send system status every 5 minutes
    setInterval(async () => {
      try {
        await this.sendSystemNotification('status-update', {
          message: 'System status update',
          ...(await this.getSystemStatus())
        });
      } catch (error) {
        console.error('Periodic notification error:', error);
      }
    }, 5 * 60 * 1000); // 5 minutes
  }

  /**
   * Handle user disconnection notification
   * @param {string} userId - User ID
   * @param {string} reason - Disconnection reason
   */
  async handleUserDisconnection(userId, reason) {
    try {
      // Update user status to offline if no more connections
      const socketCount = this.webSocketService.getSocketCountForUser(userId);
      if (socketCount === 0) {
        await this.userModel.updateStatus(userId, 'offline');

        // Notify other users about disconnection
        this.webSocketService.broadcastToAll('user-disconnected', {
          userId,
          reason,
          timestamp: new Date().toISOString()
        });
      }

      console.log(`User ${userId} disconnected: ${reason}`);

    } catch (error) {
      console.error('User disconnection handling error:', error);
    }
  }

  /**
   * Get notification statistics
   * @returns {Object} Notification statistics
   */
  getNotificationStats() {
    if (!this.webSocketService) {
      return { error: 'WebSocket service not initialized' };
    }

    const wsStats = this.webSocketService.getStats();

    return {
      ...wsStats,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = NotificationController;
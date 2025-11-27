const User = require('../models/User');
const Message = require('../models/Message');
const MessageService = require('../services/MessageService');
const KeyExchangeService = require('../services/KeyExchangeService');
const WebSocketService = require('../services/WebSocketService');
const ValidationMiddleware = require('../middleware/validation');

class MessageController {
  constructor() {
    this.userModel = new User();
    this.messageModel = new Message();
    this.messageService = new MessageService();
    this.keyExchangeService = new KeyExchangeService();
    // Note: WebSocketService will be injected during app initialization
  }

  /**
   * Send encrypted message
   */
  async sendMessage(req, res) {
    try {
      const senderId = req.session?.userId;
      const {
        recipient,
        cipherText,
        encryptedAESKey,
        signature,
        iv,
        authTag,
        expiresIn = 300, // Default 5 minutes
        oneTimeView = false,
        anonymous = false
      } = req.body;

      if (!senderId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Validate recipient exists
      const recipientUser = await this.userModel.findByUsername(recipient);
      if (!recipientUser) {
        return res.status(404).json({
          success: false,
          error: 'Recipient not found'
        });
      }

      // Validate recipient has public keys
      const recipientPublicKey = await this.keyExchangeService.getLatestPublicKeyByUsername(recipient);
      if (!recipientPublicKey) {
        return res.status(400).json({
          success: false,
          error: 'Recipient has not registered any encryption keys'
        });
      }

      // Generate unique message ID
      const messageId = this.messageModel.generateMessageId();

      // Calculate expiration time
      const expiresAt = new Date(Date.now() + (expiresIn * 1000));

      // Store message in Redis with TTL
      await this.messageService.storeMessage(
        messageId,
        { cipherText, signature, iv, authTag },
        expiresIn
      );

      // Create message metadata in database
      await this.messageModel.createMetadata(
        senderId,
        recipientUser.id,
        messageId,
        encryptedAESKey,
        expiresAt,
        oneTimeView,
        anonymous
      );

      // Add to recipient's inbox
      await this.messageService.addToUserInbox(
        recipientUser.id,
        {
          messageId,
          senderId,
          createdAt: new Date(),
          oneTimeView,
          anonymous,
          expiresAt
        },
        expiresIn
      );

      // Notify recipient via WebSocket if available
      const messageData = {
        messageId,
        senderId,
        receiverId: recipientUser.id,
        oneTimeView,
        anonymous,
        expiresIn
      };

      // Send WebSocket notification (will be handled by WebSocketService)
      if (req.app.get('webSocketService')) {
        await req.app.get('webSocketService').notifyNewMessage(messageData);
      }

      return res.status(201).json({
        success: true,
        data: {
          messageId,
          recipient: recipientUser.username,
          expiresAt,
          oneTimeView,
          anonymous,
          delivered: true
        }
      });

    } catch (error) {
      console.error('Send message error:', error);

      if (error.message.includes('already exists')) {
        return res.status(409).json({
          success: false,
          error: 'Message ID conflict'
        });
      }

      return res.status(500).json({
        success: false,
        error: 'Failed to send message'
      });
    }
  }

  /**
   * Get encrypted message by ID
   */
  async getMessage(req, res) {
    try {
      const userId = req.session?.userId;
      const { messageId } = req.params;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Get message metadata
      const metadata = await this.messageModel.getByMessageId(messageId);
      if (!metadata) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }

      // Check if user is authorized (sender or receiver)
      if (metadata.senderId !== userId && metadata.receiverId !== userId) {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      // Check if message has expired
      if (new Date(metadata.expiresAt) < new Date()) {
        return res.status(410).json({
          success: false,
          error: 'Message has expired'
        });
      }

      // Get encrypted message from Redis
      const encryptedMessage = await this.messageService.getMessage(
        messageId,
        metadata.isOneTimeView
      );

      if (!encryptedMessage) {
        return res.status(404).json({
          success: false,
          error: 'Message content not found'
        });
      }

      // Mark as read if user is receiver
      if (metadata.receiverId === userId) {
        await this.messageService.markAsRead(messageId, userId);
      }

      // Get sender's public key for signature verification
      const senderUser = await this.userModel.getById(metadata.senderId);

      return res.status(200).json({
        success: true,
        data: {
          messageId: metadata.messageId,
          cipherText: encryptedMessage.cipherText,
          signature: encryptedMessage.signature,
          iv: encryptedMessage.iv,
          authTag: encryptedMessage.authTag,
          encryptedAESKey: metadata.encryptedAesKey,
          expiresAt: metadata.expiresAt,
          isOneTimeView: metadata.isOneTimeView,
          isAnonymous: metadata.isAnonymous,
          sender: {
            id: metadata.senderId,
            username: metadata.isAnonymous ? 'Anonymous' : senderUser?.username
          },
          receiver: {
            id: metadata.receiverId
          },
          retrievedAt: new Date().toISOString()
        }
      });

    } catch (error) {
      console.error('Get message error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to retrieve message'
      });
    }
  }

  /**
   * Delete/destroy message (mark as read/destroyed)
   */
  async deleteMessage(req, res) {
    try {
      const userId = req.session?.userId;
      const { messageId } = req.params;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Get message metadata
      const metadata = await this.messageModel.getByMessageId(messageId);
      if (!metadata) {
        return res.status(404).json({
          success: false,
          error: 'Message not found'
        });
      }

      // Check if user is authorized (sender or receiver)
      if (metadata.senderId !== userId && metadata.receiverId !== userId) {
        return res.status(403).json({
          success: false,
          error: 'Access denied'
        });
      }

      // Remove from Redis storage
      const deleted = await this.messageService.getMessage(messageId, true); // Delete on retrieve
      if (deleted) {
        await this.messageModel.markAsDestroyed(messageId);
      }

      return res.status(200).json({
        success: true,
        message: 'Message deleted successfully'
      });

    } catch (error) {
      console.error('Delete message error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete message'
      });
    }
  }

  /**
   * Get user's inbox (message metadata only)
   */
  async getInbox(req, res) {
    try {
      const userId = req.session?.userId;
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Get inbox messages from Redis
      const inboxMessages = await this.messageService.getUserInbox(userId, limit, offset);

      // Get sender information for each message
      const messagesWithSenders = [];
      for (const msg of inboxMessages) {
        const senderUser = await this.userModel.getById(msg.senderId);
        messagesWithSenders.push({
          messageId: msg.messageId,
          sender: {
            id: msg.senderId,
            username: msg.anonymous ? 'Anonymous' : (senderUser?.username || 'Unknown')
          },
          isAnonymous: msg.anonymous,
          isOneTimeView: msg.oneTimeView,
          createdAt: msg.createdAt,
          expiresAt: msg.expiresAt,
          timeRemaining: Math.max(0, new Date(msg.expiresAt).getTime() - Date.now())
        });
      }

      return res.status(200).json({
        success: true,
        data: {
          messages: messagesWithSenders,
          count: messagesWithSenders.length,
          limit,
          offset
        }
      });

    } catch (error) {
      console.error('Get inbox error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get inbox'
      });
    }
  }

  /**
   * Get conversation between two users
   */
  async getConversation(req, res) {
    try {
      const userId = req.session?.userId;
      const { username } = req.params;
      const limit = parseInt(req.query.limit) || 50;
      const offset = parseInt(req.query.offset) || 0;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Find other user
      const otherUser = await this.userModel.findByUsername(username);
      if (!otherUser) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Get conversation messages
      const messages = await this.messageModel.getConversation(userId, otherUser.id, limit, offset);

      return res.status(200).json({
        success: true,
        data: {
          messages,
          otherUser: {
            id: otherUser.id,
            username: otherUser.username,
            status: otherUser.status
          },
          count: messages.length,
          limit,
          offset
        }
      });

    } catch (error) {
      console.error('Get conversation error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get conversation'
      });
    }
  }

  /**
   * Get active users list
   */
  async getActiveUsers(req, res) {
    try {
      const userId = req.session?.userId;
      const limit = parseInt(req.query.limit) || 50;
      const search = req.query.search?.trim();

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      let users;
      if (search) {
        users = await this.userModel.searchByUsername(search, limit);
      } else {
        users = await this.userModel.getAllActive(limit);
      }

      // Filter out current user and add public key status
      const filteredUsers = users
        .filter(user => user.id !== userId)
        .map(user => ({
          id: user.id,
          username: user.username,
          status: user.status,
          lastSeen: user.lastSeen,
          hasPublicKey: true // All active users should have public keys
        }));

      return res.status(200).json({
        success: true,
        data: {
          users: filteredUsers,
          count: filteredUsers.length,
          search: search || null
        }
      });

    } catch (error) {
      console.error('Get active users error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get active users'
      });
    }
  }

  /**
   * Get user's public keys
   */
  async getUserPublicKeys(req, res) {
    try {
      const { username } = req.params;

      if (!username) {
        return res.status(400).json({
          success: false,
          error: 'Username is required'
        });
      }

      const publicKeys = await this.keyExchangeService.getUserPublicKeysByUsername(username);

      if (publicKeys.length === 0) {
        return res.status(404).json({
          success: false,
          error: 'User not found or no public keys available'
        });
      }

      return res.status(200).json({
        success: true,
        data: {
          username,
          publicKeys,
          count: publicKeys.length
        }
      });

    } catch (error) {
      console.error('Get user public keys error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get public keys'
      });
    }
  }

  /**
   * Get message statistics
   */
  async getMessageStats(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const [userStats, systemStats] = await Promise.all([
        this.messageModel.getMessageStats(userId),
        this.messageModel.getSystemStats()
      ]);

      return res.status(200).json({
        success: true,
        data: {
          user: userStats,
          system: systemStats
        }
      });

    } catch (error) {
      console.error('Get message stats error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get message statistics'
      });
    }
  }

  // Validation middleware wrappers
  getValidationMiddleware() {
    return {
      validateSendMessage: [
        ValidationMiddleware.validateRecipient(),
        ValidationMiddleware.validateEncryptedData('cipherText'),
        ValidationMiddleware.validateAESKey(),
        ValidationMiddleware.validateSignature(),
        ValidationMiddleware.validateIV(),
        ValidationMiddleware.validateAuthTag(),
        ValidationMiddleware.validateMessageExpiration(),
        ValidationMiddleware.validateOneTimeView(),
        ValidationMiddleware.validateAnonymous(),
        ValidationMiddleware.validateBusinessRules(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateGetMessage: [
        ValidationMiddleware.validateMessageId(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateDeleteMessage: [
        ValidationMiddleware.validateMessageId(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateGetConversation: [
        ValidationMiddleware.validateUsernameParam(),
        ValidationMiddleware.validatePagination(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateGetPublicKeys: [
        ValidationMiddleware.validateUsernameParam(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateGetInbox: [
        ValidationMiddleware.validatePagination(),
        ValidationMiddleware.handleValidationErrors()
      ]
    };
  }
}

module.exports = MessageController;
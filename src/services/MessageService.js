const databaseConfig = require('../config/database');
const encryptionConfig = require('../config/encryption');
const Message = require('../models/Message');

class MessageService {
  constructor() {
    this.redis = null;
    this.messageModel = new Message();
    this.initRedis();
  }

  // Initialize Redis connection
  async initRedis() {
    try {
      this.redis = await databaseConfig.getRedis();
    } catch (error) {
      console.error('Failed to initialize Redis:', error);
      throw error;
    }
  }

  /**
   * Store message in Redis with TTL
   * @param {string} messageId - Unique message identifier
   * @param {Object} encryptedPayload - Encrypted message data
   * @param {number} ttl - Time to live in seconds
   * @returns {Promise<boolean>}
   */
  async storeMessage(messageId, encryptedPayload, ttl) {
    try {
      if (!this.redis) {
        throw new Error('Redis not initialized');
      }

      const messageKey = `message:${messageId}`;
      const messageData = {
        cipherText: encryptedPayload.cipherText,
        signature: encryptedPayload.signature,
        iv: encryptedPayload.iv,
        authTag: encryptedPayload.authTag,
        storedAt: new Date().toISOString()
      };

      // Store message in Redis with TTL
      await this.redis.setEx(
        messageKey,
        ttl,
        JSON.stringify(messageData)
      );

      return true;
    } catch (error) {
      throw new Error('Failed to store message in Redis: ' + error.message);
    }
  }

  /**
   * Retrieve message from Redis
   * @param {string} messageId - Unique message identifier
   * @param {boolean} deleteOnRead - Whether to delete after retrieval (for one-time view)
   * @returns {Promise<Object|null>} Message data or null if not found
   */
  async getMessage(messageId, deleteOnRead = false) {
    try {
      if (!this.redis) {
        throw new Error('Redis not initialized');
      }

      const messageKey = `message:${messageId}`;

      // Get message from Redis
      const messageData = await this.redis.get(messageKey);

      if (!messageData) {
        return null;
      }

      const parsedMessage = JSON.parse(messageData);

      // Delete if one-time view
      if (deleteOnRead) {
        await this.redis.del(messageKey);
      }

      return parsedMessage;
    } catch (error) {
      throw new Error('Failed to retrieve message from Redis: ' + error.message);
    }
  }

  /**
   * Add message to user's inbox tracking
   * @param {string} userId - User ID
   * @param {Object} messageMetadata - Message metadata
   * @param {number} ttl - Time to live for inbox entry
   * @returns {Promise<boolean>}
   */
  async addToUserInbox(userId, messageMetadata, ttl) {
    try {
      if (!this.redis) {
        throw new Error('Redis not initialized');
      }

      const inboxKey = `inbox:${userId}`;
      const messageInfo = {
        messageId: messageMetadata.messageId,
        senderId: messageMetadata.senderId,
        createdAt: messageMetadata.createdAt,
        oneTimeView: messageMetadata.oneTimeView,
        anonymous: messageMetadata.anonymous,
        expiresAt: messageMetadata.expiresAt
      };

      // Add to sorted set with score as expiration timestamp
      const score = new Date(messageMetadata.expiresAt).getTime();
      await this.redis.zAdd(
        inboxKey,
        [{
          score,
          value: JSON.stringify(messageInfo)
        }]
      );

      // Set TTL for inbox key
      await this.redis.expire(inboxKey, Math.min(ttl, 7 * 24 * 60 * 60)); // Max 7 days

      return true;
    } catch (error) {
      throw new Error('Failed to add message to user inbox: ' + error.message);
    }
  }

  /**
   * Get user's inbox messages
   * @param {string} userId - User ID
   * @param {number} limit - Maximum number of messages to retrieve
   * @param {number} offset - Offset for pagination
   * @returns {Promise<Array>} Array of message metadata
   */
  async getUserInbox(userId, limit = 50, offset = 0) {
    try {
      if (!this.redis) {
        throw new Error('Redis not initialized');
      }

      const inboxKey = `inbox:${userId}`;

      // Get messages from sorted set, ordered by expiration time
      const messages = await this.redis.zRangeWithScores(
        inboxKey,
        offset,
        offset + limit - 1,
        {
          REV: true // Get newest first
        }
      );

      return messages.map(item => {
        const metadata = JSON.parse(item.value);
        return {
          ...metadata,
          score: item.score,
          expiresAt: new Date(metadata.expiresAt)
        };
      });
    } catch (error) {
      throw new Error('Failed to get user inbox: ' + error.message);
    }
  }

  /**
   * Remove message from user's inbox
   * @param {string} userId - User ID
   * @param {string} messageId - Message ID to remove
   * @returns {Promise<boolean>}
   */
  async removeFromInbox(userId, messageId) {
    try {
      if (!this.redis) {
        throw new Error('Redis not initialized');
      }

      const inboxKey = `inbox:${userId}`;

      // Get all messages and find matching one
      const messages = await this.redis.zRange(inboxKey, 0, -1);

      for (const messageJson of messages) {
        const message = JSON.parse(messageJson);
        if (message.messageId === messageId) {
          await this.redis.zRem(inboxKey, messageJson);
          return true;
        }
      }

      return false;
    } catch (error) {
      throw new Error('Failed to remove message from inbox: ' + error.message);
    }
  }

  /**
   * Mark message as read and delete if one-time view
   * @param {string} messageId - Message ID
   * @param {string} userId - User ID (for inbox cleanup)
   * @returns {Promise<boolean>}
   */
  async markAsRead(messageId, userId) {
    try {
      // Get message metadata from database
      const metadata = await this.messageModel.getByMessageId(messageId);

      if (!metadata) {
        return false;
      }

      // Mark as read in database
      await this.messageModel.markAsRead(messageId);

      // Remove from user inbox
      await this.removeFromInbox(userId, messageId);

      // Delete from Redis if one-time view
      if (metadata.isOneTimeView) {
        const messageKey = `message:${messageId}`;
        await this.redis.del(messageKey);
        await this.messageModel.markAsDestroyed(messageId);
      }

      return true;
    } catch (error) {
      throw new Error('Failed to mark message as read: ' + error.message);
    }
  }

  /**
   * Cleanup expired messages from Redis
   * @param {number} batchSize - Number of messages to process per batch
   * @returns {Promise<number>} Number of messages cleaned up
   */
  async cleanupExpiredMessages(batchSize = 100) {
    try {
      let cleanedUp = 0;

      // Get expired messages from database metadata
      const expiredMessages = await this.messageModel.getExpiredMessages(batchSize);

      for (const messageInfo of expiredMessages) {
        try {
          const messageKey = `message:${messageInfo.messageId}`;

          // Delete from Redis
          const deleted = await this.redis.del(messageKey);

          if (deleted > 0) {
            cleanedUp++;
          }

          // Mark as expired in database
          await this.messageModel.markAsDestroyed(messageInfo.messageId);
        } catch (error) {
          console.error(`Failed to cleanup message ${messageInfo.messageId}:`, error);
        }
      }

      // Cleanup expired inbox entries
      cleanedUp += await this.cleanupExpiredInboxEntries();

      return cleanedUp;
    } catch (error) {
      throw new Error('Failed to cleanup expired messages: ' + error.message);
    }
  }

  /**
   * Cleanup expired inbox entries
   * @returns {Promise<number>} Number of entries cleaned up
   */
  async cleanupExpiredInboxEntries() {
    try {
      let cleanedUp = 0;
      const currentTime = Date.now();

      // Get all inbox keys
      const keys = await this.redis.keys('inbox:*');

      for (const inboxKey of keys) {
        try {
          // Remove expired entries from sorted set
          const removed = await this.redis.zRemRangeByScore(
            inboxKey,
            0,
            currentTime
          );

          cleanedUp += removed;
        } catch (error) {
          console.error(`Failed to cleanup inbox ${inboxKey}:`, error);
        }
      }

      return cleanedUp;
    } catch (error) {
      throw new Error('Failed to cleanup expired inbox entries: ' + error.message);
    }
  }

  /**
   * Track user WebSocket connections
   * @param {string} userId - User ID
   * @param {string} socketId - Socket ID
   * @returns {Promise<boolean>}
   */
  async trackUserConnection(userId, socketId) {
    try {
      const sessionKey = `sessions:${userId}`;

      // Add socket to user's sessions
      await this.redis.sAdd(sessionKey, socketId);
      await this.redis.expire(sessionKey, 24 * 60 * 60); // 24 hour TTL

      return true;
    } catch (error) {
      throw new Error('Failed to track user connection: ' + error.message);
    }
  }

  /**
   * Remove user WebSocket connection tracking
   * @param {string} userId - User ID
   * @param {string} socketId - Socket ID
   * @returns {Promise<boolean>}
   */
  async removeUserConnection(userId, socketId) {
    try {
      const sessionKey = `sessions:${userId}`;

      // Remove socket from user's sessions
      await this.redis.sRem(sessionKey, socketId);

      return true;
    } catch (error) {
      throw new Error('Failed to remove user connection: ' + error.message);
    }
  }

  /**
   * Get user's active socket connections
   * @param {string} userId - User ID
   * @returns {Promise<Set>} Set of socket IDs
   */
  async getUserConnections(userId) {
    try {
      const sessionKey = `sessions:${userId}`;
      const connections = await this.redis.sMembers(sessionKey);
      return new Set(connections);
    } catch (error) {
      throw new Error('Failed to get user connections: ' + error.message);
    }
  }

  /**
   * Store typing indicator
   * @param {string} userId - User ID
   * @param {string} receiverId - Receiver ID
   * @param {boolean} isTyping - Whether user is typing
   * @returns {Promise<boolean>}
   */
  async setTypingIndicator(userId, receiverId, isTyping) {
    try {
      const typingKey = `typing:${receiverId}:${userId}`;

      if (isTyping) {
        // Set typing indicator with 5 second TTL
        await this.redis.setEx(typingKey, 5, '1');
      } else {
        // Remove typing indicator
        await this.redis.del(typingKey);
      }

      return true;
    } catch (error) {
      throw new Error('Failed to set typing indicator: ' + error.message);
    }
  }

  /**
   * Get typing indicators for a user
   * @param {string} userId - User ID
   * @returns {Promise<Set>} Set of user IDs who are typing
   */
  async getTypingIndicators(userId) {
    try {
      const pattern = `typing:${userId}:*`;
      const keys = await this.redis.keys(pattern);
      const typingUsers = new Set();

      for (const key of keys) {
        const typingUserId = key.split(':')[2];
        typingUsers.add(typingUserId);
      }

      return typingUsers;
    } catch (error) {
      throw new Error('Failed to get typing indicators: ' + error.message);
    }
  }

  /**
   * Get Redis statistics
   * @returns {Promise<Object>} Redis usage statistics
   */
  async getRedisStats() {
    try {
      const info = await this.redis.info();
      const memoryInfo = await this.redis.info('memory');

      // Parse Redis info
      const stats = {
        connectedClients: 0,
        usedMemory: 0,
        totalCommands: 0,
        keyspaceHits: 0,
        keyspaceMisses: 0
      };

      // Extract key metrics from INFO output
      const lines = info.split('\r\n');
      for (const line of lines) {
        if (line.includes('connected_clients:')) {
          stats.connectedClients = parseInt(line.split(':')[1]);
        } else if (line.includes('total_commands_processed:')) {
          stats.totalCommands = parseInt(line.split(':')[1]);
        } else if (line.includes('keyspace_hits:')) {
          stats.keyspaceHits = parseInt(line.split(':')[1]);
        } else if (line.includes('keyspace_misses:')) {
          stats.keyspaceMisses = parseInt(line.split(':')[1]);
        }
      }

      // Extract memory info
      const memoryLines = memoryInfo.split('\r\n');
      for (const line of memoryLines) {
        if (line.includes('used_memory_human:')) {
          stats.usedMemoryHuman = line.split(':')[1];
        } else if (line.includes('used_memory:')) {
          stats.usedMemory = parseInt(line.split(':')[1]);
        }
      }

      // Count DarkChat specific keys
      const messageKeys = await this.redis.keys('message:*');
      const inboxKeys = await this.redis.keys('inbox:*');
      const sessionKeys = await this.redis.keys('sessions:*');
      const typingKeys = await this.redis.keys('typing:*');

      stats.darkChatKeys = {
        messages: messageKeys.length,
        inboxes: inboxKeys.length,
        sessions: sessionKeys.length,
        typing: typingKeys.length,
        total: messageKeys.length + inboxKeys.length + sessionKeys.length + typingKeys.length
      };

      return stats;
    } catch (error) {
      throw new Error('Failed to get Redis stats: ' + error.message);
    }
  }

  /**
   * Flush all DarkChat related keys (for testing or emergency)
   * @returns {Promise<number>} Number of keys deleted
   */
  async flushDarkChatKeys() {
    try {
      const patterns = ['message:*', 'inbox:*', 'sessions:*', 'typing:*'];
      let totalDeleted = 0;

      for (const pattern of patterns) {
        const keys = await this.redis.keys(pattern);
        if (keys.length > 0) {
          const deleted = await this.redis.del(keys);
          totalDeleted += deleted;
        }
      }

      return totalDeleted;
    } catch (error) {
      throw new Error('Failed to flush DarkChat keys: ' + error.message);
    }
  }

  /**
   * Validate message data structure
   * @param {Object} messageData - Message data to validate
   * @returns {boolean} True if valid
   */
  validateMessageData(messageData) {
    try {
      const requiredFields = ['cipherText', 'signature', 'iv', 'authTag'];

      for (const field of requiredFields) {
        if (!messageData[field] || typeof messageData[field] !== 'string') {
          return false;
        }
      }

      // Validate base64 format
      const base64Fields = ['cipherText', 'signature', 'iv', 'authTag'];
      const base64Pattern = /^[A-Za-z0-9+/=]+$/;

      for (const field of base64Fields) {
        if (!base64Pattern.test(messageData[field])) {
          return false;
        }
      }

      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate unique message ID
   * @returns {string} Unique message identifier
   */
  generateMessageId() {
    return encryptionConfig.generateMessageId();
  }

  /**
   * Calculate TTL for message storage
   * @param {Date} expiresAt - Expiration date
   * @returns {number} TTL in seconds
   */
  calculateTTL(expiresAt) {
    try {
      const now = new Date();
      const expiration = new Date(expiresAt);
      const diffMs = expiration.getTime() - now.getTime();

      if (diffMs <= 0) {
        return 60; // Minimum 1 minute
      }

      return Math.floor(diffMs / 1000);
    } catch (error) {
      return 300; // Default 5 minutes
    }
  }
}

module.exports = MessageService;
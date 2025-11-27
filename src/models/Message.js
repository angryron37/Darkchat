const databaseConfig = require('../config/database');
const { v4: uuidv4 } = require('uuid');
const encryptionConfig = require('../config/encryption');

class Message {
  constructor() {
    this.db = databaseConfig.getKnex();
  }

  // Create message metadata record
  async createMetadata(senderId, receiverId, messageId, encryptedAesKey, expiresAt, oneTimeView = false, anonymous = false) {
    try {
      // Validate inputs
      if (!senderId || !receiverId || !messageId || !encryptedAesKey || !expiresAt) {
        throw new Error('Missing required fields for message metadata');
      }

      // Validate expiration date
      const expiryDate = new Date(expiresAt);
      if (expiryDate <= new Date()) {
        throw new Error('Expiration time must be in the future');
      }

      // Check that expiration is not too far in the future
      const maxExpiration = new Date();
      maxExpiration.setDate(maxExpiration.getDate() + 7);
      if (expiryDate > maxExpiration) {
        throw new Error('Message cannot expire more than 7 days from now');
      }

      const [metadata] = await this.db('messages_metadata')
        .insert({
          id: uuidv4(),
          sender_id: senderId,
          receiver_id: receiverId,
          message_id: messageId,
          encrypted_aes_key: encryptedAesKey.trim(),
          expires_at: expiryDate,
          one_time_view: oneTimeView,
          anonymous,
          created_at: new Date(),
          status: 'delivered'
        })
        .returning('*');

      return this.sanitizeMetadata(metadata);
    } catch (error) {
      if (error.code === '23505') { // Unique constraint violation
        throw new Error('Message ID already exists');
      }
      throw new Error('Failed to create message metadata: ' + error.message);
    }
  }

  // Get message metadata by message ID
  async getByMessageId(messageId) {
    try {
      const metadata = await this.db('messages_metadata')
        .where('message_id', messageId)
        .first();

      return metadata ? this.sanitizeMetadata(metadata) : null;
    } catch (error) {
      throw new Error('Failed to get message metadata: ' + error.message);
    }
  }

  // Update message status
  async updateStatus(messageId, status) {
    try {
      const validStatuses = ['delivered', 'read', 'destroyed', 'expired'];
      if (!validStatuses.includes(status)) {
        throw new Error('Invalid message status');
      }

      const result = await this.db('messages_metadata')
        .where('message_id', messageId)
        .update({
          status,
          updated_at: new Date()
        });

      return result > 0;
    } catch (error) {
      throw new Error('Failed to update message status: ' + error.message);
    }
  }

  // Mark message as read
  async markAsRead(messageId) {
    try {
      const result = await this.db('messages_metadata')
        .where('message_id', messageId)
        .update({
          status: 'read',
          read_at: new Date()
        });

      return result > 0;
    } catch (error) {
      throw new Error('Failed to mark message as read: ' + error.message);
    }
  }

  // Mark message as destroyed
  async markAsDestroyed(messageId) {
    try {
      const result = await this.db('messages_metadata')
        .where('message_id', messageId)
        .update({
          status: 'destroyed',
          destroyed_at: new Date()
        });

      return result > 0;
    } catch (error) {
      throw new Error('Failed to mark message as destroyed: ' + error.message);
    }
  }

  // Get expired messages for cleanup
  async getExpiredMessages(limit = 100) {
    try {
      const messages = await this.db('messages_metadata')
        .where('expires_at', '<', new Date())
        .where('status', '!=', 'expired')
        .select('message_id', 'expires_at')
        .limit(limit);

      return messages.map(msg => ({
        messageId: msg.message_id,
        expiredAt: msg.expires_at
      }));
    } catch (error) {
      throw new Error('Failed to get expired messages: ' + error.message);
    }
  }

  // Mark expired messages
  async markExpiredMessages() {
    try {
      const result = await this.db('messages_metadata')
        .where('expires_at', '<', new Date())
        .where('status', '!=', 'expired')
        .update({
          status: 'expired',
          expired_at: new Date()
        });

      return result;
    } catch (error) {
      throw new Error('Failed to mark expired messages: ' + error.message);
    }
  }

  // Get messages for a user (sent or received)
  async getMessagesForUser(userId, limit = 50, offset = 0, status = null) {
    try {
      let query = this.db('messages_metadata')
        .where('sender_id', userId)
        .orWhere('receiver_id', userId)
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset);

      if (status) {
        query = query.where('status', status);
      }

      const messages = await query.select('*');

      return messages.map(msg => ({
        id: msg.id,
        messageId: msg.message_id,
        isSender: msg.sender_id === userId,
        isReceiver: msg.receiver_id === userId,
        status: msg.status,
        isOneTimeView: msg.one_time_view,
        isAnonymous: msg.anonymous,
        createdAt: msg.created_at,
        expiresAt: msg.expires_at,
        readAt: msg.read_at,
        destroyedAt: msg.destroyed_at
      }));
    } catch (error) {
      throw new Error('Failed to get messages for user: ' + error.message);
    }
  }

  // Get sent messages for a user
  async getSentMessages(userId, limit = 50, offset = 0) {
    try {
      const messages = await this.db('messages_metadata')
        .where('sender_id', userId)
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset)
        .select('*');

      return messages.map(msg => this.sanitizeMetadata(msg));
    } catch (error) {
      throw new Error('Failed to get sent messages: ' + error.message);
    }
  }

  // Get received messages for a user
  async getReceivedMessages(userId, limit = 50, offset = 0) {
    try {
      const messages = await this.db('messages_metadata')
        .where('receiver_id', userId)
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset)
        .select('*');

      return messages.map(msg => this.sanitizeMetadata(msg));
    } catch (error) {
      throw new Error('Failed to get received messages: ' + error.message);
    }
  }

  // Get unread messages for a user
  async getUnreadMessages(userId, limit = 50) {
    try {
      const messages = await this.db('messages_metadata')
        .where('receiver_id', userId)
        .where('status', 'delivered')
        .where('expires_at', '>', new Date())
        .orderBy('created_at', 'desc')
        .limit(limit)
        .select('*');

      return messages.map(msg => this.sanitizeMetadata(msg));
    } catch (error) {
      throw new Error('Failed to get unread messages: ' + error.message);
    }
  }

  // Get message count statistics for a user
  async getMessageStats(userId) {
    try {
      const [stats] = await this.db('messages_metadata')
        .where('sender_id', userId)
        .orWhere('receiver_id', userId)
        .select(
          this.db.raw('COUNT(*) as total_messages'),
          this.db.raw('COUNT(CASE WHEN sender_id = ? THEN 1 END) as sent_messages', [userId]),
          this.db.raw('COUNT(CASE WHEN receiver_id = ? THEN 1 END) as received_messages', [userId]),
          this.db.raw('COUNT(CASE WHEN status = \'read\' THEN 1 END) as read_messages'),
          this.db.raw('COUNT(CASE WHEN status = \'delivered\' THEN 1 END) as unread_messages'),
          this.db.raw('COUNT(CASE WHEN one_time_view = true THEN 1 END) as one_time_messages'),
          this.db.raw('COUNT(CASE WHEN anonymous = true THEN 1 END) as anonymous_messages')
        );

      return {
        totalMessages: parseInt(stats.total_messages) || 0,
        sentMessages: parseInt(stats.sent_messages) || 0,
        receivedMessages: parseInt(stats.received_messages) || 0,
        readMessages: parseInt(stats.read_messages) || 0,
        unreadMessages: parseInt(stats.unread_messages) || 0,
        oneTimeMessages: parseInt(stats.one_time_messages) || 0,
        anonymousMessages: parseInt(stats.anonymous_messages) || 0
      };
    } catch (error) {
      throw new Error('Failed to get message stats: ' + error.message);
    }
  }

  // Delete message metadata
  async delete(messageId) {
    try {
      const deleted = await this.db('messages_metadata')
        .where('message_id', messageId)
        .del();

      return deleted > 0;
    } catch (error) {
      throw new Error('Failed to delete message metadata: ' + error.message);
    }
  }

  // Delete all messages for a user
  async deleteAllUserMessages(userId) {
    try {
      const deleted = await this.db('messages_metadata')
        .where('sender_id', userId)
        .orWhere('receiver_id', userId)
        .del();

      return deleted;
    } catch (error) {
      throw new Error('Failed to delete user messages: ' + error.message);
    }
  }

  // Get conversation between two users
  async getConversation(user1Id, user2Id, limit = 50, offset = 0) {
    try {
      const messages = await this.db('messages_metadata')
        .where((builder) => {
          builder.where('sender_id', user1Id).andWhere('receiver_id', user2Id);
        })
        .orWhere((builder) => {
          builder.where('sender_id', user2Id).andWhere('receiver_id', user1Id);
        })
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset)
        .select('*');

      return messages.map(msg => ({
        id: msg.id,
        messageId: msg.message_id,
        isSender: msg.sender_id === user1Id,
        isReceiver: msg.receiver_id === user1Id,
        status: msg.status,
        isOneTimeView: msg.one_time_view,
        isAnonymous: msg.anonymous,
        createdAt: msg.created_at,
        expiresAt: msg.expires_at
      })).reverse(); // Return in chronological order
    } catch (error) {
      throw new Error('Failed to get conversation: ' + error.message);
    }
  }

  // Get message metadata by status
  async getMessagesByStatus(status, limit = 100) {
    try {
      const messages = await this.db('messages_metadata')
        .where('status', status)
        .orderBy('created_at', 'desc')
        .limit(limit)
        .select('*');

      return messages.map(msg => this.sanitizeMetadata(msg));
    } catch (error) {
      throw new Error('Failed to get messages by status: ' + error.message);
    }
  }

  // Check if user has received messages from another user
  async hasMessagesBetween(user1Id, user2Id) {
    try {
      const result = await this.db('messages_metadata')
        .where((builder) => {
          builder.where('sender_id', user1Id).andWhere('receiver_id', user2Id);
        })
        .orWhere((builder) => {
          builder.where('sender_id', user2Id).andWhere('receiver_id', user1Id);
        })
        .first();

      return !!result;
    } catch (error) {
      throw new Error('Failed to check messages between users: ' + error.message);
    }
  }

  // Clean up old message metadata
  async cleanupOldMetadata(daysOld = 30) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysOld);

      const deleted = await this.db('messages_metadata')
        .where('created_at', '<', cutoffDate)
        .whereIn('status', ['expired', 'destroyed'])
        .del();

      return deleted;
    } catch (error) {
      throw new Error('Failed to cleanup old metadata: ' + error.message);
    }
  }

  // Get system-wide message statistics
  async getSystemStats() {
    try {
      const [stats] = await this.db('messages_metadata')
        .select(
          this.db.raw('COUNT(*) as total_messages'),
          this.db.raw('COUNT(CASE WHEN status = \'delivered\' THEN 1 END) as delivered_messages'),
          this.db.raw('COUNT(CASE WHEN status = \'read\' THEN 1 END) as read_messages'),
          this.db.raw('COUNT(CASE WHEN status = \'destroyed\' THEN 1 END) as destroyed_messages'),
          this.db.raw('COUNT(CASE WHEN status = \'expired\' THEN 1 END) as expired_messages'),
          this.db.raw('COUNT(CASE WHEN one_time_view = true THEN 1 END) as one_time_messages'),
          this.db.raw('COUNT(CASE WHEN anonymous = true THEN 1 END) as anonymous_messages'),
          this.db.raw('COUNT(CASE WHEN created_at > NOW() - INTERVAL \'24 hours\' THEN 1 END) as messages_today'),
          this.db.raw('COUNT(CASE WHEN expires_at > NOW() THEN 1 END) as active_messages')
        )
        .first();

      return {
        totalMessages: parseInt(stats.total_messages) || 0,
        deliveredMessages: parseInt(stats.delivered_messages) || 0,
        readMessages: parseInt(stats.read_messages) || 0,
        destroyedMessages: parseInt(stats.destroyed_messages) || 0,
        expiredMessages: parseInt(stats.expired_messages) || 0,
        oneTimeMessages: parseInt(stats.one_time_messages) || 0,
        anonymousMessages: parseInt(stats.anonymous_messages) || 0,
        messagesToday: parseInt(stats.messages_today) || 0,
        activeMessages: parseInt(stats.active_messages) || 0
      };
    } catch (error) {
      throw new Error('Failed to get system stats: ' + error.message);
    }
  }

  // Generate unique message ID
  generateMessageId() {
    return encryptionConfig.generateMessageId();
  }

  // Validate message ID format
  validateMessageId(messageId) {
    if (!messageId || typeof messageId !== 'string') {
      return false;
    }

    // Check for base64 format with reasonable length
    const base64Pattern = /^[A-Za-z0-9+/=]+$/;
    return base64Pattern.test(messageId) &&
           messageId.length >= 16 &&
           messageId.length <= 100;
  }

  // Validate expiration time
  validateExpirationTime(expiresIn) {
    if (!expiresIn || typeof expiresIn !== 'number') {
      return false;
    }

    const minSeconds = 60; // 1 minute
    const maxSeconds = 7 * 24 * 60 * 60; // 7 days

    return expiresIn >= minSeconds && expiresIn <= maxSeconds;
  }

  // Sanitize metadata object before returning
  sanitizeMetadata(metadata) {
    if (!metadata) return null;

    return {
      id: metadata.id,
      messageId: metadata.message_id,
      senderId: metadata.sender_id,
      receiverId: metadata.receiver_id,
      encryptedAesKey: metadata.encrypted_aes_key,
      expiresAt: metadata.expires_at,
      isOneTimeView: metadata.one_time_view,
      isAnonymous: metadata.anonymous,
      status: metadata.status,
      createdAt: metadata.created_at,
      readAt: metadata.read_at,
      destroyedAt: metadata.destroyed_at
    };
  }
}

module.exports = Message;
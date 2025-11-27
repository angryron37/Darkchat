const databaseConfig = require('../config/database');
const { v4: uuidv4 } = require('uuid');

class User {
  constructor() {
    this.db = databaseConfig.getKnex();
  }

  // Create a new user with username
  async create(username) {
    try {
      const [user] = await this.db('users')
        .insert({
          id: uuidv4(),
          username: username.toLowerCase().trim(),
          created_at: new Date(),
          last_seen: new Date(),
          status: 'online'
        })
        .returning('*');

      return this.sanitizeUser(user);
    } catch (error) {
      if (error.code === '23505') { // Unique constraint violation
        throw new Error('Username already exists');
      }
      throw new Error('Failed to create user: ' + error.message);
    }
  }

  // Find user by username
  async findByUsername(username) {
    try {
      const user = await this.db('users')
        .where('username', username.toLowerCase().trim())
        .first();

      return user ? this.sanitizeUser(user) : null;
    } catch (error) {
      throw new Error('Failed to find user: ' + error.message);
    }
  }

  // Find user by ID
  async getById(userId) {
    try {
      const user = await this.db('users')
        .where('id', userId)
        .first();

      return user ? this.sanitizeUser(user) : null;
    } catch (error) {
      throw new Error('Failed to find user: ' + error.message);
    }
  }

  // Get user by username or create if doesn't exist
  async findOrCreate(username) {
    try {
      // First try to find the user
      let user = await this.findByUsername(username);

      // If user doesn't exist, create them
      if (!user) {
        user = await this.create(username);
      }

      return user;
    } catch (error) {
      throw new Error('Failed to find or create user: ' + error.message);
    }
  }

  // Update user's last seen timestamp
  async updateLastSeen(userId, status = null) {
    try {
      const updateData = {
        last_seen: new Date()
      };

      if (status) {
        updateData.status = status;
      }

      await this.db('users')
        .where('id', userId)
        .update(updateData);

      return true;
    } catch (error) {
      throw new Error('Failed to update last seen: ' + error.message);
    }
  }

  // Update user status
  async updateStatus(userId, status) {
    try {
      const validStatuses = ['online', 'away', 'busy', 'offline'];
      if (!validStatuses.includes(status)) {
        throw new Error('Invalid status');
      }

      await this.db('users')
        .where('id', userId)
        .update({
          status,
          last_seen: new Date()
        });

      return true;
    } catch (error) {
      throw new Error('Failed to update status: ' + error.message);
    }
  }

  // Get all active users (for chat list)
  async getAllActive(limit = 100, offset = 0) {
    try {
      const users = await this.db('users')
        .select('id', 'username', 'status', 'last_seen')
        .orderBy('last_seen', 'desc')
        .limit(limit)
        .offset(offset);

      return users.map(user => this.sanitizeUser(user));
    } catch (error) {
      throw new Error('Failed to get active users: ' + error.message);
    }
  }

  // Search users by username
  async searchByUsername(query, limit = 20) {
    try {
      const users = await this.db('users')
        .select('id', 'username', 'status', 'last_seen')
        .where('username', 'ilike', `%${query.toLowerCase()}%`)
        .orderBy('last_seen', 'desc')
        .limit(limit);

      return users.map(user => this.sanitizeUser(user));
    } catch (error) {
      throw new Error('Failed to search users: ' + error.message);
    }
  }

  // Check if username exists
  async usernameExists(username) {
    try {
      const result = await this.db('users')
        .where('username', username.toLowerCase().trim())
        .first();

      return !!result;
    } catch (error) {
      throw new Error('Failed to check username: ' + error.message);
    }
  }

  // Get user statistics
  async getUserStats(userId) {
    try {
      const [messageStats] = await this.db('messages_metadata')
        .where('sender_id', userId)
        .orWhere('receiver_id', userId)
        .select(
          this.db.raw('COUNT(*) as total_messages'),
          this.db.raw('COUNT(CASE WHEN sender_id = ? THEN 1 END) as sent_messages', [userId]),
          this.db.raw('COUNT(CASE WHEN receiver_id = ? THEN 1 END) as received_messages', [userId]),
          this.db.raw('COUNT(CASE WHEN created_at > NOW() - INTERVAL \'24 hours\' THEN 1 END) as messages_today', [userId])
        );

      const deviceCount = await this.db('device_sessions')
        .where('user_id', userId)
        .count('* as count')
        .first();

      return {
        totalMessages: parseInt(messageStats.total_messages) || 0,
        sentMessages: parseInt(messageStats.sent_messages) || 0,
        receivedMessages: parseInt(messageStats.received_messages) || 0,
        messagesToday: parseInt(messageStats.messages_today) || 0,
        deviceCount: parseInt(deviceCount.count) || 0
      };
    } catch (error) {
      throw new Error('Failed to get user stats: ' + error.message);
    }
  }

  // Get user's recent activity
  async getRecentActivity(userId, limit = 10) {
    try {
      const messages = await this.db('messages_metadata')
        .where('sender_id', userId)
        .orWhere('receiver_id', userId)
        .select(
          'id',
          'sender_id',
          'receiver_id',
          'message_id',
          'one_time_view',
          'anonymous',
          'created_at',
          'status'
        )
        .orderBy('created_at', 'desc')
        .limit(limit);

      return messages.map(msg => ({
        id: msg.id,
        messageId: msg.message_id,
        isSender: msg.sender_id === userId,
        isAnonymous: msg.anonymous,
        isOneTimeView: msg.one_time_view,
        createdAt: msg.created_at,
        status: msg.status
      }));
    } catch (error) {
      throw new Error('Failed to get recent activity: ' + error.message);
    }
  }

  // Clean up old inactive users
  async cleanupInactiveUsers(daysInactive = 30) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysInactive);

      const deleted = await this.db('users')
        .where('last_seen', '<', cutoffDate)
        .where('status', 'offline')
        .del();

      return deleted;
    } catch (error) {
      throw new Error('Failed to cleanup inactive users: ' + error.message);
    }
  }

  // Update user's login timestamp
  async updateLoginTime(userId) {
    try {
      await this.db('users')
        .where('id', userId)
        .update({
          last_seen: new Date(),
          status: 'online'
        });

      return true;
    } catch (error) {
      throw new Error('Failed to update login time: ' + error.message);
    }
  }

  // Delete user account
  async delete(userId) {
    try {
      await this.db.transaction(async (trx) => {
        // Delete device sessions
        await trx('device_sessions')
          .where('user_id', userId)
          .del();

        // Delete message metadata where user is sender or receiver
        await trx('messages_metadata')
          .where('sender_id', userId)
          .orWhere('receiver_id', userId)
          .del();

        // Delete user
        await trx('users')
          .where('id', userId)
          .del();
      });

      return true;
    } catch (error) {
      throw new Error('Failed to delete user: ' + error.message);
    }
  }

  // Validate username format
  validateUsername(username) {
    if (!username || typeof username !== 'string') {
      return false;
    }

    const trimmed = username.trim();
    const minLength = 2;
    const maxLength = 50;
    const validPattern = /^[a-zA-Z0-9_]+$/;

    return trimmed.length >= minLength &&
           trimmed.length <= maxLength &&
           validPattern.test(trimmed);
  }

  // Sanitize user object before returning
  sanitizeUser(user) {
    if (!user) return null;

    return {
      id: user.id,
      username: user.username,
      status: user.status,
      lastSeen: user.last_seen,
      createdAt: user.created_at
    };
  }

  // Get user count
  async getTotalUsers() {
    try {
      const result = await this.db('users')
        .count('* as count')
        .first();

      return parseInt(result.count) || 0;
    } catch (error) {
      throw new Error('Failed to get user count: ' + error.message);
    }
  }

  // Get active user count (users active in last 24 hours)
  async getActiveUserCount() {
    try {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      const result = await this.db('users')
        .where('last_seen', '>', yesterday)
        .count('* as count')
        .first();

      return parseInt(result.count) || 0;
    } catch (error) {
      throw new Error('Failed to get active user count: ' + error.message);
    }
  }
}

module.exports = User;
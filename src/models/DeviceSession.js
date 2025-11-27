const databaseConfig = require('../config/database');
const { v4: uuidv4 } = require('uuid');
const encryptionConfig = require('../config/encryption');

class DeviceSession {
  constructor() {
    this.db = databaseConfig.getKnex();
  }

  // Create a new device session
  async create(userId, deviceFingerprint, publicKey) {
    try {
      // Validate inputs
      if (!userId || !deviceFingerprint || !publicKey) {
        throw new Error('Missing required fields for device session');
      }

      // Validate public key format
      if (!this.validatePublicKey(publicKey)) {
        throw new Error('Invalid public key format');
      }

      const [deviceSession] = await this.db('device_sessions')
        .insert({
          id: uuidv4(),
          user_id: userId,
          device_fingerprint: deviceFingerprint,
          public_key: publicKey.trim(),
          created_at: new Date(),
          last_active: new Date()
        })
        .returning('*');

      return this.sanitizeDeviceSession(deviceSession);
    } catch (error) {
      if (error.code === '23505') { // Unique constraint violation
        throw new Error('Device already registered');
      }
      throw new Error('Failed to create device session: ' + error.message);
    }
  }

  // Find device session by fingerprint
  async findByDeviceFingerprint(fingerprint) {
    try {
      const deviceSession = await this.db('device_sessions')
        .where('device_fingerprint', fingerprint)
        .first();

      return deviceSession ? this.sanitizeDeviceSession(deviceSession) : null;
    } catch (error) {
      throw new Error('Failed to find device session: ' + error.message);
    }
  }

  // Find device session by user ID and fingerprint
  async findByUserAndFingerprint(userId, fingerprint) {
    try {
      const deviceSession = await this.db('device_sessions')
        .where({
          user_id: userId,
          device_fingerprint: fingerprint
        })
        .first();

      return deviceSession ? this.sanitizeDeviceSession(deviceSession) : null;
    } catch (error) {
      throw new Error('Failed to find device session: ' + error.message);
    }
  }

  // Get device session by ID
  async getById(sessionId) {
    try {
      const deviceSession = await this.db('device_sessions')
        .where('id', sessionId)
        .first();

      return deviceSession ? this.sanitizeDeviceSession(deviceSession) : null;
    } catch (error) {
      throw new Error('Failed to find device session: ' + error.message);
    }
  }

  // Update last active timestamp
  async updateLastActive(sessionId) {
    try {
      const result = await this.db('device_sessions')
        .where('id', sessionId)
        .update({
          last_active: new Date()
        });

      return result > 0;
    } catch (error) {
      throw new Error('Failed to update last active: ' + error.message);
    }
  }

  // Update last active by fingerprint
  async updateLastActiveByFingerprint(fingerprint) {
    try {
      const result = await this.db('device_sessions')
        .where('device_fingerprint', fingerprint)
        .update({
          last_active: new Date()
        });

      return result > 0;
    } catch (error) {
      throw new Error('Failed to update last active: ' + error.message);
    }
  }

  // Get all public keys for a user
  async getPublicKeysByUserId(userId) {
    try {
      const deviceSessions = await this.db('device_sessions')
        .where('user_id', userId)
        .select('id', 'public_key', 'device_fingerprint', 'created_at', 'last_active')
        .orderBy('last_active', 'desc');

      return deviceSessions.map(session => ({
        id: session.id,
        publicKey: session.public_key,
        deviceFingerprint: session.device_fingerprint,
        createdAt: session.created_at,
        lastActive: session.last_active
      }));
    } catch (error) {
      throw new Error('Failed to get public keys: ' + error.message);
    }
  }

  // Get the most recent public key for a user
  async getLatestPublicKey(userId) {
    try {
      const deviceSession = await this.db('device_sessions')
        .where('user_id', userId)
        .orderBy('last_active', 'desc')
        .first();

      return deviceSession ? deviceSession.public_key : null;
    } catch (error) {
      throw new Error('Failed to get latest public key: ' + error.message);
    }
  }

  // Get all device sessions for a user
  async getDevicesByUserId(userId, limit = 10) {
    try {
      const deviceSessions = await this.db('device_sessions')
        .where('user_id', userId)
        .select('id', 'device_fingerprint', 'created_at', 'last_active')
        .orderBy('last_active', 'desc')
        .limit(limit);

      return deviceSessions.map(session => this.sanitizeDeviceSession(session));
    } catch (error) {
      throw new Error('Failed to get devices: ' + error.message);
    }
  }

  // Delete old device sessions
  async deleteOldSessions(userId, maxAge = 30) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - maxAge);

      const deleted = await this.db('device_sessions')
        .where('user_id', userId)
        .where('created_at', '<', cutoffDate)
        .del();

      return deleted;
    } catch (error) {
      throw new Error('Failed to delete old sessions: ' + error.message);
    }
  }

  // Delete specific device session
  async delete(sessionId) {
    try {
      const deleted = await this.db('device_sessions')
        .where('id', sessionId)
        .del();

      return deleted > 0;
    } catch (error) {
      throw new Error('Failed to delete device session: ' + error.message);
    }
  }

  // Delete device session by fingerprint
  async deleteByFingerprint(fingerprint) {
    try {
      const deleted = await this.db('device_sessions')
        .where('device_fingerprint', fingerprint)
        .del();

      return deleted > 0;
    } catch (error) {
      throw new Error('Failed to delete device session: ' + error.message);
    }
  }

  // Delete all device sessions for a user
  async deleteAllByUserId(userId) {
    try {
      const deleted = await this.db('device_sessions')
        .where('user_id', userId)
        .del();

      return deleted;
    } catch (error) {
      throw new Error('Failed to delete all device sessions: ' + error.message);
    }
  }

  // Rotate keys for a device
  async rotateKeys(sessionId, newPublicKey) {
    try {
      // Validate new public key
      if (!this.validatePublicKey(newPublicKey)) {
        throw new Error('Invalid new public key format');
      }

      const result = await this.db('device_sessions')
        .where('id', sessionId)
        .update({
          public_key: newPublicKey.trim(),
          last_active: new Date()
        });

      return result > 0;
    } catch (error) {
      throw new Error('Failed to rotate keys: ' + error.message);
    }
  }

  // Validate device access
  async validateDeviceAccess(userId, deviceFingerprint) {
    try {
      const deviceSession = await this.findByUserAndFingerprint(userId, deviceFingerprint);

      if (!deviceSession) {
        return { valid: false, reason: 'Device not registered' };
      }

      // Check if device is too old (security measure)
      const maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days in milliseconds
      const deviceAge = Date.now() - new Date(deviceSession.createdAt).getTime();

      if (deviceAge > maxAge) {
        return { valid: false, reason: 'Device too old' };
      }

      // Update last active
      await this.updateLastActive(deviceSession.id);

      return { valid: true, deviceSession };
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }

  // Get device statistics
  async getDeviceStats(sessionId) {
    try {
      const deviceSession = await this.db('device_sessions')
        .where('id', sessionId)
        .first();

      if (!deviceSession) {
        return null;
      }

      const messageCount = await this.db('messages_metadata')
        .where('sender_id', deviceSession.user_id)
        .count('* as count')
        .first();

      const daysActive = Math.floor(
        (Date.now() - new Date(deviceSession.created_at).getTime()) / (1000 * 60 * 60 * 24)
      );

      return {
        deviceId: deviceSession.id,
        deviceFingerprint: deviceSession.device_fingerprint,
        createdAt: deviceSession.created_at,
        lastActive: deviceSession.last_active,
        daysActive,
        messageCount: parseInt(messageCount.count) || 0,
        isActive: (Date.now() - new Date(deviceSession.last_active).getTime()) < 24 * 60 * 60 * 1000
      };
    } catch (error) {
      throw new Error('Failed to get device stats: ' + error.message);
    }
  }

  // Clean up inactive devices
  async cleanupInactiveDevices(daysInactive = 60) {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysInactive);

      const deleted = await this.db('device_sessions')
        .where('last_active', '<', cutoffDate)
        .del();

      return deleted;
    } catch (error) {
      throw new Error('Failed to cleanup inactive devices: ' + error.message);
    }
  }

  // Get total device count
  async getTotalDeviceCount() {
    try {
      const result = await this.db('device_sessions')
        .count('* as count')
        .first();

      return parseInt(result.count) || 0;
    } catch (error) {
      throw new Error('Failed to get device count: ' + error.message);
    }
  }

  // Get active device count (devices active in last 24 hours)
  async getActiveDeviceCount() {
    try {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);

      const result = await this.db('device_sessions')
        .where('last_active', '>', yesterday)
        .count('* as count')
        .first();

      return parseInt(result.count) || 0;
    } catch (error) {
      throw new Error('Failed to get active device count: ' + error.message);
    }
  }

  // Validate public key format
  validatePublicKey(publicKey) {
    if (!publicKey || typeof publicKey !== 'string') {
      return false;
    }

    const trimmed = publicKey.trim();

    // Check for PEM format
    if (trimmed.includes('-----BEGIN PUBLIC KEY-----') &&
        trimmed.includes('-----END PUBLIC KEY-----')) {
      return true;
    }

    // Check for base64 format (simplified validation)
    const base64Pattern = /^[A-Za-z0-9+/]+={0,2}$/;
    return base64Pattern.test(trimmed) && trimmed.length > 100;
  }

  // Generate device fingerprint (backup method)
  static generateDeviceFingerprint() {
    return encryptionConfig.generateDeviceFingerprint();
  }

  // Sanitize device session object before returning
  sanitizeDeviceSession(deviceSession) {
    if (!deviceSession) return null;

    return {
      id: deviceSession.id,
      userId: deviceSession.user_id,
      deviceFingerprint: deviceSession.device_fingerprint,
      publicKey: deviceSession.public_key,
      createdAt: deviceSession.created_at,
      lastActive: deviceSession.last_active
    };
  }

  // Check if user has too many devices
  async hasTooManyDevices(userId, maxDevices = 10) {
    try {
      const count = await this.db('device_sessions')
        .where('user_id', userId)
        .count('* as count')
        .first();

      return parseInt(count.count) >= maxDevices;
    } catch (error) {
      throw new Error('Failed to check device count: ' + error.message);
    }
  }

  // Get oldest device for a user
  async getOldestDevice(userId) {
    try {
      const deviceSession = await this.db('device_sessions')
        .where('user_id', userId)
        .orderBy('created_at', 'asc')
        .first();

      return deviceSession ? this.sanitizeDeviceSession(deviceSession) : null;
    } catch (error) {
      throw new Error('Failed to get oldest device: ' + error.message);
    }
  }
}

module.exports = DeviceSession;
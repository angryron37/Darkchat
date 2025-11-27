const User = require('../models/User');
const DeviceSession = require('../models/DeviceSession');
const EncryptionService = require('./EncryptionService');
const encryptionConfig = require('../config/encryption');

class KeyExchangeService {
  constructor() {
    this.userModel = new User();
    this.deviceSessionModel = new DeviceSession();
    this.encryptionService = new EncryptionService();
  }

  /**
   * Register device public key for user
   * @param {string} userId - User ID
   * @param {string} deviceFingerprint - Device fingerprint
   * @param {string} publicKey - PEM formatted RSA public key
   * @returns {Promise<Object>} Device session information
   */
  async registerDevicePublicKey(userId, deviceFingerprint, publicKey) {
    try {
      // Validate inputs
      if (!userId || !deviceFingerprint || !publicKey) {
        throw new Error('All fields are required for device key registration');
      }

      // Validate public key format
      if (!this.encryptionService.validatePublicKey(publicKey)) {
        throw new Error('Invalid public key format');
      }

      // Check if user has too many devices
      const hasTooMany = await this.deviceSessionModel.hasTooManyDevices(userId);
      if (hasTooMany) {
        // Remove oldest device if limit exceeded
        const oldestDevice = await this.deviceSessionModel.getOldestDevice(userId);
        if (oldestDevice) {
          await this.deviceSessionModel.delete(oldestDevice.id);
        }
      }

      // Create or update device session
      let deviceSession = await this.deviceSessionModel.findByUserAndFingerprint(userId, deviceFingerprint);

      if (deviceSession) {
        // Update existing device's public key (key rotation)
        await this.deviceSessionModel.rotateKeys(deviceSession.id, publicKey);
        deviceSession = await this.deviceSessionModel.getById(deviceSession.id);
      } else {
        // Create new device session
        deviceSession = await this.deviceSessionModel.create(userId, deviceFingerprint, publicKey);
      }

      return this.sanitizeDeviceSession(deviceSession);
    } catch (error) {
      throw new Error('Failed to register device public key: ' + error.message);
    }
  }

  /**
   * Get all public keys for a user
   * @param {string} userId - User ID
   * @returns {Promise<Array>} Array of public key information
   */
  async getUserPublicKeys(userId) {
    try {
      if (!userId) {
        throw new Error('User ID is required');
      }

      const deviceSessions = await this.deviceSessionModel.getPublicKeysByUserId(userId);

      return deviceSessions.map(session => ({
        deviceId: session.id,
        publicKey: session.publicKey,
        deviceFingerprint: session.deviceFingerprint,
        createdAt: session.createdAt,
        lastActive: session.lastActive,
        fingerprint: this.encryptionService.generateKeyFingerprint(session.publicKey)
      }));
    } catch (error) {
      throw new Error('Failed to get user public keys: ' + error.message);
    }
  }

  /**
   * Get public keys by username
   * @param {string} username - Username
   * @returns {Promise<Array>} Array of public key information
   */
  async getUserPublicKeysByUsername(username) {
    try {
      if (!username) {
        throw new Error('Username is required');
      }

      // Find user by username
      const user = await this.userModel.findByUsername(username);
      if (!user) {
        throw new Error('User not found');
      }

      return await this.getUserPublicKeys(user.id);
    } catch (error) {
      throw new Error('Failed to get user public keys by username: ' + error.message);
    }
  }

  /**
   * Get the most recent public key for a user
   * @param {string} userId - User ID
   * @returns {Promise<string|null>} PEM formatted public key or null
   */
  async getLatestPublicKey(userId) {
    try {
      if (!userId) {
        throw new Error('User ID is required');
      }

      return await this.deviceSessionModel.getLatestPublicKey(userId);
    } catch (error) {
      throw new Error('Failed to get latest public key: ' + error.message);
    }
  }

  /**
   * Get the most recent public key by username
   * @param {string} username - Username
   * @returns {Promise<string|null>} PEM formatted public key or null
   */
  async getLatestPublicKeyByUsername(username) {
    try {
      if (!username) {
        throw new Error('Username is required');
      }

      // Find user by username
      const user = await this.userModel.findByUsername(username);
      if (!user) {
        return null;
      }

      return await this.getLatestPublicKey(user.id);
    } catch (error) {
      throw new Error('Failed to get latest public key by username: ' + error.message);
    }
  }

  /**
   * Validate device access
   * @param {string} userId - User ID
   * @param {string} deviceFingerprint - Device fingerprint
   * @returns {Promise<Object>} Validation result
   */
  async validateDeviceAccess(userId, deviceFingerprint) {
    try {
      if (!userId || !deviceFingerprint) {
        return { valid: false, reason: 'Missing user ID or device fingerprint' };
      }

      const validation = await this.deviceSessionModel.validateDeviceAccess(userId, deviceFingerprint);

      if (!validation.valid) {
        return validation;
      }

      return {
        valid: true,
        deviceSession: this.sanitizeDeviceSession(validation.deviceSession)
      };
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }

  /**
   * Rotate keys for a device
   * @param {string} userId - User ID
   * @param {string} deviceFingerprint - Device fingerprint
   * @param {string} newPublicKey - New PEM formatted public key
   * @returns {Promise<boolean>} Success status
   */
  async rotateKeys(userId, deviceFingerprint, newPublicKey) {
    try {
      if (!userId || !deviceFingerprint || !newPublicKey) {
        throw new Error('All fields are required for key rotation');
      }

      // Validate new public key
      if (!this.encryptionService.validatePublicKey(newPublicKey)) {
        throw new Error('Invalid new public key format');
      }

      // Find device session
      const deviceSession = await this.deviceSessionModel.findByUserAndFingerprint(userId, deviceFingerprint);
      if (!deviceSession) {
        throw new Error('Device not found');
      }

      // Rotate keys
      const success = await this.deviceSessionModel.rotateKeys(deviceSession.id, newPublicKey);

      if (!success) {
        throw new Error('Key rotation failed');
      }

      return true;
    } catch (error) {
      throw new Error('Failed to rotate keys: ' + error.message);
    }
  }

  /**
   * Revoke device access
   * @param {string} userId - User ID
   * @param {string} deviceFingerprint - Device fingerprint
   * @returns {Promise<boolean>} Success status
   */
  async revokeDevice(userId, deviceFingerprint) {
    try {
      if (!userId || !deviceFingerprint) {
        throw new Error('User ID and device fingerprint are required');
      }

      // Find and delete device session
      const deviceSession = await this.deviceSessionModel.findByUserAndFingerprint(userId, deviceFingerprint);
      if (!deviceSession) {
        throw new Error('Device not found');
      }

      const success = await this.deviceSessionModel.delete(deviceSession.id);

      if (!success) {
        throw new Error('Device revocation failed');
      }

      return true;
    } catch (error) {
      throw new Error('Failed to revoke device: ' + error.message);
    }
  }

  /**
   * Revoke all devices for a user
   * @param {string} userId - User ID
   * @returns {Promise<number>} Number of devices revoked
   */
  async revokeAllDevices(userId) {
    try {
      if (!userId) {
        throw new Error('User ID is required');
      }

      return await this.deviceSessionModel.deleteAllByUserId(userId);
    } catch (error) {
      throw new Error('Failed to revoke all devices: ' + error.message);
    }
  }

  /**
   * Get device information
   * @param {string} userId - User ID
   * @param {string} deviceFingerprint - Device fingerprint
   * @returns {Promise<Object|null>} Device information
   */
  async getDeviceInfo(userId, deviceFingerprint) {
    try {
      if (!userId || !deviceFingerprint) {
        throw new Error('User ID and device fingerprint are required');
      }

      const deviceSession = await this.deviceSessionModel.findByUserAndFingerprint(userId, deviceFingerprint);
      if (!deviceSession) {
        return null;
      }

      // Get additional device statistics
      const stats = await this.deviceSessionModel.getDeviceStats(deviceSession.id);

      return {
        ...this.sanitizeDeviceSession(deviceSession),
        ...stats,
        keyFingerprint: this.encryptionService.generateKeyFingerprint(deviceSession.publicKey)
      };
    } catch (error) {
      throw new Error('Failed to get device info: ' + error.message);
    }
  }

  /**
   * Get all devices for a user
   * @param {string} userId - User ID
   * @param {number} limit - Maximum number of devices to return
   * @returns {Promise<Array>} Array of device information
   */
  async getUserDevices(userId, limit = 10) {
    try {
      if (!userId) {
        throw new Error('User ID is required');
      }

      const deviceSessions = await this.deviceSessionModel.getDevicesByUserId(userId, limit);

      const devices = [];
      for (const session of deviceSessions) {
        const stats = await this.deviceSessionModel.getDeviceStats(session.id);
        devices.push({
          ...session,
          ...stats,
          keyFingerprint: this.encryptionService.generateKeyFingerprint(session.publicKey)
        });
      }

      return devices;
    } catch (error) {
      throw new Error('Failed to get user devices: ' + error.message);
    }
  }

  /**
   * Validate public key strength and format
   * @param {string} publicKey - PEM formatted public key
   * @returns {Promise<Object>} Validation result
   */
  async validatePublicKeyStrength(publicKey) {
    try {
      if (!publicKey) {
        return { valid: false, reason: 'Public key is required' };
      }

      // Basic format validation
      if (!this.encryptionService.validatePublicKey(publicKey)) {
        return { valid: false, reason: 'Invalid public key format' };
      }

      // Generate test key pair for comparison
      const testKeyPair = await this.encryptionService.generateRSAKeyPair();

      // Test encryption/decryption with the public key
      const testData = 'test-data-for-validation';
      const encrypted = this.encryptionService.encryptWithRSA(testData, publicKey);

      // Note: We can't test decryption without the private key
      // But we can verify the encrypted data is valid base64
      const isBase64 = /^[A-Za-z0-9+/=]+$/.test(encrypted);
      if (!isBase64) {
        return { valid: false, reason: 'Public key encryption test failed' };
      }

      // Generate key fingerprint
      const fingerprint = this.encryptionService.generateKeyFingerprint(publicKey);

      return {
        valid: true,
        fingerprint,
        keySize: encryptionConfig.get('rsa.keySize'),
        algorithm: 'RSA-OAEP',
        hash: 'SHA-256'
      };
    } catch (error) {
      return { valid: false, reason: error.message };
    }
  }

  /**
   * Generate secure device fingerprint
   * @param {Object} deviceInfo - Device information for entropy
   * @returns {string} Device fingerprint
   */
  static generateSecureDeviceFingerprint(deviceInfo = {}) {
    try {
      const crypto = require('crypto');
      const {
        userAgent = '',
        acceptLanguage = '',
        platform = '',
        screen = '',
        timezone = '',
        timestamp = Date.now().toString()
      } = deviceInfo;

      const entropy = `${userAgent}|${acceptLanguage}|${platform}|${screen}|${timezone}|${timestamp}`;
      const hash = crypto.createHash('sha256').update(entropy).digest('hex');

      return hash.substring(0, 64); // 64 character fingerprint
    } catch (error) {
      // Fallback to basic fingerprint generation
      return DeviceSession.generateDeviceFingerprint();
    }
  }

  /**
   * Check if user has valid devices
   * @param {string} userId - User ID
   * @returns {Promise<boolean>} True if user has at least one valid device
   */
  async hasValidDevices(userId) {
    try {
      if (!userId) {
        return false;
      }

      const devices = await this.deviceSessionModel.getDevicesByUserId(userId, 1);
      return devices.length > 0;
    } catch (error) {
      console.error('Error checking valid devices:', error);
      return false;
    }
  }

  /**
   * Clean up old inactive devices
   * @param {number} daysInactive - Days of inactivity before cleanup
   * @returns {Promise<number>} Number of devices cleaned up
   */
  async cleanupOldDevices(daysInactive = 60) {
    try {
      return await this.deviceSessionModel.cleanupInactiveDevices(daysInactive);
    } catch (error) {
      throw new Error('Failed to cleanup old devices: ' + error.message);
    }
  }

  /**
   * Get key exchange statistics
   * @returns {Promise<Object>} Statistics about key management
   */
  async getStatistics() {
    try {
      const totalDevices = await this.deviceSessionModel.getTotalDeviceCount();
      const activeDevices = await this.deviceSessionModel.getActiveDeviceCount();

      // Get average devices per user
      const totalUsers = await this.userModel.getTotalUsers();
      const avgDevicesPerUser = totalUsers > 0 ? (totalDevices / totalUsers).toFixed(2) : 0;

      return {
        totalDevices,
        activeDevices,
        inactiveDevices: totalDevices - activeDevices,
        totalUsers,
        avgDevicesPerUser: parseFloat(avgDevicesPerUser),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error('Failed to get key exchange statistics: ' + error.message);
    }
  }

  /**
   * Export device data for user (privacy-focused)
   * @param {string} userId - User ID
   * @returns {Promise<Object>} Device data export
   */
  async exportDeviceData(userId) {
    try {
      if (!userId) {
        throw new Error('User ID is required');
      }

      const devices = await this.getUserDevices(userId);

      return {
        userId,
        exportDate: new Date().toISOString(),
        deviceCount: devices.length,
        devices: devices.map(device => ({
          deviceId: device.id,
          deviceFingerprint: device.deviceFingerprint,
          keyFingerprint: device.keyFingerprint,
          createdAt: device.createdAt,
          lastActive: device.lastActive,
          isActive: device.isActive,
          daysActive: device.daysActive
          // Note: Not exporting actual public keys for privacy
        }))
      };
    } catch (error) {
      throw new Error('Failed to export device data: ' + error.message);
    }
  }

  /**
   * Sanitize device session for safe output
   * @param {Object} deviceSession - Raw device session
   * @returns {Object} Sanitized device session
   */
  sanitizeDeviceSession(deviceSession) {
    if (!deviceSession) return null;

    return {
      id: deviceSession.id,
      userId: deviceSession.userId,
      deviceFingerprint: deviceSession.deviceFingerprint,
      publicKey: deviceSession.publicKey,
      createdAt: deviceSession.createdAt,
      lastActive: deviceSession.lastActive
    };
  }
}

module.exports = KeyExchangeService;
const User = require('../models/User');
const DeviceSession = require('../models/DeviceSession');
const KeyExchangeService = require('../services/KeyExchangeService');
const ValidationMiddleware = require('../middleware/validation');
const { body } = require('express-validator');
const encryptionConfig = require('../config/encryption');

class AuthController {
  constructor() {
    this.userModel = new User();
    this.deviceSessionModel = new DeviceSession();
    this.keyExchangeService = new KeyExchangeService();
  }

  /**
   * User login - creates or finds user and initializes session
   */
  async login(req, res) {
    try {
      const { username } = req.body;

      // Validate username format
      if (!this.userModel.validateUsername(username)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid username format. Use 2-50 characters: letters, numbers, underscores'
        });
      }

      // Find or create user
      const user = await this.userModel.findOrCreate(username);

      // Update user status and last seen
      await this.userModel.updateLoginTime(user.id);

      // Initialize session
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.createdAt = new Date();
      req.session.lastActivity = new Date();

      // Generate device fingerprint if not present
      if (!req.deviceFingerprint) {
        req.deviceFingerprint = encryptionConfig.generateDeviceFingerprint();
      }

      return res.status(200).json({
        success: true,
        data: {
          user: {
            id: user.id,
            username: user.username,
            status: user.status,
            createdAt: user.createdAt
          },
          deviceFingerprint: req.deviceFingerprint,
          requiresKeyRegistration: true
        }
      });

    } catch (error) {
      console.error('Login error:', error);
      return res.status(500).json({
        success: false,
        error: 'Login failed. Please try again.'
      });
    }
  }

  /**
   * User logout - destroys session and cleans up
   */
  async logout(req, res) {
    try {
      const userId = req.session?.userId;

      if (userId) {
        // Update user status to offline
        await this.userModel.updateStatus(userId, 'offline');
      }

      // Destroy session
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destroy error:', err);
          return res.status(500).json({
            success: false,
            error: 'Logout failed'
          });
        }

        return res.status(200).json({
          success: true,
          message: 'Logged out successfully'
        });
      });

    } catch (error) {
      console.error('Logout error:', error);
      return res.status(500).json({
        success: false,
        error: 'Logout failed'
      });
    }
  }

  /**
   * Get current user information
   */
  async getMe(req, res) {
    try {
      if (!req.session?.userId) {
        return res.status(401).json({
          success: false,
          error: 'Not authenticated'
        });
      }

      const user = await this.userModel.getById(req.session.userId);
      if (!user) {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      // Check if user has registered device keys
      const hasDeviceKeys = await this.keyExchangeService.hasValidDevices(user.id);

      return res.status(200).json({
        success: true,
        data: {
          user: {
            id: user.id,
            username: user.username,
            status: user.status,
            lastSeen: user.lastSeen,
            createdAt: user.createdAt
          },
          deviceFingerprint: req.deviceFingerprint,
          hasDeviceKeys,
          requiresKeyRegistration: !hasDeviceKeys
        }
      });

    } catch (error) {
      console.error('Get me error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get user information'
      });
    }
  }

  /**
   * Register device public key
   */
  async registerDevice(req, res) {
    try {
      const userId = req.session?.userId;
      const { publicKey } = req.body;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      if (!publicKey) {
        return res.status(400).json({
          success: false,
          error: 'Public key is required'
        });
      }

      // Validate public key format and strength
      const keyValidation = await this.keyExchangeService.validatePublicKeyStrength(publicKey);
      if (!keyValidation.valid) {
        return res.status(400).json({
          success: false,
          error: `Invalid public key: ${keyValidation.reason}`
        });
      }

      // Register device public key
      const deviceSession = await this.keyExchangeService.registerDevicePublicKey(
        userId,
        req.deviceFingerprint,
        publicKey
      );

      // Update session to indicate key registration
      req.session.deviceRegistered = true;
      req.session.deviceId = deviceSession.id;

      return res.status(201).json({
        success: true,
        data: {
          device: deviceSession,
          keyFingerprint: keyValidation.fingerprint,
          message: 'Device registered successfully'
        }
      });

    } catch (error) {
      console.error('Register device error:', error);

      if (error.message.includes('already exists')) {
        return res.status(409).json({
          success: false,
          error: 'Device already registered'
        });
      }

      return res.status(500).json({
        success: false,
        error: 'Device registration failed'
      });
    }
  }

  /**
   * Get user's registered devices
   */
  async getMyDevices(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const devices = await this.keyExchangeService.getUserDevices(userId);

      return res.status(200).json({
        success: true,
        data: {
          devices,
          count: devices.length
        }
      });

    } catch (error) {
      console.error('Get devices error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get devices'
      });
    }
  }

  /**
   * Revoke device access
   */
  async revokeDevice(req, res) {
    try {
      const userId = req.session?.userId;
      const { deviceFingerprint } = req.body;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      if (!deviceFingerprint) {
        return res.status(400).json({
          success: false,
          error: 'Device fingerprint is required'
        });
      }

      const success = await this.keyExchangeService.revokeDevice(userId, deviceFingerprint);

      if (!success) {
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }

      return res.status(200).json({
        success: true,
        message: 'Device revoked successfully'
      });

    } catch (error) {
      console.error('Revoke device error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to revoke device'
      });
    }
  }

  /**
   * Revoke all devices
   */
  async revokeAllDevices(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const revokedCount = await this.keyExchangeService.revokeAllDevices(userId);

      return res.status(200).json({
        success: true,
        data: {
          revokedCount,
          message: `Revoked ${revokedCount} devices successfully`
        }
      });

    } catch (error) {
      console.error('Revoke all devices error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to revoke devices'
      });
    }
  }

  /**
   * Update user status
   */
  async updateStatus(req, res) {
    try {
      const userId = req.session?.userId;
      const { status } = req.body;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const validStatuses = ['online', 'away', 'busy', 'offline'];
      if (!validStatuses.includes(status)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid status. Must be: online, away, busy, or offline'
        });
      }

      await this.userModel.updateStatus(userId, status);

      return res.status(200).json({
        success: true,
        data: {
          status
        }
      });

    } catch (error) {
      console.error('Update status error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to update status'
      });
    }
  }

  /**
   * Generate key pair (for client-side use)
   */
  async generateKeyPair(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      // Generate RSA key pair
      const keyPair = await this.keyExchangeService.encryptionService.generateRSAKeyPair();

      return res.status(200).json({
        success: true,
        data: {
          publicKey: keyPair.publicKey,
          privateKey: keyPair.privateKey,
          keySize: encryptionConfig.get('rsa.keySize'),
          algorithm: 'RSA-OAEP',
          hash: 'SHA-256'
        }
      });

    } catch (error) {
      console.error('Generate key pair error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to generate key pair'
      });
    }
  }

  /**
   * Get user statistics
   */
  async getUserStats(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const [userStats, deviceCount] = await Promise.all([
        this.userModel.getUserStats(userId),
        this.keyExchangeService.getUserDevices(userId).then(devices => devices.length)
      ]);

      return res.status(200).json({
        success: true,
        data: {
          messages: userStats,
          deviceCount,
          joinDate: req.session.createdAt
        }
      });

    } catch (error) {
      console.error('Get user stats error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get user statistics'
      });
    }
  }

  /**
   * Export user data (privacy compliant)
   */
  async exportUserData(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      const [user, deviceData, messageStats] = await Promise.all([
        this.userModel.getById(userId),
        this.keyExchangeService.exportDeviceData(userId),
        this.userModel.getUserStats(userId)
      ]);

      const exportData = {
        user: {
          id: user.id,
          username: user.username,
          status: user.status,
          createdAt: user.createdAt,
          lastSeen: user.lastSeen
        },
        devices: deviceData,
        statistics: messageStats,
        exportDate: new Date().toISOString(),
        version: '1.0'
      };

      return res.status(200).json({
        success: true,
        data: exportData
      });

    } catch (error) {
      console.error('Export user data error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to export user data'
      });
    }
  }

  /**
   * Delete user account
   */
  async deleteAccount(req, res) {
    try {
      const userId = req.session?.userId;
      const { confirmation } = req.body;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      if (confirmation !== 'DELETE') {
        return res.status(400).json({
          success: false,
          error: 'Account deletion requires "DELETE" confirmation'
        });
      }

      // Delete user and all associated data
      await this.userModel.delete(userId);

      // Destroy session
      req.session.destroy(() => {});

      return res.status(200).json({
        success: true,
        message: 'Account deleted successfully'
      });

    } catch (error) {
      console.error('Delete account error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to delete account'
      });
    }
  }

  // Validation middleware wrappers
  getValidationMiddleware() {
    return {
      validateLogin: [
        ValidationMiddleware.validateUsername(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateRegisterDevice: [
        ValidationMiddleware.validatePublicKey(),
        ValidationMiddleware.validateDeviceFingerprint(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateUpdateStatus: [
        body('status').isIn(['online', 'away', 'busy', 'offline']).withMessage('Invalid status'),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateRevokeDevice: [
        ValidationMiddleware.validateDeviceFingerprint(),
        ValidationMiddleware.handleValidationErrors()
      ],
      validateDeleteAccount: [
        body('confirmation').equals('DELETE').withMessage('Confirmation must be "DELETE"'),
        ValidationMiddleware.handleValidationErrors()
      ]
    };
  }
}

module.exports = AuthController;
const User = require('../models/User');
const KeyExchangeService = require('../services/KeyExchangeService');
const config = require('../config/app');

class ChatController {
  constructor() {
    this.userModel = new User();
    this.keyExchangeService = new KeyExchangeService();
  }

  /**
   * Render login page
   */
  async loginPage(req, res) {
    try {
      // If user is already authenticated, redirect to chat list
      if (req.session?.userId) {
        return res.redirect('/chat-list');
      }

      return res.render('login', {
        title: 'DarkChat - Secure Anonymous Messaging',
        description: 'Login to start secure, encrypted conversations',
        error: req.query.error ? decodeURIComponent(req.query.error) : null,
        success: req.query.success ? decodeURIComponent(req.query.success) : null,
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment()
      });

    } catch (error) {
      console.error('Login page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load login page',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render chat list page
   */
  async chatListPage(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.redirect('/login?error=' + encodeURIComponent('Authentication required'));
      }

      // Get user information
      const user = await this.userModel.getById(userId);
      if (!user) {
        req.session.destroy(() => {});
        return res.redirect('/login?error=' + encodeURIComponent('User not found'));
      }

      // Check if user has device keys registered
      const hasDeviceKeys = await this.keyExchangeService.hasValidDevices(userId);

      // Get active users for chat list
      const activeUsers = await this.userModel.getAllActive(100);

      // Filter out current user and format for display
      const chatUsers = activeUsers
        .filter(u => u.id !== userId)
        .map(u => ({
          id: u.id,
          username: u.username,
          status: u.status,
          lastSeen: u.lastSeen,
          statusClass: this.getStatusClass(u.status),
          lastSeenText: this.formatLastSeen(u.lastSeen)
        }));

      return res.render('chatList', {
        title: 'DarkChat - Contacts',
        user: {
          id: user.id,
          username: user.username,
          status: user.status,
          hasDeviceKeys
        },
        users: chatUsers,
        requiresKeyRegistration: !hasDeviceKeys,
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment()
      });

    } catch (error) {
      console.error('Chat list page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load chat list',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render chat room page
   */
  async chatRoomPage(req, res) {
    try {
      const userId = req.session?.userId;
      const { username } = req.params;

      if (!userId) {
        return res.redirect('/login?error=' + encodeURIComponent('Authentication required'));
      }

      // Get current user
      const currentUser = await this.userModel.getById(userId);
      if (!currentUser) {
        req.session.destroy(() => {});
        return res.redirect('/login?error=' + encodeURIComponent('User not found'));
      }

      // Get chat partner
      const partnerUser = await this.userModel.findByUsername(username);
      if (!partnerUser) {
        return res.status(404).render('error', {
          title: 'User Not Found',
          message: `User "${username}" does not exist`
        });
      }

      // Check if user has device keys
      const hasDeviceKeys = await this.keyExchangeService.hasValidDevices(userId);

      // Get partner's public keys
      const partnerPublicKeys = await this.keyExchangeService.getUserPublicKeysByUsername(username);
      if (partnerPublicKeys.length === 0) {
        return res.status(400).render('error', {
          title: 'Encryption Keys Required',
          message: `${username} has not registered encryption keys yet`,
          action: 'Please ask them to generate and register their encryption keys first'
        });
      }

      return res.render('chatRoom', {
        title: `DarkChat - ${username}`,
        currentUser: {
          id: currentUser.id,
          username: currentUser.username,
          status: currentUser.status,
          hasDeviceKeys
        },
        partnerUser: {
          id: partnerUser.id,
          username: partnerUser.username,
          status: partnerUser.status,
          statusClass: this.getStatusClass(partnerUser.status),
          publicKeys: partnerPublicKeys.map(key => ({
            fingerprint: key.fingerprint,
            createdAt: key.createdAt
          }))
        },
        encryptionConfig: {
          rsaKeySize: config.get('rsa.keySize'),
          aesKeySize: config.get('aes.keySize'),
          defaultTTL: config.get('messageTTL') || 300
        },
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment(),
        websocketUrl: this.getWebSocketUrl(req)
      });

    } catch (error) {
      console.error('Chat room page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load chat room',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render key generation page
   */
  async generateKeysPage(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.redirect('/login?error=' + encodeURIComponent('Authentication required'));
      }

      const user = await this.userModel.getById(userId);
      if (!user) {
        req.session.destroy(() => {});
        return res.redirect('/login?error=' + encodeURIComponent('User not found'));
      }

      return res.render('generateKeys', {
        title: 'DarkChat - Generate Encryption Keys',
        user: {
          id: user.id,
          username: user.username
        },
        encryptionConfig: {
          rsaKeySize: config.get('rsa.keySize'),
          algorithm: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment()
      });

    } catch (error) {
      console.error('Generate keys page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load key generation page',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render privacy policy page
   */
  async privacyPage(req, res) {
    try {
      return res.render('privacy', {
        title: 'DarkChat - Privacy Policy',
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment()
      });

    } catch (error) {
      console.error('Privacy page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load privacy policy',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render about page
   */
  async aboutPage(req, res) {
    try {
      return res.render('about', {
        title: 'DarkChat - About',
        description: 'Learn about DarkChat\'s secure, private messaging platform',
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment()
      });

    } catch (error) {
      console.error('About page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load about page',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render settings page
   */
  async settingsPage(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.redirect('/login?error=' + encodeURIComponent('Authentication required'));
      }

      const user = await this.userModel.getById(userId);
      if (!user) {
        req.session.destroy(() => {});
        return res.redirect('/login?error=' + encodeURIComponent('User not found'));
      }

      // Get user's devices
      const devices = await this.keyExchangeService.getUserDevices(userId);

      return res.render('settings', {
        title: 'DarkChat - Settings',
        user: {
          id: user.id,
          username: user.username,
          status: user.status,
          createdAt: user.createdAt
        },
        devices,
        deviceCount: devices.length,
        availableStatuses: [
          { value: 'online', label: 'Online', class: 'status-online' },
          { value: 'away', label: 'Away', class: 'status-away' },
          { value: 'busy', label: 'Busy', class: 'status-busy' },
          { value: 'offline', label: 'Offline', class: 'status-offline' }
        ],
        csrfToken: req.session?.csrfToken || '',
        isDevelopment: config.isDevelopment()
      });

    } catch (error) {
      console.error('Settings page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to load settings page',
        error: config.isDevelopment() ? error.message : null
      });
    }
  }

  /**
   * Render error page
   */
  async errorPage(req, res) {
    try {
      const { status = 500, message = 'An error occurred' } = req.query;

      return res.status(parseInt(status)).render('error', {
        title: `Error ${status}`,
        message: decodeURIComponent(message),
        error: config.isDevelopment() ? req.query.details || null : null,
        showHome: true
      });

    } catch (error) {
      console.error('Error page error:', error);
      return res.status(500).render('error', {
        title: 'Server Error',
        message: 'Unable to display error page',
        showHome: true
      });
    }
  }

  /**
   * API endpoint to get WebSocket configuration
   */
  async getWebSocketConfig(req, res) {
    try {
      const userId = req.session?.userId;

      if (!userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }

      return res.status(200).json({
        success: true,
        data: {
          url: this.getWebSocketUrl(req),
          transports: ['websocket', 'polling'],
          timeout: 20000,
          forceNew: true
        }
      });

    } catch (error) {
      console.error('Get WebSocket config error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to get WebSocket configuration'
      });
    }
  }

  /**
   * Helper method to get WebSocket URL based on request
   */
  getWebSocketUrl(req) {
    const protocol = req.protocol === 'https' ? 'wss' : 'ws';
    const host = req.get('host');
    return `${protocol}://${host}`;
  }

  /**
   * Helper method to get status CSS class
   */
  getStatusClass(status) {
    const statusClasses = {
      'online': 'status-online',
      'away': 'status-away',
      'busy': 'status-busy',
      'offline': 'status-offline'
    };

    return statusClasses[status] || 'status-offline';
  }

  /**
   * Helper method to format last seen time
   */
  formatLastSeen(lastSeen) {
    if (!lastSeen) return 'Never';

    const now = new Date();
    const lastSeenDate = new Date(lastSeen);
    const diffMs = now - lastSeenDate;
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMinutes < 1) return 'Just now';
    if (diffMinutes < 60) return `${diffMinutes} minutes ago`;
    if (diffHours < 24) return `${diffHours} hours ago`;
    if (diffDays < 7) return `${diffDays} days ago`;

    return lastSeenDate.toLocaleDateString();
  }

  /**
   * Handle 404 errors
   */
  async notFound(req, res) {
    return res.status(404).render('error', {
      title: 'Page Not Found',
      message: 'The page you are looking for does not exist',
      showHome: true
    });
  }
}

module.exports = ChatController;
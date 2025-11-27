/**
 * DarkChat Chat Room Interface
 * Handles message sending, encryption, and real-time communication
 */

class DarkChatRoom {
  constructor() {
    this.encryption = null;
    this.websocket = null;
    this.config = window.DARKCHAT_CONFIG;
    this.isConnected = false;
    this.partnerPublicKey = null;
    this.typingTimer = null;
    this.messageQueue = [];
    this.settings = this.loadSettings();
  }

  async init() {
    try {
      console.log('Initializing DarkChat Room...');

      // Initialize encryption
      this.encryption = new DarkChatEncryption();

      // Load or generate keys
      if (!this.encryption.loadKeys()) {
        // Generate new keys if none exist
        await this.encryption.initialize();
        this.encryption.storeKeys();
      } else {
        await this.encryption.initialize();
      }

      // Initialize WebSocket connection
      await this.initWebSocket();

      // Setup UI event listeners
      this.setupEventListeners();

      // Load partner's public key
      await this.loadPartnerPublicKey();

      // Load existing conversation
      await this.loadConversation();

      // Update UI
      this.updateEncryptionStatus();
      this.updateCharacterCount();

      console.log('DarkChat Room initialized successfully');

    } catch (error) {
      console.error('Failed to initialize chat room:', error);
      this.showError('Failed to initialize chat room: ' + error.message);
    }
  }

  async initWebSocket() {
    try {
      this.websocket = new DarkChatWebSocket();
      await this.websocket.connect(this.config.websocket.url, {
        userId: this.config.currentUser.id,
        username: this.config.currentUser.username,
        token: this.config.security.csrfToken
      });

      // Setup WebSocket event handlers
      this.websocket.on('connected', () => {
        this.isConnected = true;
        this.updateConnectionStatus('Connected');
      });

      this.websocket.on('disconnected', () => {
        this.isConnected = false;
        this.updateConnectionStatus('Disconnected');
      });

      this.websocket.on('new-message', (data) => {
        this.handleNewMessage(data);
      });

      this.websocket.on('message-status-update', (data) => {
        this.handleMessageStatusUpdate(data);
      });

      this.websocket.on('typing-indicator', (data) => {
        this.handleTypingIndicator(data);
      });

      this.websocket.on('error', (error) => {
        this.showError('WebSocket error: ' + error.message);
      });

    } catch (error) {
      console.error('WebSocket initialization failed:', error);
      throw error;
    }
  }

  setupEventListeners() {
    // Message form submission
    const messageForm = document.getElementById('messageForm');
    if (messageForm) {
      messageForm.addEventListener('submit', (e) => {
        e.preventDefault();
        this.sendMessage();
      });
    }

    // Message input events
    const messageInput = document.getElementById('messageInput');
    if (messageInput) {
      messageInput.addEventListener('input', () => {
        this.updateCharacterCount();
        this.handleTyping();
      });

      messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          this.sendMessage();
        }
      });
    }

    // Settings buttons
    const encryptionInfoBtn = document.getElementById('encryptionInfoBtn');
    if (encryptionInfoBtn) {
      encryptionInfoBtn.addEventListener('click', () => {
        this.showEncryptionInfo();
      });
    }

    const chatSettingsBtn = document.getElementById('chatSettingsBtn');
    if (chatSettingsBtn) {
      chatSettingsBtn.addEventListener('click', () => {
        this.showChatSettings();
      });
    }

    // Modal close buttons
    document.querySelectorAll('.modal-close').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.target.closest('.modal').style.display = 'none';
      });
    });

    // Settings save button
    const saveChatSettingsBtn = document.getElementById('saveChatSettings');
    if (saveChatSettingsBtn) {
      saveChatSettingsBtn.addEventListener('click', () => {
        this.saveSettings();
      });
    }

    // Settings reset button
    const resetChatSettingsBtn = document.getElementById('resetChatSettings');
    if (resetChatSettingsBtn) {
      resetChatSettingsBtn.addEventListener('click', () => {
        this.resetSettings();
      });
    }

    // Close modals when clicking outside
    document.querySelectorAll('.modal').forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          modal.style.display = 'none';
        }
      });
    });
  }

  async loadPartnerPublicKey() {
    try {
      const response = await fetch(`/api/users/${this.config.partner.username}/public-keys`);
      const data = await response.json();

      if (data.success && data.data.publicKeys.length > 0) {
        // Use the most recent public key
        this.partnerPublicKey = data.data.publicKeys[0].publicKey;
        console.log('Partner public key loaded');
      } else {
        throw new Error('No public keys found for partner');
      }
    } catch (error) {
      console.error('Failed to load partner public key:', error);
      this.showError('Failed to load encryption keys for partner');
    }
  }

  async loadConversation() {
    try {
      const response = await fetch(`/api/messages/conversation/${this.config.partner.username}`);
      const data = await response.json();

      if (data.success) {
        data.data.messages.forEach(message => {
          this.displayMessage(message);
        });
      }
    } catch (error) {
      console.error('Failed to load conversation:', error);
    }
  }

  async sendMessage() {
    try {
      const messageInput = document.getElementById('messageInput');
      const message = messageInput.value.trim();

      if (!message) {
        return;
      }

      if (!this.partnerPublicKey) {
        this.showError('Partner encryption keys not loaded');
        return;
      }

      // Get message options
      const anonymous = document.getElementById('anonymousMessage').checked;
      const oneTimeView = document.getElementById('oneTimeView').checked;
      const expiresIn = parseInt(document.getElementById('messageExpiration').value);

      // Disable send button
      const sendBtn = document.getElementById('sendBtn');
      const originalText = sendBtn.innerHTML;
      sendBtn.disabled = true;
      sendBtn.innerHTML = '⏳ Encrypting...';

      try {
        // Encrypt message
        const encryptedData = await this.encryption.encryptMessage(message, this.partnerPublicKey);

        // Send to server
        const response = await fetch('/api/messages/send', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': this.config.security.csrfToken
          },
          body: JSON.stringify({
            recipient: this.config.partner.username,
            ...encryptedData,
            expiresIn,
            oneTimeView,
            anonymous
          })
        });

        const result = await response.json();

        if (result.success) {
          // Clear input
          messageInput.value = '';
          this.updateCharacterCount();

          // Add to local display
          this.displayMessage({
            messageId: result.data.messageId,
            isSender: true,
            content: message,
            isAnonymous: anonymous,
            isOneTimeView: oneTimeView,
            createdAt: new Date(),
            expiresAt: result.data.expiresAt
          });

        } else {
          throw new Error(result.error || 'Failed to send message');
        }

      } finally {
        // Re-enable send button
        sendBtn.disabled = false;
        sendBtn.innerHTML = originalText;
      }

    } catch (error) {
      console.error('Failed to send message:', error);
      this.showError('Failed to send message: ' + error.message);
    }
  }

  async handleNewMessage(data) {
    if (data.senderId !== this.config.partner.id) {
      return; // Not for this chat
    }

    try {
      // Get encrypted message content
      const response = await fetch(`/api/messages/${data.messageId}`);
      const messageData = await response.json();

      if (messageData.success) {
        // Decrypt message
        const decryptedContent = await this.encryption.decryptMessage(
          messageData.data,
          this.partnerPublicKey
        );

        // Display message
        this.displayMessage({
          messageId: data.messageId,
          isSender: false,
          content: decryptedContent,
          isAnonymous: data.isAnonymous,
          isOneTimeView: data.isOneTimeView,
          createdAt: new Date(),
          expiresAt: messageData.data.expiresAt
        });

        // Mark as read
        await this.markMessageAsRead(data.messageId);

        // Show notification
        if (document.hidden) {
          this.showNotification(`${data.anonymous ? 'Anonymous' : data.sender}: New message`);
        }
      }
    } catch (error) {
      console.error('Failed to handle new message:', error);
      this.showError('Failed to decrypt received message');
    }
  }

  displayMessage(message) {
    const messagesList = document.getElementById('messagesList');
    if (!messagesList) return;

    // Remove empty state if this is the first message
    const emptyState = messagesList.querySelector('.empty-state');
    if (emptyState) {
      emptyState.remove();
    }

    const messageElement = document.createElement('div');
    messageElement.className = `message ${message.isSender ? 'message-sent' : 'message-received'}`;
    messageElement.setAttribute('data-message-id', message.messageId);

    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';
    messageContent.textContent = message.content;

    const messageMeta = document.createElement('div');
    messageMeta.className = 'message-meta';

    let metaText = '';
    if (message.isAnonymous && !message.isSender) {
      metaText += '👤 Anonymous • ';
    }
    metaText += this.formatTime(message.createdAt);

    if (message.isOneTimeView) {
      metaText += ' • 👁️ One-time view';
    }

    if (message.expiresAt) {
      const timeRemaining = this.getTimeRemaining(message.expiresAt);
      metaText += ` • ⏰ ${timeRemaining}`;
    }

    messageMeta.textContent = metaText;

    messageElement.appendChild(messageContent);
    messageElement.appendChild(messageMeta);

    // Add expiration timer if applicable
    if (message.expiresAt && !message.isSender) {
      this.startExpirationTimer(messageElement, message.expiresAt, message.messageId);
    }

    messagesList.appendChild(messageElement);

    // Scroll to bottom
    messagesList.scrollTop = messagesList.scrollHeight;

    // Handle one-time view
    if (message.isOneTimeView && !message.isSender) {
      setTimeout(() => {
        this.destroyMessage(message.messageId);
      }, 5000); // Give user 5 seconds to read
    }
  }

  startExpirationTimer(element, expiresAt, messageId) {
    const updateTimer = () => {
      const timeRemaining = this.getTimeRemaining(expiresAt);
      const metaElement = element.querySelector('.message-meta');

      if (metaElement) {
        let metaText = metaElement.textContent;
        const timeMatch = metaText.match(/• ⏰ (.+)$/);

        if (timeMatch) {
          metaText = metaText.replace(/• ⏰ .+$/, `• ⏰ ${timeRemaining}`);
          metaElement.textContent = metaText;
        }
      }

      if (new Date() >= new Date(expiresAt)) {
        this.destroyMessage(messageId);
      } else {
        setTimeout(updateTimer, 1000);
      }
    };

    setTimeout(updateTimer, 1000);
  }

  async destroyMessage(messageId) {
    try {
      // Remove from UI
      const messageElement = document.querySelector(`[data-message-id="${messageId}"]`);
      if (messageElement) {
        messageElement.style.opacity = '0';
        messageElement.style.transform = 'scale(0.8)';

        setTimeout(() => {
          messageElement.remove();
        }, 300);
      }

      // Delete from server
      await fetch(`/api/messages/${messageId}`, {
        method: 'DELETE',
        headers: {
          'X-CSRF-Token': this.config.security.csrfToken
        }
      });
    } catch (error) {
      console.error('Failed to destroy message:', error);
    }
  }

  async markMessageAsRead(messageId) {
    try {
      await fetch(`/api/messages/${messageId}`, {
        method: 'DELETE',
        headers: {
          'X-CSRF-Token': this.config.security.csrfToken
        }
      });
    } catch (error) {
      console.error('Failed to mark message as read:', error);
    }
  }

  handleTyping() {
    if (!this.isConnected) return;

    // Clear existing timer
    if (this.typingTimer) {
      clearTimeout(this.typingTimer);
    }

    // Send typing started
    this.websocket.emit('typing-start', {
      receiverId: this.config.partner.id
    });

    // Set timer to send typing stopped
    this.typingTimer = setTimeout(() => {
      this.websocket.emit('typing-stop', {
        receiverId: this.config.partner.id
      });
    }, 1000);
  }

  handleTypingIndicator(data) {
    if (data.userId !== this.config.partner.id) return;

    const typingIndicator = document.getElementById('typingIndicator');
    if (typingIndicator) {
      typingIndicator.style.display = data.isTyping ? 'block' : 'none';
    }
  }

  handleMessageStatusUpdate(data) {
    console.log('Message status update:', data);
    // Update message status in UI if needed
  }

  updateCharacterCount() {
    const messageInput = document.getElementById('messageInput');
    const charCount = document.getElementById('charCount');

    if (messageInput && charCount) {
      const count = messageInput.value.length;
      charCount.textContent = count;

      if (count > 9000) {
        charCount.style.color = '#ff4444';
      } else if (count > 8000) {
        charCount.style.color = '#ff8800';
      } else {
        charCount.style.color = '#666';
      }
    }
  }

  updateConnectionStatus(status) {
    const connectionStatus = document.getElementById('connectionStatus');
    if (connectionStatus) {
      connectionStatus.innerHTML = `
        <span class="status-dot status-${status.toLowerCase()}"></span>
        ${status}
      `;
    }
  }

  updateEncryptionStatus() {
    const encryptionStatus = document.getElementById('encryptionStatus');
    if (encryptionStatus && this.partnerPublicKey) {
      encryptionStatus.textContent = '🔒 End-to-End Encrypted';
      encryptionStatus.className = 'encryption-status encrypted';
    }
  }

  showEncryptionInfo() {
    const modal = document.getElementById('encryptionModal');
    if (modal) {
      modal.style.display = 'block';
    }
  }

  showChatSettings() {
    const modal = document.getElementById('chatSettingsModal');
    if (modal) {
      // Load current settings into modal
      document.getElementById('defaultAnonymous').checked = this.settings.defaultAnonymous;
      document.getElementById('defaultOneTime').checked = this.settings.defaultOneTime;
      document.getElementById('defaultExpiration').value = this.settings.defaultExpiration;
      document.getElementById('enableTypingIndicators').checked = this.settings.enableTypingIndicators;
      document.getElementById('enableReadReceipts').checked = this.settings.enableReadReceipts;
      document.getElementById('enableSoundNotifications').checked = this.settings.enableSoundNotifications;

      modal.style.display = 'block';
    }
  }

  saveSettings() {
    this.settings = {
      defaultAnonymous: document.getElementById('defaultAnonymous').checked,
      defaultOneTime: document.getElementById('defaultOneTime').checked,
      defaultExpiration: parseInt(document.getElementById('defaultExpiration').value),
      enableTypingIndicators: document.getElementById('enableTypingIndicators').checked,
      enableReadReceipts: document.getElementById('enableReadReceipts').checked,
      enableSoundNotifications: document.getElementById('enableSoundNotifications').checked
    };

    localStorage.setItem('darkchat_settings', JSON.stringify(this.settings));

    // Apply settings
    this.applySettings();

    // Close modal
    document.getElementById('chatSettingsModal').style.display = 'none';

    this.showSuccess('Settings saved successfully');
  }

  resetSettings() {
    this.settings = this.getDefaultSettings();
    localStorage.removeItem('darkchat_settings');
    this.applySettings();
    this.showChatSettings(); // Reload modal
    this.showSuccess('Settings reset to defaults');
  }

  loadSettings() {
    const saved = localStorage.getItem('darkchat_settings');
    return saved ? JSON.parse(saved) : this.getDefaultSettings();
  }

  getDefaultSettings() {
    return {
      defaultAnonymous: false,
      defaultOneTime: false,
      defaultExpiration: 300, // 5 minutes
      enableTypingIndicators: true,
      enableReadReceipts: true,
      enableSoundNotifications: true
    };
  }

  applySettings() {
    // Apply default values to form
    if (this.settings.defaultAnonymous !== undefined) {
      document.getElementById('anonymousMessage').checked = this.settings.defaultAnonymous;
    }
    if (this.settings.defaultOneTime !== undefined) {
      document.getElementById('oneTimeView').checked = this.settings.defaultOneTime;
    }
    if (this.settings.defaultExpiration) {
      document.getElementById('messageExpiration').value = this.settings.defaultExpiration;
    }
  }

  formatTime(date) {
    return new Date(date).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  getTimeRemaining(expiresAt) {
    const now = new Date();
    const expiry = new Date(expiresAt);
    const diff = expiry - now;

    if (diff <= 0) return 'Expired';

    const minutes = Math.floor(diff / (1000 * 60));
    const seconds = Math.floor((diff % (1000 * 60)) / 1000);

    if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  }

  showError(message) {
    console.error(message);
    // You could implement a toast notification here
    alert('Error: ' + message);
  }

  showSuccess(message) {
    console.log(message);
    // You could implement a toast notification here
    // alert('Success: ' + message);
  }

  showNotification(message) {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('DarkChat', {
        body: message,
        icon: '/static/images/favicon.ico',
        silent: !this.settings.enableSoundNotifications
      });
    }
  }

  cleanup() {
    // Cleanup WebSocket
    if (this.websocket) {
      this.websocket.disconnect();
    }

    // Clear typing timer
    if (this.typingTimer) {
      clearTimeout(this.typingTimer);
    }

    // Cleanup encryption
    if (this.encryption) {
      this.encryption.cleanup();
    }
  }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  if (window.DARKCHAT_CONFIG && window.DARKCHAT_CONFIG.partner) {
    window.darkChatRoom = new DarkChatRoom();
    window.DarkChat = {
      init: () => window.darkChatRoom.init(),
      cleanup: () => window.darkChatRoom.cleanup()
    };
  }
});
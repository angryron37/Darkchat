/**
 * DarkChat Client-Side Encryption
 * Handles RSA key generation, AES encryption, and message signing
 */

class DarkChatEncryption {
  constructor() {
    this.rsaKeyPair = null;
    this.publicKey = null;
    this.privateKey = null;
    this.isInitialized = false;
  }

  /**
   * Initialize encryption with existing keys or generate new ones
   */
  async initialize(keys = null) {
    try {
      if (keys && keys.publicKey && keys.privateKey) {
        // Use provided keys
        this.publicKey = keys.publicKey;
        this.privateKey = keys.privateKey;
        console.log('Encryption initialized with existing keys');
      } else {
        // Generate new keys
        await this.generateKeyPair();
        console.log('Encryption initialized with new keys');
      }

      this.isInitialized = true;
      return {
        publicKey: this.publicKey,
        privateKey: this.privateKey
      };
    } catch (error) {
      console.error('Failed to initialize encryption:', error);
      throw error;
    }
  }

  /**
   * Generate RSA key pair
   */
  async generateKeyPair() {
    try {
      const keyPair = await this.generateRSAKeyPair();
      this.rsaKeyPair = keyPair;
      this.publicKey = keyPair.publicKey;
      this.privateKey = keyPair.privateKey;

      return keyPair;
    } catch (error) {
      console.error('Failed to generate key pair:', error);
      throw error;
    }
  }

  /**
   * Generate RSA key pair using Web Crypto API or Node.js crypto
   */
  async generateRSAKeyPair() {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      return await this.generateRSAKeyPairBrowser();
    } else {
      return await this.generateRSAKeyPairNode();
    }
  }

  /**
   * Generate RSA key pair in browser using Web Crypto API
   */
  async generateRSAKeyPairBrowser() {
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: "RSA-OAEP",
          modulusLength: 4096,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
      );

      const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
      const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

      return {
        publicKey: this.arrayBufferToBase64(publicKey),
        privateKey: this.arrayBufferToBase64(privateKey)
      };
    } catch (error) {
      console.error('Browser key generation failed:', error);
      throw new Error('Failed to generate encryption keys in browser');
    }
  }

  /**
   * Generate RSA key pair in Node.js environment
   */
  async generateRSAKeyPairNode() {
    try {
      const crypto = require('crypto');
      const keyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });

      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.privateKey
      };
    } catch (error) {
      console.error('Node.js key generation failed:', error);
      throw new Error('Failed to generate encryption keys');
    }
  }

  /**
   * Encrypt message for recipient
   */
  async encryptMessage(message, recipientPublicKey) {
    if (!this.isInitialized) {
      throw new Error('Encryption not initialized');
    }

    try {
      // Generate random AES key for this message
      const aesKey = this.generateAESKey();

      // Encrypt message with AES
      const aesEncrypted = await this.encryptWithAES(message, aesKey);

      // Encrypt AES key with recipient's RSA public key
      const encryptedAESKey = await this.encryptWithRSA(aesKey, recipientPublicKey);

      // Sign the message with sender's private key
      const signature = await this.signMessage(message);

      return {
        cipherText: aesEncrypted.cipherText,
        iv: aesEncrypted.iv,
        authTag: aesEncrypted.authTag,
        encryptedAESKey,
        signature
      };
    } catch (error) {
      console.error('Message encryption failed:', error);
      throw new Error('Failed to encrypt message');
    }
  }

  /**
   * Decrypt received message
   */
  async decryptMessage(encryptedData, senderPublicKey) {
    if (!this.isInitialized) {
      throw new Error('Encryption not initialized');
    }

    try {
      const { cipherText, iv, authTag, encryptedAESKey, signature } = encryptedData;

      // Decrypt AES key with private RSA key
      const aesKey = await this.decryptWithRSA(encryptedAESKey);

      // Decrypt message with AES
      const decryptedMessage = await this.decryptWithAES(cipherText, iv, authTag, aesKey);

      // Verify signature with sender's public key
      const isValidSignature = await this.verifySignature(decryptedMessage, signature, senderPublicKey);

      if (!isValidSignature) {
        throw new Error('Invalid message signature');
      }

      return decryptedMessage;
    } catch (error) {
      console.error('Message decryption failed:', error);
      throw new Error('Failed to decrypt message');
    }
  }

  /**
   * Generate AES key
   */
  generateAESKey() {
    if (typeof window !== 'undefined' && window.crypto) {
      return window.crypto.getRandomValues(new Uint8Array(32));
    } else {
      const crypto = require('crypto');
      return crypto.randomBytes(32);
    }
  }

  /**
   * Encrypt with AES-256-GCM
   */
  async encryptWithAES(message, key) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return await this.encryptWithAESBrowser(message, key);
      } else {
        return await this.encryptWithAESNode(message, key);
      }
    } catch (error) {
      console.error('AES encryption failed:', error);
      throw error;
    }
  }

  /**
   * AES encryption in browser
   */
  async encryptWithAESBrowser(message, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      await window.crypto.subtle.importKey(
        "raw",
        key,
        "AES-GCM",
        false,
        ["encrypt"]
      ),
      new TextEncoder().encode(message)
    );

    const encryptedArray = new Uint8Array(encrypted);
    const authTag = encryptedArray.slice(encryptedArray.length - 16);
    const cipherText = encryptedArray.slice(0, encryptedArray.length - 16);

    return {
      cipherText: this.arrayBufferToBase64(cipherText),
      iv: this.arrayBufferToBase64(iv),
      authTag: this.arrayBufferToBase64(authTag)
    };
  }

  /**
   * AES encryption in Node.js
   */
  async encryptWithAESNode(message, key) {
    const crypto = require('crypto');
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipher('aes-256-gcm', key);
    cipher.setAAD(Buffer.from('darkchat-aes', 'utf8'));

    let encrypted = cipher.update(message, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const authTag = cipher.getAuthTag();

    return {
      cipherText: encrypted,
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64')
    };
  }

  /**
   * Decrypt with AES-256-GCM
   */
  async decryptWithAES(cipherText, iv, authTag, key) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return await this.decryptWithAESBrowser(cipherText, iv, authTag, key);
      } else {
        return await this.decryptWithAESNode(cipherText, iv, authTag, key);
      }
    } catch (error) {
      console.error('AES decryption failed:', error);
      throw error;
    }
  }

  /**
   * AES decryption in browser
   */
  async decryptWithAESBrowser(cipherText, iv, authTag, key) {
    const cipherTextBuffer = this.base64ToArrayBuffer(cipherText);
    const ivBuffer = this.base64ToArrayBuffer(iv);
    const authTagBuffer = this.base64ToArrayBuffer(authTag);

    const encryptedData = new Uint8Array(cipherTextBuffer.byteLength + authTagBuffer.byteLength);
    encryptedData.set(new Uint8Array(cipherTextBuffer));
    encryptedData.set(new Uint8Array(authTagBuffer), cipherTextBuffer.byteLength);

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBuffer
      },
      await window.crypto.subtle.importKey(
        "raw",
        key,
        "AES-GCM",
        false,
        ["decrypt"]
      ),
      encryptedData
    );

    return new TextDecoder().decode(decrypted);
  }

  /**
   * AES decryption in Node.js
   */
  async decryptWithAESNode(cipherText, iv, authTag, key) {
    const crypto = require('crypto');

    const decipher = crypto.createDecipher('aes-256-gcm', key);
    decipher.setAAD(Buffer.from('darkchat-aes', 'utf8'));
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));

    let decrypted = decipher.update(cipherText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Encrypt with RSA public key
   */
  async encryptWithRSA(data, publicKey) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return await this.encryptWithRSABrowser(data, publicKey);
      } else {
        return await this.encryptWithRSANode(data, publicKey);
      }
    } catch (error) {
      console.error('RSA encryption failed:', error);
      throw error;
    }
  }

  /**
   * RSA encryption in browser
   */
  async encryptWithRSABrowser(data, publicKey) {
    const publicKeyBuffer = this.base64ToArrayBuffer(publicKey);
    const key = await window.crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["encrypt"]
    );

    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: "RSA-OAEP"
      },
      key,
      data
    );

    return this.arrayBufferToBase64(encrypted);
  }

  /**
   * RSA encryption in Node.js
   */
  async encryptWithRSANode(data, publicKey) {
    const crypto = require('crypto');
    const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data);
    return crypto.publicEncrypt({
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, buffer).toString('base64');
  }

  /**
   * Decrypt with RSA private key
   */
  async decryptWithRSA(encryptedData) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return await this.decryptWithRSABrowser(encryptedData);
      } else {
        return await this.decryptWithRSANode(encryptedData);
      }
    } catch (error) {
      console.error('RSA decryption failed:', error);
      throw error;
    }
  }

  /**
   * RSA decryption in browser
   */
  async decryptWithRSABrowser(encryptedData) {
    const privateKeyBuffer = this.base64ToArrayBuffer(this.privateKey);
    const encryptedBuffer = this.base64ToArrayBuffer(encryptedData);

    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      privateKeyBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["decrypt"]
    );

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      key,
      encryptedBuffer
    );

    return new Uint8Array(decrypted);
  }

  /**
   * RSA decryption in Node.js
   */
  async decryptWithRSANode(encryptedData) {
    const crypto = require('crypto');
    return crypto.privateDecrypt({
      key: this.privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, Buffer.from(encryptedData, 'base64'));
  }

  /**
   * Sign message with private key
   */
  async signMessage(message) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return await this.signMessageBrowser(message);
      } else {
        return await this.signMessageNode(message);
      }
    } catch (error) {
      console.error('Message signing failed:', error);
      throw error;
    }
  }

  /**
   * Message signing in browser
   */
  async signMessageBrowser(message) {
    const privateKeyBuffer = this.base64ToArrayBuffer(this.privateKey);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      privateKeyBuffer,
      {
        name: "RSA-PSS",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

    const signature = await window.crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32
      },
      key,
      new TextEncoder().encode(message)
    );

    return this.arrayBufferToBase64(signature);
  }

  /**
   * Message signing in Node.js
   */
  async signMessageNode(message) {
    const crypto = require('crypto');
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(message);
    return sign.sign(this.privateKey, 'base64');
  }

  /**
   * Verify message signature
   */
  async verifySignature(message, signature, publicKey) {
    try {
      if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
        return await this.verifySignatureBrowser(message, signature, publicKey);
      } else {
        return await this.verifySignatureNode(message, signature, publicKey);
      }
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }

  /**
   * Signature verification in browser
   */
  async verifySignatureBrowser(message, signature, publicKey) {
    const publicKeyBuffer = this.base64ToArrayBuffer(publicKey);
    const signatureBuffer = this.base64ToArrayBuffer(signature);

    const key = await window.crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "RSA-PSS",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    return await window.crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: 32
      },
      key,
      signatureBuffer,
      new TextEncoder().encode(message)
    );
  }

  /**
   * Signature verification in Node.js
   */
  async verifySignatureNode(message, signature, publicKey) {
    const crypto = require('crypto');
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(message);
    return verify.verify(publicKey, signature, 'base64');
  }

  /**
   * Convert ArrayBuffer to Base64
   */
  arrayBufferToBase64(buffer) {
    if (typeof window !== 'undefined' && window.btoa) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return window.btoa(binary);
    } else {
      const Buffer = require('buffer').Buffer;
      return Buffer.from(buffer).toString('base64');
    }
  }

  /**
   * Convert Base64 to ArrayBuffer
   */
  base64ToArrayBuffer(base64) {
    if (typeof window !== 'undefined' && window.atob) {
      const binaryString = window.atob(base64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      return bytes.buffer;
    } else {
      const Buffer = require('buffer').Buffer;
      return Buffer.from(base64, 'base64');
    }
  }

  /**
   * Clear sensitive data from memory
   */
  cleanup() {
    this.rsaKeyPair = null;
    this.publicKey = null;
    this.privateKey = null;
    this.isInitialized = false;

    // Clear any stored keys from localStorage/sessionStorage
    if (typeof window !== 'undefined') {
      localStorage.removeItem('darkchat_private_key');
      sessionStorage.removeItem('darkchat_private_key');
    }
  }

  /**
   * Store keys securely (session only)
   */
  storeKeys() {
    if (typeof window !== 'undefined' && this.privateKey) {
      // Store private key in sessionStorage (cleared when tab closes)
      sessionStorage.setItem('darkchat_private_key', this.privateKey);
    }
  }

  /**
   * Load keys from storage
   */
  loadKeys() {
    if (typeof window !== 'undefined') {
      const privateKey = sessionStorage.getItem('darkchat_private_key');
      if (privateKey) {
        // Derive public key from private key
        // This is a simplified approach - in production, you'd store both
        this.privateKey = privateKey;
        this.isInitialized = true;
        return true;
      }
    }
    return false;
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DarkChatEncryption;
} else {
  window.DarkChatEncryption = DarkChatEncryption;
}
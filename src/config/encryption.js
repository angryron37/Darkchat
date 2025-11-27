class EncryptionConfig {
  constructor() {
    this.config = this.loadEncryptionConfig();
  }

  loadEncryptionConfig() {
    return {
      // RSA Configuration
      rsa: {
        keySize: parseInt(process.env.RSA_KEY_SIZE) || 4096,
        publicExponent: 0x10001, // 65537 (standard)
        algorithm: 'RSA-OAEP',
        hash: 'SHA-256',
        mgf1Hash: 'SHA-256',
        saltLength: 32
      },

      // AES Configuration
      aes: {
        keySize: 256, // AES-256
        ivLength: 12, // GCM recommended IV length
        tagLength: 16, // GCM authentication tag length
        algorithm: 'AES-GCM',
        mode: 'GCM'
      },

      // Digital Signatures
      signature: {
        algorithm: 'RSA-PSS',
        hash: 'SHA-256',
        saltLength: 32
      },

      // Key Derivation
      keyDerivation: {
        algorithm: 'PBKDF2',
        iterations: 100000,
        hash: 'SHA-256',
        saltLength: 32
      },

      // Random Generation
      random: {
        bytesPerMessageKey: 32, // 256 bits for AES key
        deviceIdLength: 32,
        messageIdLength: 32,
        sessionIdLength: 64
      },

      // Encoding
      encoding: {
        format: 'base64',
        urlSafe: false,
        padding: true
      },

      // Security Parameters
      security: {
        maxKeyAge: 24 * 60 * 60 * 1000, // 24 hours for key rotation
        maxMessageAge: 7 * 24 * 60 * 60 * 1000, // 7 days maximum message age
        minKeyEntropy: 7.0, // Minimum entropy for generated keys
        rejectOldKeys: true
      },

      // Performance Tuning
      performance: {
        keyGenerationTimeout: 5000, // 5 seconds max for key generation
        encryptionTimeout: 1000, // 1 second max for encryption
        decryptionTimeout: 1000, // 1 second max for decryption
        signatureTimeout: 1000, // 1 second max for signing
        parallelOperations: true,
        webWorkerSupport: true
      },

      // Browser Crypto API Fallback
      fallback: {
        useForgeWhenCryptoUnavailable: true,
        validateWebCryptoSupport: true,
        gracefulDegradation: true
      }
    };
  }

  // Get RSA key pair generation parameters
  getRSAKeyPairParams() {
    return {
      modulusLength: this.config.rsa.keySize,
      publicExponent: this.config.rsa.publicExponent,
      hash: { name: this.config.rsa.hash },
      name: this.config.rsa.algorithm
    };
  }

  // Get AES encryption parameters
  getAESEncryptParams() {
    return {
      name: this.config.aes.algorithm,
      iv: this.generateRandomBytes(this.config.aes.ivLength),
      tagLength: this.config.aes.tagLength
    };
  }

  // Get AES decryption parameters
  getAESDecryptParams(iv) {
    return {
      name: this.config.aes.algorithm,
      iv: iv
    };
  }

  // Get RSA encryption parameters
  getRSAEncryptParams() {
    return {
      name: this.config.rsa.algorithm,
      hash: { name: this.config.rsa.hash }
    };
  }

  // Get RSA decryption parameters
  getRSADecryptParams() {
    return {
      name: this.config.rsa.algorithm,
      hash: { name: this.config.rsa.hash }
    };
  }

  // Get signature parameters
  getSignatureParams() {
    return {
      name: this.config.signature.algorithm,
      hash: { name: this.config.signature.hash },
      saltLength: this.config.signature.saltLength
    };
  }

  // Get key derivation parameters
  getKeyDerivationParams(salt) {
    return {
      name: this.config.keyDerivation.algorithm,
      hash: this.config.keyDerivation.hash,
      iterations: this.config.keyDerivation.iterations,
      salt: salt
    };
  }

  // Generate cryptographically secure random bytes
  generateRandomBytes(length) {
    const crypto = require('crypto');
    return crypto.randomBytes(length);
  }

  // Generate random UUID for message IDs
  generateMessageId() {
    const crypto = require('crypto');
    return crypto.randomBytes(this.config.random.messageIdLength).toString('base64');
  }

  // Generate device fingerprint
  generateDeviceFingerprint() {
    const crypto = require('crypto');
    const timestamp = Date.now().toString();
    const random = crypto.randomBytes(this.config.random.deviceIdLength).toString('base64');
    const hash = crypto.createHash('sha256').update(timestamp + random).digest('hex');
    return hash.substring(0, 64); // 64 character fingerprint
  }

  // Validate key strength
  validateKeyStrength(key, keyType = 'rsa') {
    const crypto = require('crypto');

    try {
      if (keyType === 'rsa') {
        // For RSA keys, we'd need to parse the key to check bit length
        // This is a simplified check - in production, you'd want more rigorous validation
        return key.length > 100; // Basic length check
      } else if (keyType === 'aes') {
        // AES key should be 32 bytes for AES-256
        return Buffer.isBuffer(key) && key.length === 32;
      }
      return false;
    } catch (error) {
      console.error('Key validation error:', error);
      return false;
    }
  }

  // Check if WebCrypto API is available in the browser
  isWebCryptoAvailable() {
    return typeof window !== 'undefined' &&
           window.crypto &&
           window.crypto.subtle &&
           window.crypto.getRandomValues;
  }

  // Get configuration value
  get(path, defaultValue = undefined) {
    const keys = path.split('.');
    let current = this.config;

    for (const key of keys) {
      if (current[key] === undefined) {
        return defaultValue;
      }
      current = current[key];
    }

    return current;
  }

  // Validate security configuration
  validateSecurityConfig() {
    const errors = [];

    // Check RSA key size
    if (this.config.rsa.keySize < 2048) {
      errors.push('RSA key size should be at least 2048 bits');
    }

    // Check AES key size
    if (this.config.aes.keySize !== 256) {
      errors.push('AES key size should be 256 bits for security');
    }

    // Check iteration count for PBKDF2
    if (this.config.keyDerivation.iterations < 100000) {
      errors.push('PBKDF2 iterations should be at least 100,000 for security');
    }

    if (errors.length > 0) {
      throw new Error('Security configuration validation failed: ' + errors.join(', '));
    }

    return true;
  }

  // Get complete configuration
  getAll() {
    return { ...this.config };
  }
}

module.exports = new EncryptionConfig();
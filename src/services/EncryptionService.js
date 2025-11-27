const crypto = require('crypto');
const forge = require('node-forge');
const encryptionConfig = require('../config/encryption');

class EncryptionService {
  constructor() {
    this.config = encryptionConfig;
  }

  /**
   * Generate RSA key pair for device
   * @returns {Promise<{publicKey: string, privateKey: string}>}
   */
  async generateRSAKeyPair() {
    try {
      return new Promise((resolve, reject) => {
        // Use node-forge for RSA key generation (more reliable than WebCrypto in Node.js)
        const keySize = this.config.get('rsa.keySize');
        const publicExponent = this.config.get('rsa.publicExponent');

        forge.pki.rsa.generateKeyPair({
          bits: keySize,
          e: publicExponent,
          workers: -1 // Use all available workers
        }, (err, keyPair) => {
          if (err) {
            reject(new Error('RSA key generation failed: ' + err.message));
            return;
          }

          try {
            // Convert to PEM format
            const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
            const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);

            // Validate key strength
            if (!this.validateRSAKeyPair(publicKeyPem, privateKeyPem)) {
              reject(new Error('Generated RSA key pair failed validation'));
              return;
            }

            resolve({
              publicKey: publicKeyPem,
              privateKey: privateKeyPem
            });
          } catch (conversionError) {
            reject(new Error('Key conversion failed: ' + conversionError.message));
          }
        });
      });
    } catch (error) {
      throw new Error('Failed to generate RSA key pair: ' + error.message);
    }
  }

  /**
   * Generate random AES key for message encryption
   * @returns {Buffer} 32-byte AES-256 key
   */
  generateAESKey() {
    try {
      const keySize = this.config.get('aes.keySize') / 8; // Convert bits to bytes
      return crypto.randomBytes(keySize);
    } catch (error) {
      throw new Error('Failed to generate AES key: ' + error.message);
    }
  }

  /**
   * Encrypt message content with AES-256-GCM
   * @param {string|Buffer} message - Message to encrypt
   * @param {Buffer} key - AES key (32 bytes for AES-256)
   * @returns {Promise<{cipherText: string, iv: string, authTag: string}>}
   */
  async encryptWithAES(message, key) {
    try {
      // Validate inputs
      if (!message || !key) {
        throw new Error('Message and key are required');
      }

      if (key.length !== 32) {
        throw new Error('AES key must be 32 bytes for AES-256');
      }

      // Generate random IV
      const ivLength = this.config.get('aes.ivLength');
      const iv = crypto.randomBytes(ivLength);

      // Create cipher
      const algorithm = this.config.get('aes.algorithm');
      const cipher = crypto.createCipher(algorithm, key);

      // Start with empty authTag
      let authTag;

      cipher.setAAD(Buffer.from('darkchat-aes', 'utf8'));

      // Encrypt the message
      let cipherText = cipher.update(message, 'utf8', 'base64');
      cipherText += cipher.final('base64');

      // Get authentication tag
      authTag = cipher.getAuthTag().toString('base64');

      return {
        cipherText,
        iv: iv.toString('base64'),
        authTag
      };
    } catch (error) {
      throw new Error('AES encryption failed: ' + error.message);
    }
  }

  /**
   * Decrypt message content with AES-256-GCM
   * @param {string} cipherText - Base64 encoded ciphertext
   * @param {string} iv - Base64 encoded initialization vector
   * @param {string} authTag - Base64 encoded authentication tag
   * @param {Buffer} key - AES key (32 bytes for AES-256)
   * @returns {Promise<string>} Decrypted message
   */
  async decryptWithAES(cipherText, iv, authTag, key) {
    try {
      // Validate inputs
      if (!cipherText || !iv || !authTag || !key) {
        throw new Error('All AES decryption parameters are required');
      }

      if (key.length !== 32) {
        throw new Error('AES key must be 32 bytes for AES-256');
      }

      // Create decipher
      const algorithm = this.config.get('aes.algorithm');
      const decipher = crypto.createDecipher(algorithm, key);

      // Set AAD and authentication tag
      decipher.setAAD(Buffer.from('darkchat-aes', 'utf8'));
      decipher.setAuthTag(Buffer.from(authTag, 'base64'));

      // Decrypt the message
      let decrypted = decipher.update(cipherText, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      throw new Error('AES decryption failed: ' + error.message);
    }
  }

  /**
   * Encrypt data with RSA public key
   * @param {string|Buffer} data - Data to encrypt (typically AES key)
   * @param {string} publicKey - PEM formatted RSA public key
   * @returns {string} Base64 encrypted data
   */
  encryptWithRSA(data, publicKey) {
    try {
      // Validate inputs
      if (!data || !publicKey) {
        throw new Error('Data and public key are required');
      }

      // Convert public key from PEM
      const rsaPublicKey = forge.pki.publicKeyFromPem(publicKey);

      // Convert data to buffer if it's a string
      const dataBuffer = Buffer.isBuffer(data) ? data : Buffer.from(data);

      // Encrypt with RSA-OAEP
      const encrypted = rsaPublicKey.encrypt(dataBuffer.toString('binary'), 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create()
        }
      });

      return Buffer.from(encrypted, 'binary').toString('base64');
    } catch (error) {
      throw new Error('RSA encryption failed: ' + error.message);
    }
  }

  /**
   * Decrypt data with RSA private key
   * @param {string} encryptedData - Base64 encrypted data
   * @param {string} privateKey - PEM formatted RSA private key
   * @returns {Buffer} Decrypted data
   */
  decryptWithRSA(encryptedData, privateKey) {
    try {
      // Validate inputs
      if (!encryptedData || !privateKey) {
        throw new Error('Encrypted data and private key are required');
      }

      // Convert private key from PEM
      const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKey);

      // Convert from base64 to binary
      const encryptedBinary = Buffer.from(encryptedData, 'base64').toString('binary');

      // Decrypt with RSA-OAEP
      const decrypted = rsaPrivateKey.decrypt(encryptedBinary, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: {
          md: forge.md.sha256.create()
        }
      });

      return Buffer.from(decrypted, 'binary');
    } catch (error) {
      throw new Error('RSA decryption failed: ' + error.message);
    }
  }

  /**
   * Create digital signature for message
   * @param {string} message - Message to sign
   * @param {string} privateKey - PEM formatted RSA private key
   * @returns {string} Base64 encoded signature
   */
  signMessage(message, privateKey) {
    try {
      // Validate inputs
      if (!message || !privateKey) {
        throw new Error('Message and private key are required');
      }

      // Convert private key from PEM
      const rsaPrivateKey = forge.pki.privateKeyFromPem(privateKey);

      // Create message hash
      const md = forge.md.sha256.create();
      md.update(message, 'utf8');

      // Sign with RSA-PSS
      const signature = rsaPrivateKey.sign(md, 'RSASSA-PKCS1-V1_5');

      return forge.util.encode64(signature);
    } catch (error) {
      throw new Error('Message signing failed: ' + error.message);
    }
  }

  /**
   * Verify digital signature
   * @param {string} message - Original message
   * @param {string} signature - Base64 encoded signature
   * @param {string} publicKey - PEM formatted RSA public key
   * @returns {boolean} True if signature is valid
   */
  verifySignature(message, signature, publicKey) {
    try {
      // Validate inputs
      if (!message || !signature || !publicKey) {
        return false;
      }

      // Convert public key from PEM
      const rsaPublicKey = forge.pki.publicKeyFromPem(publicKey);

      // Create message hash
      const md = forge.md.sha256.create();
      md.update(message, 'utf8');

      // Decode signature from base64
      const signatureBytes = forge.util.decode64(signature);

      // Verify with RSASSA-PKCS1-V1_5
      const verified = rsaPublicKey.verify(md.digest().bytes(), signatureBytes, 'RSASSA-PKCS1-V1_5');

      return verified;
    } catch (error) {
      // Signature verification failed
      return false;
    }
  }

  /**
   * Complete message encryption process
   * @param {string} message - Plain text message
   * @param {string} recipientPublicKey - Recipient's RSA public key
   * @param {string} senderPrivateKey - Sender's RSA private key
   * @returns {Promise<{cipherText, encryptedAESKey, iv, authTag, signature}>}
   */
  async encryptMessage(message, recipientPublicKey, senderPrivateKey) {
    try {
      // Generate AES key for this message
      const aesKey = this.generateAESKey();

      // Encrypt message with AES
      const aesEncrypted = await this.encryptWithAES(message, aesKey);

      // Encrypt AES key with recipient's RSA public key
      const encryptedAESKey = this.encryptWithRSA(aesKey, recipientPublicKey);

      // Sign the message with sender's private key
      const signature = this.signMessage(message, senderPrivateKey);

      return {
        cipherText: aesEncrypted.cipherText,
        iv: aesEncrypted.iv,
        authTag: aesEncrypted.authTag,
        encryptedAESKey,
        signature
      };
    } catch (error) {
      throw new Error('Message encryption failed: ' + error.message);
    }
  }

  /**
   * Complete message decryption process
   * @param {Object} encryptedData - Encrypted message data
   * @param {string} recipientPrivateKey - Recipient's RSA private key
   * @param {string} senderPublicKey - Sender's RSA public key
   * @returns {Promise<string>} Decrypted message
   */
  async decryptMessage(encryptedData, recipientPrivateKey, senderPublicKey) {
    try {
      const { cipherText, iv, authTag, encryptedAESKey, signature } = encryptedData;

      // Decrypt AES key with recipient's RSA private key
      const aesKey = this.decryptWithRSA(encryptedAESKey, recipientPrivateKey);

      // Decrypt message with AES
      const decryptedMessage = await this.decryptWithAES(cipherText, iv, authTag, aesKey);

      // Verify signature with sender's public key
      const isValidSignature = this.verifySignature(decryptedMessage, signature, senderPublicKey);

      if (!isValidSignature) {
        throw new Error('Invalid message signature');
      }

      return decryptedMessage;
    } catch (error) {
      throw new Error('Message decryption failed: ' + error.message);
    }
  }

  /**
   * Generate secure random bytes
   * @param {number} length - Number of bytes to generate
   * @returns {Buffer}
   */
  generateRandomBytes(length) {
    try {
      return crypto.randomBytes(length);
    } catch (error) {
      throw new Error('Failed to generate random bytes: ' + error.message);
    }
  }

  /**
   * Validate RSA key pair
   * @param {string} publicKey - PEM formatted public key
   * @param {string} privateKey - PEM formatted private key
   * @returns {boolean}
   */
  validateRSAKeyPair(publicKey, privateKey) {
    try {
      // Test encryption/decryption
      const testData = 'test-data-for-key-validation';
      const encrypted = this.encryptWithRSA(testData, publicKey);
      const decrypted = this.decryptWithRSA(encrypted, privateKey);

      return decrypted.toString() === testData;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate public key format
   * @param {string} publicKey - PEM formatted public key
   * @returns {boolean}
   */
  validatePublicKey(publicKey) {
    try {
      forge.pki.publicKeyFromPem(publicKey);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate private key format
   * @param {string} privateKey - PEM formatted private key
   * @returns {boolean}
   */
  validatePrivateKey(privateKey) {
    try {
      forge.pki.privateKeyFromPem(privateKey);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate key fingerprint for identification
   * @param {string} publicKey - PEM formatted public key
   * @returns {string} SHA-256 hash fingerprint
   */
  generateKeyFingerprint(publicKey) {
    try {
      const hash = crypto.createHash('sha256');
      hash.update(publicKey);
      return hash.digest('hex').substring(0, 32);
    } catch (error) {
      throw new Error('Failed to generate key fingerprint: ' + error.message);
    }
  }

  /**
   * Derive key from password using PBKDF2
   * @param {string} password - Password
   * @param {Buffer} salt - Random salt
   * @returns {Buffer} Derived key
   */
  deriveKey(password, salt) {
    try {
      const iterations = this.config.get('keyDerivation.iterations');
      const keyLength = this.config.get('aes.keySize') / 8;
      const hash = this.config.get('keyDerivation.hash');

      return crypto.pbkdf2Sync(password, salt, iterations, keyLength, hash);
    } catch (error) {
      throw new Error('Key derivation failed: ' + error.message);
    }
  }

  /**
   * Generate salt for key derivation
   * @param {number} length - Salt length in bytes
   * @returns {Buffer}
   */
  generateSalt(length = null) {
    const saltLength = length || this.config.get('keyDerivation.saltLength');
    return this.generateRandomBytes(saltLength);
  }

  /**
   * Compare two buffers in constant time to prevent timing attacks
   * @param {Buffer} a - First buffer
   * @param {Buffer} b - Second buffer
   * @returns {boolean} True if buffers are equal
   */
  constantTimeCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }

    return result === 0;
  }

  /**
   * Clear sensitive data from memory
   * @param {Buffer|string} data - Sensitive data to clear
   */
  clearSensitiveData(data) {
    try {
      if (Buffer.isBuffer(data)) {
        data.fill(0);
      } else if (typeof data === 'string') {
        // For strings, we can't directly clear memory in JavaScript
        // But we can overwrite the variable reference
        data = '';
      }
    } catch (error) {
      // Ignore errors during cleanup
    }
  }
}

module.exports = EncryptionService;
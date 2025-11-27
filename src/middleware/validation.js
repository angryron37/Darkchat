const { body, param, query, validationResult } = require('express-validator');
const config = require('../config/app');

class ValidationMiddleware {
  constructor() {
    this.config = config;
  }

  // Handle validation errors
  handleValidationErrors() {
    return (req, res, next) => {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        const isJsonRequest = req.xhr || req.headers.accept === 'application/json';

        if (isJsonRequest) {
          return res.status(400).json({
            success: false,
            error: 'Validation failed',
            details: errors.array().map(error => ({
              field: error.path,
              message: error.msg,
              value: error.value
            }))
          });
        } else {
          return res.status(400).render('error', {
            error: {
              title: 'Validation Error',
              message: 'Please check your input and try again.',
              details: errors.array()
            }
          });
        }
      }

      next();
    };
  }

  // Username validation
  validateUsername() {
    return body('username')
      .trim()
      .isLength({
        min: this.config.get('limits.minUsernameLength'),
        max: this.config.get('limits.maxUsernameLength')
      })
      .withMessage(`Username must be between ${this.config.get('limits.minUsernameLength')} and ${this.config.get('limits.maxUsernameLength')} characters`)
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores')
      .escape();
  }

  // Message content validation
  validateMessageContent() {
    return body('content')
      .trim()
      .isLength({ max: this.config.get('limits.maxMessageLength') })
      .withMessage(`Message cannot exceed ${this.config.get('limits.maxMessageLength')} characters`)
      .not()
      .isEmpty()
      .withMessage('Message content cannot be empty')
      .escape();
  }

  // Recipient validation
  validateRecipient() {
    return body('recipient')
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('Recipient username must be between 2 and 50 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Recipient username can only contain letters, numbers, and underscores')
      .escape();
  }

  // Public key validation
  validatePublicKey() {
    return body('publicKey')
      .trim()
      .isLength({ min: 100 })
      .withMessage('Public key is too short')
      .matches(/^(-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----|[A-Za-z0-9+/]+={0,2})$/)
      .withMessage('Invalid public key format');
  }

  // Device fingerprint validation
  validateDeviceFingerprint() {
    return body('deviceFingerprint')
      .trim()
      .isLength({ min: 32, max: 64 })
      .withMessage('Device fingerprint must be between 32 and 64 characters')
      .isHexadecimal()
      .withMessage('Device fingerprint must be hexadecimal');
  }

  // Message ID validation
  validateMessageId() {
    return param('messageId')
      .trim()
      .isLength({ min: 16, max: 100 })
      .withMessage('Invalid message ID format')
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage('Invalid message ID characters');
  }

  // User ID validation
  validateUserId() {
    return param('userId')
      .isUUID()
      .withMessage('Invalid user ID format');
  }

  // Username parameter validation
  validateUsernameParam() {
    return param('username')
      .trim()
      .isLength({ min: 2, max: 50 })
      .withMessage('Username must be between 2 and 50 characters')
      .matches(/^[a-zA-Z0-9_]+$/)
      .withMessage('Username can only contain letters, numbers, and underscores');
  }

  // Message expiration validation
  validateMessageExpiration() {
    return body('expiresIn')
      .optional()
      .isInt({ min: 60, max: 86400 }) // 1 minute to 24 hours
      .withMessage('Expiration time must be between 60 and 86400 seconds');
  }

  // One-time view validation
  validateOneTimeView() {
    return body('oneTimeView')
      .optional()
      .isBoolean()
      .withMessage('One-time view must be a boolean value');
  }

  // Anonymous message validation
  validateAnonymous() {
    return body('anonymous')
      .optional()
      .isBoolean()
      .withMessage('Anonymous flag must be a boolean value');
  }

  // Encrypted data validation
  validateEncryptedData(field) {
    return body(field)
      .trim()
      .isLength({ min: 1 })
      .withMessage(`${field} cannot be empty`)
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage(`Invalid ${field} format - must be base64 encoded`);
  }

  // AES key validation
  validateAESKey() {
    return body('encryptedAESKey')
      .trim()
      .isLength({ min: 100 }) // RSA encrypted 32-byte key + padding
      .withMessage('Encrypted AES key is too short')
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage('Invalid encrypted AES key format');
  }

  // Signature validation
  validateSignature() {
    return body('signature')
      .trim()
      .isLength({ min: 100 })
      .withMessage('Signature is too short')
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage('Invalid signature format');
  }

  // IV (Initialization Vector) validation
  validateIV() {
    return body('iv')
      .trim()
      .isLength({ min: 12, max: 24 }) // GCM recommended length
      .withMessage('IV must be between 12 and 24 characters')
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage('Invalid IV format - must be base64 encoded');
  }

  // Auth tag validation
  validateAuthTag() {
    return body('authTag')
      .trim()
      .isLength({ min: 16, max: 24 }) // GCM authentication tag
      .withMessage('Auth tag must be between 16 and 24 characters')
      .matches(/^[A-Za-z0-9+/=]+$/)
      .withMessage('Invalid authentication tag format');
  }

  // Complete message validation for sending
  validateSendMessage() {
    return [
      this.validateRecipient(),
      this.validateEncryptedData('cipherText'),
      this.validateAESKey(),
      this.validateSignature(),
      this.validateIV(),
      this.validateAuthTag(),
      this.validateMessageExpiration(),
      this.validateOneTimeView(),
      this.validateAnonymous(),
      this.handleValidationErrors()
    ];
  }

  // Complete message validation for retrieving
  validateRetrieveMessage() {
    return [
      this.validateMessageId(),
      this.handleValidationErrors()
    ];
  }

  // User registration validation
  validateUserRegistration() {
    return [
      this.validateUsername(),
      this.validatePublicKey(),
      this.validateDeviceFingerprint(),
      this.handleValidationErrors()
    ];
  }

  // Device key registration validation
  validateDeviceRegistration() {
    return [
      this.validatePublicKey(),
      this.validateDeviceFingerprint(),
      this.handleValidationErrors()
    ];
  }

  // Login validation
  validateLogin() {
    return [
      this.validateUsername(),
      this.handleValidationErrors()
    ];
  }

  // Chat room access validation
  validateChatAccess() {
    return [
      this.validateUsernameParam(),
      this.handleValidationErrors()
    ];
  }

  // Query parameter validation for pagination
  validatePagination() {
    return [
      query('page')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Page must be a positive integer'),
      query('limit')
        .optional()
        .isInt({ min: 1, max: 100 })
        .withMessage('Limit must be between 1 and 100'),
      this.handleValidationErrors()
    ];
  }

  // Date range validation
  validateDateRange() {
    return [
      query('startDate')
        .optional()
        .isISO8601()
        .withMessage('Start date must be a valid ISO 8601 date'),
      query('endDate')
        .optional()
        .isISO8601()
        .withMessage('End date must be a valid ISO 8601 date'),
      this.handleValidationErrors()
    ];
  }

  // Custom validation for complex business rules
  validateBusinessRules() {
    return (req, res, next) => {
      const errors = [];

      // Prevent users from messaging themselves
      if (req.body.recipient && req.session?.username) {
        if (req.body.recipient.toLowerCase() === req.session.username.toLowerCase()) {
          errors.push({
            field: 'recipient',
            message: 'Cannot send messages to yourself'
          });
        }
      }

      // Validate that expiration time is reasonable
      if (req.body.expiresIn) {
        const maxExpiration = 7 * 24 * 60 * 60; // 7 days in seconds
        if (req.body.expiresIn > maxExpiration) {
          errors.push({
            field: 'expiresIn',
            message: 'Message cannot expire more than 7 days from now'
          });
        }
      }

      // Ensure one-time view and long expiration don't conflict
      if (req.body.oneTimeView === true && req.body.expiresIn > 3600) {
        errors.push({
          field: 'expiresIn',
          message: 'One-time view messages should have shorter expiration times'
        });
      }

      if (errors.length > 0) {
        const isJsonRequest = req.xhr || req.headers.accept === 'application/json';

        if (isJsonRequest) {
          return res.status(400).json({
            success: false,
            error: 'Validation failed',
            details: errors
          });
        } else {
          return res.status(400).render('error', {
            error: {
              title: 'Validation Error',
              message: 'Please check your input and try again.',
              details: errors
            }
          });
        }
      }

      next();
    };
  }

  // Sanitize and validate JSON input
  validateJSONInput() {
    return (req, res, next) => {
      if (req.is('application/json')) {
        try {
          // If request body is a string, parse it
          if (typeof req.body === 'string') {
            req.body = JSON.parse(req.body);
          }

          // Validate JSON object
          if (req.body === null || typeof req.body !== 'object') {
            throw new Error('Invalid JSON object');
          }

          // Check for prototype pollution
          if (req.body.__proto__ || req.body.constructor?.prototype) {
            throw new Error('Invalid JSON structure');
          }

        } catch (error) {
          return res.status(400).json({
            success: false,
            error: 'Invalid JSON input'
          });
        }
      }

      next();
    };
  }

  // Validate file uploads (if implemented later)
  validateFileUpload() {
    return (req, res, next) => {
      // Placeholder for future file upload validation
      // For now, reject all file uploads for security
      if (req.files && Object.keys(req.files).length > 0) {
        return res.status(400).json({
          success: false,
          error: 'File uploads are not supported'
        });
      }

      next();
    };
  }
}

module.exports = new ValidationMiddleware();
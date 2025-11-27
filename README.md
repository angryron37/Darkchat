# DarkChat - Secure Anonymous Messaging Platform

🔒 **DarkChat** is a secure, temporary, browser-based communication platform with end-to-end encryption, self-destructing messages, and zero-knowledge architecture.

## 🚀 Features

### Security & Privacy
- **End-to-End Encryption**: RSA-4096 + AES-256-GCM encryption
- **Self-Destructing Messages**: Auto-delete after viewing or timer expiration
- **Zero-Knowledge Architecture**: Server cannot decrypt messages
- **Anonymous Messaging**: Send messages without revealing identity
- **No Chat History**: Messages stored temporarily only
- **One-Time View**: Messages delete immediately after reading
- **Perfect Forward Secrecy**: New encryption keys per message

### Real-time Communication
- **WebSocket Integration**: Instant message delivery
- **Typing Indicators**: See when someone is typing
- **Read Receipts**: Know when messages are read
- **Multi-Device Support**: Each device has unique encryption keys
- **User Status**: Online/offline/away/busy status

## 🛠 Technology Stack

- **Backend**: Node.js, Express.js, PostgreSQL, Redis
- **Frontend**: EJS templates, vanilla JavaScript
- **Cryptography**: RSA-4096, AES-256-GCM, Web Crypto API
- **Real-time**: Socket.IO WebSockets
- **Security**: Helmet.js, CSRF protection, rate limiting

## 📦 Quick Start

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Setup environment**
   ```bash
   cp .env.example .env
   # Edit .env with your database and Redis settings
   ```

3. **Run migrations**
   ```bash
   npm run migrate
   ```

4. **Start the application**
   ```bash
   npm run dev
   ```

5. **Access the application**
   - Open http://localhost:3000
   - Create a username and start chatting securely!

## 🐳 Docker Deployment

```bash
docker-compose up -d
```

## 🔒 Security Features

- Messages are encrypted client-side before sending
- Server stores only encrypted payloads with automatic deletion
- Each message uses a unique AES-256 key
- RSA-4096 for secure key exchange
- Perfect forward secrecy
- Zero-knowledge architecture

## 📚 Documentation

See the complete implementation for detailed documentation on:
- Security architecture
- API endpoints
- Encryption protocols
- Deployment guides

---

**DarkChat** - Private, secure messaging for the privacy-conscious user.

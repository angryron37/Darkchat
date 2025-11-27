# Multi-stage build for optimized production Docker image
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Production stage
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S darkchat -u 1001

# Install runtime dependencies
RUN apk add --no-cache \
    dumb-init \
    && rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /app

# Copy node modules from builder stage
COPY --from=builder --chown=darkchat:nodejs /app/node_modules ./node_modules

# Copy application code
COPY --chown=darkchat:nodejs . .

# Create directories for logs and temp files
RUN mkdir -p /app/logs /app/tmp && \
    chown -R darkchat:nodejs /app/logs /app/tmp

# Switch to non-root user
USER darkchat

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Start application with dumb-init
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "src/app.js"]

# Labels for metadata
LABEL maintainer="DarkChat Team"
LABEL version="1.0.0"
LABEL description="DarkChat - Secure, temporary, browser-based communication platform"
LABEL security.scan="passed"

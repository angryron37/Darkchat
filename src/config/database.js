const knex = require('knex');
const redis = require('redis');

class DatabaseConfig {
  constructor() {
    this.knexInstance = null;
    this.redisInstance = null;
  }

  // PostgreSQL configuration with Knex
  getKnexConfig() {
    return {
      client: 'pg',
      connection: {
        connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/darkchat',
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'darkchat'
      },
      pool: {
        min: 2,
        max: 10,
        acquireTimeoutMillis: 30000,
        createTimeoutMillis: 30000,
        destroyTimeoutMillis: 5000,
        idleTimeoutMillis: 30000,
        reapIntervalMillis: 1000,
        createRetryIntervalMillis: 100
      },
      migrations: {
        directory: './src/migrations',
        tableName: 'knex_migrations'
      },
      useNullAsDefault: true
    };
  }

  // Get Knex instance (singleton pattern)
  getKnex() {
    if (!this.knexInstance) {
      this.knexInstance = knex(this.getKnexConfig());
    }
    return this.knexInstance;
  }

  // Redis configuration
  getRedisConfig() {
    return {
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD || undefined,
      db: process.env.REDIS_DB || 0,
      retryDelayOnFailover: 100,
      enableReadyCheck: false,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      keepAlive: 30000,
      connectTimeout: 10000,
      lazyConnect: true
    };
  }

  // Get Redis instance (singleton pattern)
  async getRedis() {
    if (!this.redisInstance) {
      this.redisInstance = redis.createClient(this.getRedisConfig());

      // Event handlers for connection management
      this.redisInstance.on('connect', () => {
        console.log('Redis client connected');
      });

      this.redisInstance.on('error', (err) => {
        console.error('Redis client error:', err);
      });

      this.redisInstance.on('end', () => {
        console.log('Redis client disconnected');
      });

      this.redisInstance.on('reconnecting', () => {
        console.log('Redis client reconnecting');
      });

      // Connect to Redis
      await this.redisInstance.connect();
    }
    return this.redisInstance;
  }

  // Test database connections
  async testConnections() {
    try {
      // Test PostgreSQL connection
      const knex = this.getKnex();
      await knex.raw('SELECT 1');
      console.log('PostgreSQL connection successful');

      // Test Redis connection
      const redis = await this.getRedis();
      await redis.ping();
      console.log('Redis connection successful');

      return { postgresql: true, redis: true };
    } catch (error) {
      console.error('Database connection test failed:', error);
      throw error;
    }
  }

  // Graceful shutdown
  async close() {
    try {
      if (this.knexInstance) {
        await this.knexInstance.destroy();
        console.log('PostgreSQL connection closed');
      }

      if (this.redisInstance) {
        await this.redisInstance.quit();
        console.log('Redis connection closed');
      }
    } catch (error) {
      console.error('Error closing database connections:', error);
      throw error;
    }
  }
}

module.exports = new DatabaseConfig();
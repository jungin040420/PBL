const mysql = require('mysql2/promise');
const redis = require('redis');

//MySQL
const db = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '9789',
  database: process.env.DB_NAME     || 'mfa_db',
});

const testDBConnection = async () => {
  try {
    const conn = await db.getConnection();
    console.log('MySQL 연결 성공');
    conn.release();
  } catch (error) {
    console.error('MySQL 연결 실패:', error.message);
  }
};
testDBConnection();

//Redis
const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
  }
});

redisClient.on('connect', () => {
  console.log('Redis 연결 성공');
});

redisClient.on('error', (error) => {
  console.error('Redis 연결 실패:', error.message);
});

const connectRedis = async () => {
  try {
    await redisClient.connect();
    console.log('Redis connect() 완료');

    await redisClient.set('test', 'hello');
    const val = await redisClient.get('test');
    console.log('Redis 테스트 값:', val);
    await redisClient.del('test');

  } catch (error) {
    console.error('Redis connect() 실패:', error.message);
  }
};
connectRedis();

module.exports = { db, redisClient };
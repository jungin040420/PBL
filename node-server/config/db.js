const mysql = require('mysql2/promise');
const redis = require('redis');

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

const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
  }
});

redisClient.connect();
module.exports = { db, redisClient };
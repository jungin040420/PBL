const mysql = require('mysql2/promise');
const redis = require('redis');

//MySQL
const db = mysql.createPool({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

const authDb = mysql.createPool({
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.AUTH_DB_NAME || 'authdb', 
});

const mlPool = mysql.createPool({
  host:     process.env.ML_DB_HOST,
  user:     process.env.ML_DB_USER,
  password: process.env.ML_DB_PASSWORD,
  database: process.env.ML_DB_NAME,
});

const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
for (const key of requiredEnvVars) {
  if (!process.env[key]) {
    throw new Error(`[설정 오류] 환경변수 ${key}가 설정되지 않았습니다. .env.dev를 확인하세요.`);
  }
}

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

redisClient.on('connect', () => {console.log('Redis 연결 성공');});

redisClient.on('error', (error) => {console.error('Redis 연결 실패:', error.message);});

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

module.exports = { db, mlPool, redisClient };
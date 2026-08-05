const mysql = require("mysql2/promise");
const redis = require("redis");

// MySQL
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "9789",
  database: process.env.DB_NAME || "mfa_db",

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const testDBConnection = async () => {
  let conn;

  try {
    conn = await db.getConnection();

    await conn.query("SELECT 1");

    console.log("MySQL 연결 성공", {
      host: process.env.DB_HOST || "localhost",
      port: Number(process.env.DB_PORT || 3306),
      database: process.env.DB_NAME || "mfa_db",
      hasUser: Boolean(process.env.DB_USER),
    });
  } catch (error) {
    console.error("MySQL 연결 실패:", error.message);
  } finally {
    if (conn) {
      conn.release();
    }
  }
};

testDBConnection();

// Redis
const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST || "localhost",
    port: Number(process.env.REDIS_PORT || 6379),

    reconnectStrategy: (retries) => {
      if (retries > 10) {
        return new Error(
            "Redis 재연결 최대 횟수를 초과했습니다."
        );
      }

      return Math.min(retries * 500, 3000);
    },
  },
});

redisClient.on("connect", () => {
  console.log("Redis 연결 성공");
});

redisClient.on("ready", () => {
  console.log("Redis 사용 준비 완료");
});

redisClient.on("error", (error) => {
  console.error("Redis 연결 실패:", error.message);
});

const connectRedis = async () => {
  try {
    if (!redisClient.isOpen) {
      await redisClient.connect();
    }

    console.log("Redis connect() 완료");

    await redisClient.set("test", "hello");

    const value = await redisClient.get("test");

    console.log("Redis 테스트 값:", value);

    await redisClient.del("test");
  } catch (error) {
    console.error(
        "Redis connect() 실패:",
        error.message
    );
  }
};

connectRedis();

module.exports = {
  db,
  redisClient,
};
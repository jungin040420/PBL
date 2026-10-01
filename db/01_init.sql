CREATE USER IF NOT EXISTS 'authuser'@'%' IDENTIFIED BY '<AUTH_USER_PASSWORD>';

CREATE DATABASE IF NOT EXISTS mfa_db;
USE mfa_db;

GRANT ALL PRIVILEGES ON mfa_db.* TO 'authuser'@'%';

CREATE TABLE IF NOT EXISTS users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)  NOT NULL UNIQUE,
  display_name  VARCHAR(100) NOT NULL,
  email         VARCHAR(100) NOT NULL UNIQUE,
  last_login_region VARCHAR(10) DEFAULT NULL,
  created_at    DATETIME     DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS passkeys (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT          NOT NULL,
  credential_id  VARCHAR(500) NOT NULL UNIQUE,
  public_key     TEXT         NOT NULL,
  counter        INT          DEFAULT 0,
  created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
  authenticator_type VARCHAR(50)  DEFAULT 'unknown',
  is_active      TINYINT(1)   DEFAULT 1,

  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id          BIGINT       AUTO_INCREMENT PRIMARY KEY,
  event_type  VARCHAR(50)  NOT NULL,
  payload     TEXT         NOT NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
 
-- 연결 확인용 테스트 데이터 (나중에 삭제)
INSERT IGNORE INTO users (username, display_name, email)
VALUES ('testuser', '테스트 유저', 'test@test.com');

-- authdb
CREATE DATABASE IF NOT EXISTS authdb;
USE authdb;

GRANT SELECT, INSERT, UPDATE, DELETE ON authdb.* TO 'authuser'@'%';

-- 멀티 소스 접속 로그
CREATE TABLE IF NOT EXISTS access_logs (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     VARCHAR(64),
    -- device      VARCHAR(255),
    -- user_agent  TEXT, 
    -- location    VARCHAR(100), -> 필요한 건지 확인 후 수정
    auth_result ENUM('success','fail') NOT NULL,
    reason      VARCHAR(255),
    created_at  DATETIME      NOT NULL DEFAULT NOW()
);

-- F-11: 리스크 점수 기록
CREATE TABLE IF NOT EXISTS risk_scores (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     VARCHAR(64),
    ip          VARCHAR(45),  -- 추후 수정 필요
    device      VARCHAR(255),
    score       INT           NOT NULL DEFAULT 0,
    reason      JSON,
    created_at  DATETIME      NOT NULL DEFAULT NOW()
);

-- F-13: 로그 중앙 집중화
CREATE TABLE IF NOT EXISTS unified_logs (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    source      VARCHAR(50)   NOT NULL,
    level       ENUM('info','warn','error') NOT NULL DEFAULT 'info',
    message     TEXT,
    meta        JSON,
    created_at  DATETIME      NOT NULL DEFAULT NOW()
);

-- 인덱스
CREATE INDEX idx_access_user    ON access_logs(user_id);
CREATE INDEX idx_access_created ON access_logs(created_at);
CREATE INDEX idx_risk_user      ON risk_scores(user_id);
CREATE INDEX idx_unified_source ON unified_logs(source);
CREATE INDEX idx_unified_created ON unified_logs(created_at);

FLUSH PRIVILEGES;
CREATE DATABASE IF NOT EXISTS authdb;
USE authdb;

-- F-12: 멀티 소스 접속 로그
CREATE TABLE IF NOT EXISTS access_logs (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     VARCHAR(64),
    ip          VARCHAR(45)   NOT NULL,
    device      VARCHAR(255),
    user_agent  TEXT,
    location    VARCHAR(100),
    auth_result ENUM('success','fail') NOT NULL,
    created_at  DATETIME      NOT NULL DEFAULT NOW()
);

-- F-11: 리스크 점수 기록
CREATE TABLE IF NOT EXISTS risk_scores (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     VARCHAR(64),
    ip          VARCHAR(45),
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
CREATE INDEX idx_access_ip      ON access_logs(ip);
CREATE INDEX idx_access_user    ON access_logs(user_id);
CREATE INDEX idx_access_created ON access_logs(created_at);
CREATE INDEX idx_risk_user      ON risk_scores(user_id);
CREATE INDEX idx_unified_source ON unified_logs(source);
CREATE INDEX idx_unified_created ON unified_logs(created_at);
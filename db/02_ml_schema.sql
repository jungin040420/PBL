-- =====================================================================
-- 02_ml_schema.sql
-- ML 학습용 피처 로그 저장소 스키마
--
-- 근거 문서 : F-07 v9.4 §5 ⑧ (테이블·컬럼 정의)
--             F-08 v2.6 §1   (접근통제 3요건 / 등급 분류)
--             F-09 v2.3 §3   (보존기간·파기)
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
-- 수정일     : 2026.08.25
--
-- [실행 순서] 01_init.sql → 본 파일 → 03_ml_grants.sql → 04_purge_event.sql
-- [적용 방법]
--   (A) docker-compose mysql volumes: ./db:/docker-entrypoint-initdb.d 마운트 후 초기화
--   (B) 또는 기존 DB에 ALTER TABLE 별도 적용
-- [주의] CREATE TABLE IF NOT EXISTS는 기존 테이블 구조를 자동 변경하지 않음
-- =====================================================================


-- 1. 스키마 생성 -------------------------------------------------------
--    mfa_db(원본 식별정보)와 ml_db(학습 데이터)를 분리 (F-08 §1)
-- ---------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS ml_db
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE ml_db;


-- 2. ml_feature_logs — ML 입력 Feature (append-only) ------------------
--    쓰기 주체: Python Risk 서버 (로그인 이벤트당 1회 INSERT)
--    원본 IP·기기 ID·credentialId 직접 저장 금지 — 파생 Feature만 저장
--    data_source: REAL=실제 로그인, TEST=회귀/테스트 데이터
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_feature_logs (

    -- [메타] ──────────────────────────────────────────────────────────

                                               event_id                      VARCHAR(32)  NOT NULL
    COMMENT 'PK. 로그인 이벤트 식별자. Python Risk 서버 생성. ml_predictions 연결 키',

    created_at                    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    COMMENT 'INSERT 시각. 보존 및 Sliding Window 기준 컬럼',

    data_source                   VARCHAR(20)  NOT NULL DEFAULT 'REAL'
    COMMENT '데이터 출처. REAL=실제 로그인, TEST=회귀/테스트',


    -- [식별자] — 그룹핑/시계열 분석용 (모델 입력 Feature 아님) ────────

    user_id_hash                  CHAR(64)     NOT NULL
    COMMENT 'SHA-256 + USERID_SALT 기반 사용자 식별자 해시',


    -- [B] Behavior ────────────────────────────────────────────────────

    login_frequency               INT          NULL
    COMMENT '로그인 빈도',

    failed_login_count            INT          NULL
    COMMENT '로그인 실패 횟수',

    challenge_response_time       FLOAT        NULL
    COMMENT 'WebAuthn Challenge 응답시간(ms)',

    authentication_method_changed TINYINT(1)   NULL
    COMMENT '0/1. 인증 수단 변경 여부',


    -- [N] Network ─────────────────────────────────────────────────────

    ip_changed                    TINYINT(1)   NULL
    COMMENT '0/1. IP 변경 여부. 원본 IP·IP 해시 저장하지 않음',

    region_changed                TINYINT(1)   NULL
    COMMENT '0/1. 접속 지역 변경 여부',


    -- [D] Device ──────────────────────────────────────────────────────

    sign_count_abnormal           TINYINT(1)   NULL
    COMMENT '0/1. WebAuthn signCount 이상 여부',

    credential_mismatch           TINYINT(1)   NULL
    COMMENT '0/1. Credential 불일치 여부. 원본 credentialId 저장하지 않음',

    user_agent_changed            TINYINT(1)   NULL
    COMMENT '0/1. User-Agent 변경 여부',

    is_new_device                 TINYINT(1)   NULL
    COMMENT '0/1. 직전 로그인 대비 기기 변경 여부',


    -- [T] Threat History ──────────────────────────────────────────────

    consecutive_failure_count     INT          NULL
    COMMENT '연속 로그인 실패 횟수',

    blacklist_ip_detected         TINYINT(1)   NULL
    COMMENT '0/1. 블랙리스트 IP 탐지 결과. 원본 IP 저장하지 않음',


    -- [C] Context ─────────────────────────────────────────────────────

    login_hour                    TINYINT      NULL
    COMMENT '0~23. 로그인 시간대',

    day_of_week                   TINYINT      NULL
    COMMENT '0~6. 로그인 요일',

    login_region                  VARCHAR(32)  NULL
    COMMENT '로그인 지역 코드. 예: KR',

    has_previous_context          TINYINT(1)   NULL
    COMMENT '0/1. Redis에 이전 로그인 Context 존재 여부',


    -- Key / Index ─────────────────────────────────────────────────────

    PRIMARY KEY (event_id),

    INDEX idx_created_at (created_at),

    INDEX idx_user_created (user_id_hash, created_at),

    INDEX idx_data_source_created (data_source, created_at)

    ) ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    COLLATE=utf8mb4_unicode_ci
    COMMENT='ML 입력 피처 벡터. append-only. REAL/TEST 데이터 구분';


-- 3. ml_predictions — Isolation Forest 추론 결과 ----------------------
--    ml_feature_logs와 FK 미설정 (보존기간 상이 → 파기 시 FK 충돌 방지)
--    event_id로 논리 연결
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_predictions (

                                              event_id             VARCHAR(32)  NOT NULL
    COMMENT 'PK. ml_feature_logs와 논리 연결되는 로그인 이벤트 식별자',

    anomaly_score        FLOAT        NULL
    COMMENT 'Isolation Forest anomaly score (score_samples() 반환값)',

    anomaly_label        VARCHAR(16)  NULL
    COMMENT 'NORMAL / ANOMALY',

    model_version        VARCHAR(32)  NULL
    COMMENT '모델 버전. 예: iforest-v1.0.0',

    top_anomaly_features JSON         NULL
    COMMENT '이상 판단 기여 Feature 목록. 관리자 검토 및 감사용',

    predicted_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    COMMENT 'ML 추론 시각. 보존 및 파기 기준 컬럼',

    PRIMARY KEY (event_id),

    INDEX idx_predicted_at (predicted_at)

    ) ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    COLLATE=utf8mb4_unicode_ci
    COMMENT='Isolation Forest 추론 결과';
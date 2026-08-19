-- =====================================================================
-- 02_ml_schema.sql
-- ML 학습용 피처 로그 저장소 스키마
--
-- 근거 문서 : F-07 v9.1 §5 ⑧ (테이블·컬럼 정의)
--             F-08 v2.1 §1   (접근통제 3요건 / 등급 분류)
--             F-09 v2.0 §3   (보존기간·파기)
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
-- 수정일     : 2026.08.18
--
-- [적용 방법]
--   (A) docker-compose mysql 서비스에
--       volumes:
--         - ./db:/docker-entrypoint-initdb.d
--       마운트 후 신규 DB 초기화 시 적용
--
--   (B) 또는 필요한 ALTER TABLE을 기존 DB에 별도 적용
--
-- [주의]
--   CREATE TABLE IF NOT EXISTS는 이미 존재하는 테이블 구조를
--   자동으로 변경하지 않는다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. 스키마 생성
--
-- F-08 §1 통제요건:
-- 원본 식별정보를 저장하는 사용자 테이블(mfa_db)과
-- ML 학습 데이터 저장소(ml_db)를 분리한다.
-- ---------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS ml_db
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE ml_db;


-- ---------------------------------------------------------------------
-- 2. ml_feature_logs
--
-- ML 입력 Feature 저장용 append-only 테이블
--
-- 쓰기 시점:
--   로그인 이벤트 발생 후 Python Risk 서버에서 1회 INSERT
--
-- 저장 원칙:
--   원본 IP / 기기 ID / credential ID 등을 직접 저장하지 않는다.
--
--   IP 관련 정보:
--     ip_hash 저장 X
--     ip_changed 파생 Feature 저장 O
--
--   User-Agent 관련 정보:
--     원본 User-Agent 저장 X
--     user_agent_changed 파생 Feature 저장 O
--
-- data_source:
--   REAL = 실제 로그인 과정에서 생성된 데이터
--   TEST = 회귀/테스트용 데이터
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ml_feature_logs (

    -- ================================================================
    -- [메타]
    -- ================================================================

                                               event_id                      VARCHAR(32)  NOT NULL
    COMMENT 'PK. 로그인 이벤트 식별자. Python Risk 서버 생성. ml_predictions 연결 키',

    created_at                    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    COMMENT 'INSERT 시각. 데이터 보존 및 Sliding Window 기준 컬럼',

    data_source                   VARCHAR(20)  NOT NULL DEFAULT 'REAL'
    COMMENT '데이터 출처. REAL=실제 로그인 데이터, TEST=회귀/테스트 데이터',


    -- ================================================================
    -- [식별자]
    --
    -- 모델 입력 Feature가 아니라 사용자별 그룹핑/시계열 분석용
    -- ================================================================

    user_id_hash                  CHAR(64)     NOT NULL
    COMMENT 'SHA-256 + USERID_SALT 기반 사용자 식별자 해시. 모델 직접 입력 Feature 아님',


    -- ================================================================
    -- [B] Behavior
    -- ================================================================

    login_frequency               INT          NULL
    COMMENT '로그인 빈도. 이상 로그인 빈도 탐지용 Feature',

    failed_login_count            INT          NULL
    COMMENT '로그인 실패 횟수. 실패 패턴 탐지용 Feature',

    challenge_response_time       FLOAT        NULL
    COMMENT 'WebAuthn Challenge 응답시간(ms). 자동화 및 비정상 응답속도 탐지용 Feature',

    authentication_method_changed TINYINT(1)   NULL
    COMMENT '0/1. 인증 수단 변경 여부',


    -- ================================================================
    -- [N] Network
    -- ================================================================

    ip_changed                    TINYINT(1)   NULL
    COMMENT '0/1. 이전 로그인 대비 IP 변경 여부. 원본 IP 또는 IP 해시는 저장하지 않음',

    region_changed                TINYINT(1)   NULL
    COMMENT '0/1. 이전 로그인 대비 접속 지역 변경 여부',


    -- ================================================================
    -- [D] Device
    -- ================================================================

    sign_count_abnormal           TINYINT(1)   NULL
    COMMENT '0/1. WebAuthn signCount 이상 여부. 리플레이 공격 탐지',

    credential_mismatch           TINYINT(1)   NULL
    COMMENT '0/1. Credential 불일치 여부. 원본 credentialId는 저장하지 않음',

    user_agent_changed            TINYINT(1)   NULL
    COMMENT '0/1. 이전 로그인 대비 User-Agent 변경 여부',

    is_new_device                 TINYINT(1)   NULL
    COMMENT '0/1. 신규 Device 여부. 0=기존 기기, 1=신규 기기',


    -- ================================================================
    -- [T] Threat History
    -- ================================================================

    consecutive_failure_count     INT          NULL
    COMMENT '연속 로그인 실패 횟수. 반복 공격 탐지용',

    blacklist_ip_detected         TINYINT(1)   NULL
    COMMENT '0/1. 블랙리스트 IP 탐지 결과. 원본 IP는 저장하지 않음',


    -- ================================================================
    -- [C] Context
    -- ================================================================

    login_hour                    TINYINT      NULL
    COMMENT '0~23. 로그인 시간대 Feature',

    day_of_week                   TINYINT      NULL
    COMMENT '0~6. 로그인 요일 Feature',

    login_region                  VARCHAR(32)  NULL
    COMMENT '현재 로그인 지역 코드. 예: KR',

    has_previous_context          TINYINT(1)   NULL
    COMMENT '0/1. Redis에 이전 로그인 Context 존재 여부',


    -- ================================================================
    -- Key / Index
    -- ================================================================

    PRIMARY KEY (event_id),

    -- 데이터 보존/파기 쿼리 성능 확보
    INDEX idx_created_at (created_at),

    -- 사용자별 시계열 조회 및 재학습 데이터 추출
    INDEX idx_user_created (user_id_hash, created_at),

    -- REAL / TEST 데이터 분리 조회
    INDEX idx_data_source_created (data_source, created_at)

    ) ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    COLLATE=utf8mb4_unicode_ci
    COMMENT='ML 입력 피처 벡터. append-only. REAL/TEST 데이터 구분';


-- ---------------------------------------------------------------------
-- 3. ml_predictions
--
-- Isolation Forest 추론 결과 저장
--
-- ml_feature_logs와 FOREIGN KEY를 설정하지 않는다.
--
-- 이유:
--   Feature 데이터와 Prediction 데이터의 보존기간이 다를 수 있으며,
--   Feature 데이터 파기 시 FK 제약으로 삭제가 실패하는 것을 방지한다.
--
-- 두 테이블은 event_id를 통해 논리적으로 연결한다.
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ml_predictions (

                                              event_id             VARCHAR(32)  NOT NULL
    COMMENT 'PK. ml_feature_logs와 논리적으로 연결되는 로그인 이벤트 식별자',

    anomaly_score        FLOAT        NULL
    COMMENT 'Isolation Forest 모델 원시 anomaly score. score_samples() 반환값',

    anomaly_label        VARCHAR(16)  NULL
    COMMENT 'NORMAL / ANOMALY',

    model_version        VARCHAR(32)  NULL
    COMMENT 'Isolation Forest 모델 버전. 예: iforest-v1.0.0',

    top_anomaly_features JSON         NULL
    COMMENT '이상 판단에 기여한 Feature 목록. 관리자 검토 및 감사 참고용',

    predicted_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    COMMENT 'ML 추론 시각. 보존 및 파기 기준 컬럼',

    PRIMARY KEY (event_id),

    INDEX idx_predicted_at (predicted_at)

    ) ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    COLLATE=utf8mb4_unicode_ci
    COMMENT='Isolation Forest 추론 결과';


-- ---------------------------------------------------------------------
-- 4. 데이터 보존 정책 참고
--
-- REAL Feature 데이터:
--   REAL 데이터만 90일 Sliding Window 대상으로 관리한다.
--
-- TEST 데이터:
--   Regression Test 기준 데이터로 사용하기 때문에
--   REAL 데이터 자동 파기 조건에서 제외한다.
--
-- 주의:
--   아래 DELETE는 정책 참고용이며 자동 EVENT 등록 여부는
--   F-09 운영 정책에 따라 별도로 결정한다.
-- ---------------------------------------------------------------------

-- REAL 데이터 90일 초과 삭제 예시
--
-- DELETE FROM ml_feature_logs
-- WHERE data_source = 'REAL'
--   AND created_at < NOW() - INTERVAL 90 DAY;


-- ---------------------------------------------------------------------
-- 5. Prediction 보존 정책 참고
--
-- ml_predictions:
--   1년 보존 정책 적용 시 아래 조건으로 파기 가능
-- ---------------------------------------------------------------------

-- DELETE FROM ml_predictions
-- WHERE predicted_at < NOW() - INTERVAL 1 YEAR;
-- =====================================================================
-- 04_purge_event.sql
-- MySQL Event Scheduler 자동 파기 Event 등록
--
-- 근거 문서 : F-09 v2.3 §3 「Event Scheduler 실행 주기 및 파기 쿼리 정의」
--
--   테이블               보존기간    조건
--   audit_logs           1년        created_at 기준
--   access_logs          1년        created_at 기준
--   ml_feature_logs      90일       data_source='REAL' / created_at 기준
--   ml_predictions       1년        predicted_at 기준
--   risk_scores          1년        created_at 기준
--
-- 실행 주기 : 매일 새벽 02:00
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
-- 수정일     : 2026.08.26
--
-- [실행 순서] 01_init.sql → 02_ml_schema.sql → 03_ml_grants.sql → 본 파일
-- [COMMENT]   Event COMMENT는 ASCII 표기 (EC2 터미널 한글 손실 방지)
-- [실행 주체] 관리자 계정으로 생성 (DEFINER)
--             ml_writer·ml_reader에는 DELETE 미부여 (F-08 v2.6 §1 최소권한)
-- =====================================================================


-- 0. Event Scheduler 활성화 --------------------------------------------
--    영구 적용: my.cnf [mysqld] event_scheduler = ON
--    확인: SHOW VARIABLES LIKE 'event_scheduler';  → ON
-- ---------------------------------------------------------------------
SET GLOBAL event_scheduler = ON;


-- =====================================================================
-- ML DB
-- =====================================================================
USE ml_db;


-- 1. ml_feature_logs — REAL 데이터 90일 Sliding Window -----------------
--    TEST 데이터는 Regression Test 기준이므로 파기 대상 제외
-- ---------------------------------------------------------------------
DROP EVENT IF EXISTS ev_purge_ml_feature_logs;

CREATE EVENT ev_purge_ml_feature_logs
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (
      TIMESTAMP(CURRENT_DATE)
      + INTERVAL 1 DAY
      + INTERVAL 2 HOUR
    )
  COMMENT
    'F-09 v2.3: ml_feature_logs REAL data, 90-day sliding window, daily 02:00'
  DO
DELETE FROM ml_db.ml_feature_logs
WHERE data_source = 'REAL'
  AND created_at < NOW() - INTERVAL 90 DAY;


-- 2. ml_predictions — 1년 보존 ----------------------------------------
--    ml_feature_logs와 보존기간 상이 → FK 미설정, event_id로 논리 연결
-- ---------------------------------------------------------------------
DROP EVENT IF EXISTS ev_purge_ml_predictions;

CREATE EVENT ev_purge_ml_predictions
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (
      TIMESTAMP(CURRENT_DATE)
      + INTERVAL 1 DAY
      + INTERVAL 2 HOUR
    )
  COMMENT
    'F-09 v2.3: ml_predictions retention 1 year, daily 02:00'
  DO
DELETE FROM ml_db.ml_predictions
WHERE predicted_at < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- MFA DB
-- =====================================================================


-- 3. audit_logs — 감사 로그 1년 보존 ----------------------------------
--    USE ml_db 상태이므로 스키마명 명시
-- ---------------------------------------------------------------------
DROP EVENT IF EXISTS mfa_db.ev_purge_audit_logs;

CREATE EVENT mfa_db.ev_purge_audit_logs
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (
      TIMESTAMP(CURRENT_DATE)
      + INTERVAL 1 DAY
      + INTERVAL 2 HOUR
    )
  COMMENT
    'F-09 v2.3: audit_logs retention 1 year, daily 02:00'
  DO
DELETE FROM mfa_db.audit_logs
WHERE created_at < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- AUTH DB
-- =====================================================================
USE authdb;


-- 4. risk_scores — 1년 보존 -------------------------------------------
--    created_at 인덱스가 없는 경우 아래 주석 해제 후 생성
-- ---------------------------------------------------------------------

-- CREATE INDEX idx_risk_created ON risk_scores(created_at);

DROP EVENT IF EXISTS ev_purge_risk_scores;

CREATE EVENT ev_purge_risk_scores
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (
      TIMESTAMP(CURRENT_DATE)
      + INTERVAL 1 DAY
      + INTERVAL 2 HOUR
    )
  COMMENT
    'F-09 v2.3: risk_scores retention 1 year, daily 02:00'
  DO
DELETE FROM authdb.risk_scores
WHERE created_at < NOW() - INTERVAL 1 YEAR;


-- 5. access_logs — 1년 보존 -------------------------------------------
--    created_at 인덱스(idx_access_created)는 01_init.sql에서 생성 완료
-- ---------------------------------------------------------------------
DROP EVENT IF EXISTS ev_purge_access_logs;

CREATE EVENT ev_purge_access_logs
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (
      TIMESTAMP(CURRENT_DATE)
      + INTERVAL 1 DAY
      + INTERVAL 2 HOUR
    )
  COMMENT
    'F-09 v2.3: access_logs retention 1 year, daily 02:00'
  DO
DELETE FROM authdb.access_logs
WHERE created_at < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- 6. 검증 (적용 후 확인용)
-- =====================================================================
--   SHOW VARIABLES LIKE 'event_scheduler';
--   SHOW EVENTS FROM ml_db;     → ev_purge_ml_feature_logs, ev_purge_ml_predictions
--   SHOW EVENTS FROM mfa_db;    → ev_purge_audit_logs
--   SHOW EVENTS FROM authdb;    → ev_purge_risk_scores, ev_purge_access_logs
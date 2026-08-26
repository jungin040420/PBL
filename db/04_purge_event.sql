-- =====================================================================
-- 04_purge_event.sql
-- MySQL Event Scheduler 자동 파기 Event 등록
--
-- 근거 문서 : F-09 v2.2 §3 「Event Scheduler 실행 주기 및 파기 쿼리 정의」
--
--             audit_logs
--               : 매일 새벽 2시
--               : created_at < NOW() - INTERVAL 1 YEAR
--
--             access_logs
--               : 매일 새벽 2시
--               : created_at < NOW() - INTERVAL 1 YEAR
--
--             ml_feature_logs
--               : 매일 새벽 2시
--               : data_source='REAL'
--               : created_at < NOW() - INTERVAL 90 DAY
--
--             ml_predictions
--               : 매일 새벽 2시
--               : predicted_at < NOW() - INTERVAL 1 YEAR
--
--             risk_scores
--               : 매일 새벽 2시
--               : created_at < NOW() - INTERVAL 1 YEAR
--
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
-- 수정일     : 2026.08.26
--
-- [실행 순서]
--   01_init.sql
--   02_ml_schema.sql
--   03_ml_grants.sql
--   실행 후 적용할 것
--
-- [실행 주체]
--   본 Event는 관리자 계정으로 생성하며,
--   생성한 계정이 DEFINER가 됩니다.
--
--   ml_writer / ml_reader 에는 DELETE 권한을 부여하지 않습니다.
--   (F-08 §1 최소권한)
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. Event Scheduler 활성화
--
-- MySQL Event Scheduler는 기본적으로 비활성화될 수 있으므로
-- 운영 환경에서 활성화 여부를 확인한다.
--
-- 즉시 적용:
--
--   SET GLOBAL event_scheduler = ON;
--
-- 영구 적용:
--
--   my.cnf
--
--   [mysqld]
--   event_scheduler = ON
--
-- 확인:
--
--   SHOW VARIABLES LIKE 'event_scheduler';
--
-- 결과가 ON이어야 정상
-- ---------------------------------------------------------------------

SET GLOBAL event_scheduler = ON;


-- =====================================================================
-- ML DB
-- =====================================================================

USE ml_db;


-- ---------------------------------------------------------------------
-- 1. ml_feature_logs
--
-- REAL 데이터 90일 Sliding Window
--
-- 중요:
--
-- TEST 데이터는 Regression Test 기준 데이터로 유지해야 하므로
-- 자동 파기 대상에서 제외한다.
--
-- 따라서:
--
--   data_source = 'REAL'
--
-- 조건을 반드시 포함한다.
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
    'F-09 v2.2: ml_feature_logs REAL 데이터 90일 Sliding Window 파기. 매일 02:00'

  DO

DELETE FROM ml_db.ml_feature_logs

WHERE data_source = 'REAL'

  AND created_at
    < NOW() - INTERVAL 90 DAY;


-- ---------------------------------------------------------------------
-- 2. ml_predictions
--
-- ML 자동 판단 결과 1년 보존
--
-- ml_feature_logs와 보존기간이 다르므로
-- FOREIGN KEY를 설정하지 않는다.
--
-- event_id를 통해 논리적으로만 연결한다.
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
    'F-09 v2.2: ml_predictions 1년 보존 후 파기. 매일 02:00'

  DO

DELETE FROM ml_db.ml_predictions

WHERE predicted_at
          < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- MFA DB
-- =====================================================================


-- ---------------------------------------------------------------------
-- 3. audit_logs
--
-- 감사 로그 1년 보존
--
-- 본 파일은 USE ml_db 상태이므로
-- Event 이름 및 테이블 이름에 mfa_db 스키마를 명시한다.
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
    'F-09 v2.2: audit_logs 1년 보존 후 파기. 매일 02:00'

  DO

DELETE FROM mfa_db.audit_logs

WHERE created_at
          < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- AUTH DB
-- =====================================================================


-- ---------------------------------------------------------------------
-- 4. risk_scores
--
-- 자동 인증 판단 결과의 감사/이의제기 대응 기록
--
-- 보존기간:
--   1년
--
-- 기존 risk_scores 테이블에는 created_at 인덱스가 없으므로
-- 파기 Event 성능 확보를 위해 인덱스를 추가한다.
--
-- 주의:
--   이미 idx_risk_created 인덱스가 존재하는 환경에서는
--   CREATE INDEX가 실패할 수 있으므로
--   운영 반영 전 SHOW INDEX로 존재 여부를 확인한다.
-- ---------------------------------------------------------------------

USE authdb;


-- ---------------------------------------------------------------------
-- risk_scores created_at 인덱스 확인 예시
--
-- SHOW INDEX FROM risk_scores;
--
-- idx_risk_created가 없다면 아래 CREATE INDEX 실행
-- ---------------------------------------------------------------------

-- CREATE INDEX idx_risk_created
-- ON risk_scores(created_at);


-- ---------------------------------------------------------------------
-- risk_scores 1년 보존 Event
-- ---------------------------------------------------------------------

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
    'F-09 v2.2: risk_scores 1년 보존 후 파기. 매일 02:00'

  DO

DELETE FROM authdb.risk_scores

WHERE created_at
          < NOW() - INTERVAL 1 YEAR;


-- ---------------------------------------------------------------------
-- 5. access_logs
--
-- 인증 성공·실패 접근 기록
--
-- 보존기간:
--   1년
--
-- auth_failures 테이블을 별도로 두지 않고 본 테이블로 통합했으므로
-- (인증·DB 담당 협의 결과) audit_logs와 동일한 보존기간을 적용한다.
--
-- created_at 인덱스(idx_access_created)는 01_init.sql에 이미 존재하므로
-- 별도 인덱스 추가가 필요하지 않다.
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
    'F-09 v2.2: access_logs 1년 보존 후 파기. 매일 02:00'

  DO

DELETE FROM authdb.access_logs

WHERE created_at
          < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- 6. 검증
-- =====================================================================

-- ---------------------------------------------------------------------
-- Event Scheduler 확인
-- ---------------------------------------------------------------------

-- SHOW VARIABLES LIKE 'event_scheduler';


-- ---------------------------------------------------------------------
-- ml_db Event 확인
-- ---------------------------------------------------------------------

-- SHOW EVENTS FROM ml_db;

-- 정상 기대 Event:
--
-- ev_purge_ml_feature_logs
-- ev_purge_ml_predictions


-- ---------------------------------------------------------------------
-- mfa_db Event 확인
-- ---------------------------------------------------------------------

-- SHOW EVENTS FROM mfa_db;

-- 정상 기대 Event:
--
-- ev_purge_audit_logs


-- ---------------------------------------------------------------------
-- authdb Event 확인
-- ---------------------------------------------------------------------

-- SHOW EVENTS FROM authdb;

-- 정상 기대 Event:
--
-- ev_purge_risk_scores
-- ev_purge_access_logs


-- ---------------------------------------------------------------------
-- risk_scores 인덱스 확인
-- ---------------------------------------------------------------------

-- SHOW INDEX FROM authdb.risk_scores;


-- ---------------------------------------------------------------------
-- access_logs 인덱스 확인
-- ---------------------------------------------------------------------

-- SHOW INDEX FROM authdb.access_logs;

-- 정상 기대 인덱스:
--
-- idx_access_created (01_init.sql에서 생성)


-- =====================================================================
-- 7. 데이터 파기 정책 요약
-- =====================================================================

-- ---------------------------------------------------------------------
-- ml_feature_logs
--
-- REAL:
--   90일 초과 데이터 삭제
--
-- TEST:
--   Regression Test 기준 데이터이므로
--   REAL 자동 파기 Event 대상에서 제외
-- ---------------------------------------------------------------------

-- DELETE FROM ml_db.ml_feature_logs
-- WHERE data_source = 'REAL'
--   AND created_at < NOW() - INTERVAL 90 DAY;


-- ---------------------------------------------------------------------
-- ml_predictions
--
-- 1년 보존
-- ---------------------------------------------------------------------

-- DELETE FROM ml_db.ml_predictions
-- WHERE predicted_at < NOW() - INTERVAL 1 YEAR;


-- ---------------------------------------------------------------------
-- audit_logs
--
-- 1년 보존
-- ---------------------------------------------------------------------

-- DELETE FROM mfa_db.audit_logs
-- WHERE created_at < NOW() - INTERVAL 1 YEAR;


-- ---------------------------------------------------------------------
-- risk_scores
--
-- 1년 보존
-- ---------------------------------------------------------------------

-- DELETE FROM authdb.risk_scores
-- WHERE created_at < NOW() - INTERVAL 1 YEAR;


-- ---------------------------------------------------------------------
-- access_logs
--
-- 1년 보존
-- ---------------------------------------------------------------------

-- DELETE FROM authdb.access_logs
-- WHERE created_at < NOW() - INTERVAL 1 YEAR;


-- =====================================================================
-- 8. 삭제 건수 감사 로그
--
-- F-09 v2.2 §3은 Event Scheduler 실행 후
-- 삭제 건수를 F-06 감사 로그에 기록하도록 정의하고 있다.
--
-- 본 프로젝트에서는 개발 일정상 구현 범위에서 제외한다.
-- (인증·DB 담당 협의 결과, 2026.08)
--
-- 운영 전환 시 ROW_COUNT() 결과를 감사 로그에 기록하는 절차를
-- 추가하며, Event가 ml_db·mfa_db·authdb 3개 스키마에 걸쳐 있으므로
-- DEFINER 계정의 교차 스키마 INSERT 권한을 함께 검토한다.
-- =====================================================================
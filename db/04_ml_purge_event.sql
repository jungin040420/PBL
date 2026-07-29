-- =====================================================================
-- ml_purge_event.sql
-- ML 테이블 자동 파기 Event 등록
--
-- 근거 문서 : F-09 v2.0 §3 「Event Scheduler 실행 주기 및 파기 쿼리 정의」
--             ml_feature_logs : 매일 새벽 2시 / created_at   < NOW() - INTERVAL 90 DAY
--             ml_predictions  : 매일 새벽 2시 / predicted_at < NOW() - INTERVAL 1 YEAR
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
--
-- [실행 순서] ml_schema.sql 실행 후 적용할 것
--
-- [실행 주체] 본 Event 는 관리자 계정으로 생성하며, 생성한 계정이
--             DEFINER 가 됩니다. ml_writer / ml_reader 에는 DELETE 권한을
--             부여하지 않습니다. (F-08 §1 최소권한)
-- =====================================================================


-- ---------------------------------------------------------------------
-- 0. [서버 담당자 확인 필요] Event Scheduler 활성화
--
--    MySQL Event Scheduler 는 기본적으로 비활성화 상태입니다.
--    아래 두 가지를 모두 적용해야 재시작 후에도 유지됩니다. (F-09 v2.0 §3)
--
--    (1) 즉시 적용
--        SET GLOBAL event_scheduler = ON;
--
--    (2) 영구 적용 — my.cnf 의 [mysqld] 섹션에 추가
--        event_scheduler = ON
--
--    확인 : SHOW VARIABLES LIKE 'event_scheduler';   -->  ON 이어야 정상
-- ---------------------------------------------------------------------
SET GLOBAL event_scheduler = ON;


USE ml_db;


-- ---------------------------------------------------------------------
-- 1. ml_feature_logs — Sliding Window 90일
--
--    Isolation Forest 재학습 시 최근 90일 데이터를 사용하는 초기 권장안에
--    따른 원본 데이터 보유량 제한. 재학습 조건(7일 경과 또는 신규 1,000건)
--    과는 무관하게 보유량 자체를 90일로 제한합니다. (F-09 v2.0)
-- ---------------------------------------------------------------------
DROP EVENT IF EXISTS ev_purge_ml_feature_logs;

CREATE EVENT ev_purge_ml_feature_logs
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 1 DAY + INTERVAL 2 HOUR)
  COMMENT 'F-09 v2.0: ml_feature_logs 90일 Sliding Window 파기. 매일 02:00'
  DO
    DELETE FROM ml_db.ml_feature_logs
     WHERE created_at < NOW() - INTERVAL 90 DAY;


-- ---------------------------------------------------------------------
-- 2. ml_predictions — 1년 보존
--
--    AI 자동 판단 결과의 감사 기록. audit_logs 와 동일 성격.
--    근거 : 개인정보보호법 시행령 제48조의2 (감사기록 보관)
--           EU AI Act — 고위험 AI 자동 생성 로그 보관 의무
--    (F-09 v2.0 §3 및 법적 근거표)
--
--    ml_feature_logs 와 보존기간이 다르므로 FOREIGN KEY 를 걸지 않습니다.
--    90일 경과 후 ml_predictions 레코드는 대응하는 입력 피처 없이
--    단독으로 남으며, 이는 의도된 설계입니다.
-- ---------------------------------------------------------------------
DROP EVENT IF EXISTS ev_purge_ml_predictions;

CREATE EVENT ev_purge_ml_predictions
  ON SCHEDULE
    EVERY 1 DAY
    STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 1 DAY + INTERVAL 2 HOUR)
  COMMENT 'F-09 v2.0: ml_predictions 1년 보존 후 파기. 매일 02:00'
  DO
    DELETE FROM ml_db.ml_predictions
     WHERE predicted_at < NOW() - INTERVAL 1 YEAR;


-- ---------------------------------------------------------------------
-- 3. 검증 (F-09 v2.0 §「운영 점검」)
--
--   SHOW EVENTS FROM ml_db;
--     --> 두 Event 가 ENABLED 상태여야 정상. 운영 배포 후 1회 + 월 1회 확인
--
--   SHOW VARIABLES LIKE 'event_scheduler';
--     --> ON
-- ---------------------------------------------------------------------


-- ---------------------------------------------------------------------
-- 4. [미구현] 삭제 건수 감사 로그 기록
--
--    F-09 v2.0 은 "Event Scheduler 실행 완료 후 삭제 건수를 F-06 감사 로그에
--    기록" 하도록 정의하고 있습니다. 본 파일은 삭제만 수행하며 감사 로그
--    기록은 포함하지 않았습니다.
--
--    F-06 감사 로그의 스키마·기록 주체가 확정된 뒤
--    ROW_COUNT() 값을 적재하는 절차를 추가해야 합니다.
--    (해당 테이블이 mfa_db 에 있을 경우 DEFINER 계정의 교차 스키마 쓰기
--     권한이 필요하므로 서버 담당자와 협의 필요)
-- ---------------------------------------------------------------------
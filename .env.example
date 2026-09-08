-- =====================================================================
-- ml_grants.sql
-- ML 전용 DB 계정 생성 및 권한 부여 (최소권한 원칙)
--
-- 근거 문서 : F-08 v2.6 §1 접근통제 요건
--             F-07 v9.4 §5 ⑧ 저장 위치 및 계정
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
--
-- [실행 순서] ml_schema.sql → 본 파일 순서로 적용
-- [비밀번호] 개발 환경 전용 — 운영 전환 시 환경변수 주입으로 분리
--            (F-08 §5 하드코딩 금지 조항 준수)
-- =====================================================================


-- 1. 계정 생성 --------------------------------------------------------
--    호스트 '%' : docker-compose 내부 컨테이너 IP 가변 대응
--    외부 접근 차단은 compose ports 설정으로 통제
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'ml_writer'@'%' IDENTIFIED BY '<DEV_PW_PLACEHOLDER>';
CREATE USER IF NOT EXISTS 'ml_reader'@'%' IDENTIFIED BY '<DEV_PW_PLACEHOLDER>';


-- 2. ml_writer — 적재 전용 (INSERT only) ------------------------------
--    사용 주체 : python-risk/main.py (FastAPI)
--    INSERT만 부여 — 누적 학습 데이터 조회·수정·삭제 불가 (최소권한)
--    파기는 Event Scheduler 가 단독 수행 (F-09 §3)
-- ---------------------------------------------------------------------
GRANT INSERT ON ml_db.ml_feature_logs TO 'ml_writer'@'%';
GRANT INSERT ON ml_db.ml_predictions  TO 'ml_writer'@'%';


-- 3. ml_reader — 조회 전용 (SELECT only) ------------------------------
--    사용 주체 : Isolation Forest 학습·추론
--    SELECT만 부여 — 로그 변경·삭제 불가 (감사 추적 보장)
-- ---------------------------------------------------------------------
GRANT SELECT ON ml_db.ml_feature_logs TO 'ml_reader'@'%';
GRANT SELECT ON ml_db.ml_predictions  TO 'ml_reader'@'%';


-- 4. 적용 -------------------------------------------------------------
FLUSH PRIVILEGES;


-- 5. 검증 (적용 후 확인용) --------------------------------------------
--    SHOW GRANTS FOR 'ml_writer'@'%';
--    SHOW GRANTS FOR 'ml_reader'@'%';
--    기대: ml_writer → INSERT only, ml_reader → SELECT only
--          두 계정 모두 mfa_db 권한 없음 (F-08 §1 물리적 분리)
-- ---------------------------------------------------------------------
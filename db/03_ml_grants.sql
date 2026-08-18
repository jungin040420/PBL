-- =====================================================================
-- ml_grants.sql
-- ML 전용 DB 계정 생성 및 권한 부여
--
-- 근거 문서 : F-08 v2.1 §1 접근통제 요건
--             "ml_feature_logs·ml_predictions 는 ML 서비스 전용 DB 계정만
--              접근 가능하도록 권한 분리"
--             F-07 v9.1 §5 ⑧ 「저장 위치 및 계정」
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
--
-- [실행 순서] ml_schema.sql 실행 후 적용할 것
--
-- [비밀번호] 개발 단계 한정
--            본 파일의 계정 비밀번호는 개발 환경 전용이며 SQL에 직접 기재합니다.
--            운영 전환 시에는 초기화 스크립트에서 분리하여 환경변수 주입 방식으로
--            변경합니다. (F-08 §5 「키를 코드에 하드코딩」 금지 조항 준수)
--            AES_KEY·USERID_SALT·COMPARE_SALT 등 비식별화 키는 본 조항의 예외가
--            아니며 환경변수로만 관리합니다.
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. 계정 생성
--    호스트를 '%' 로 두는 이유: docker-compose dev-network 내부의
--    node-server / ml-service 컨테이너에서 접속하며, 컨테이너 IP 가
--    재생성 시마다 바뀌기 때문. 외부 노출은 compose 의 ports 설정으로 통제.
-- ---------------------------------------------------------------------
CREATE USER IF NOT EXISTS 'ml_writer'@'%' IDENTIFIED BY 'f7f2659489612bf13645638bf28eae1ea5eadee358ac9087';
CREATE USER IF NOT EXISTS 'ml_reader'@'%' IDENTIFIED BY 'b0a38fd74d5bac8633cae7d847f06b36ab059f827ceb859e';


-- ---------------------------------------------------------------------
-- 2. ml_writer — 적재 전용 (INSERT only)
--
--    사용 주체 : python-risk/main.py (FastAPI). Node → FastAPI → ml_db 경로로 적재.
--
--    SELECT 를 주지 않는 이유 : 적재 주체가 누적 학습 데이터를 읽을 수
--    없어야 최소권한이 성립한다. UPDATE/DELETE 를 주지 않는 이유 :
--    ml_feature_logs 는 append-only 이며(F-07 v9.1), 파기는 Event Scheduler
--    가 단독으로 수행한다(F-09 §3).
-- ---------------------------------------------------------------------
GRANT INSERT ON ml_db.ml_feature_logs TO 'ml_writer'@'%';
GRANT INSERT ON ml_db.ml_predictions  TO 'ml_writer'@'%';


-- ---------------------------------------------------------------------
-- 3. ml_reader — 조회 전용 (SELECT only)
--
--    사용 주체 : Isolation Forest 학습 · 추론 (ML 담당)
--
--    쓰기 권한을 주지 않는 이유 : 학습 주체가 로그를 변경·삭제할 수 없어야
--    감사 추적이 성립한다.
-- ---------------------------------------------------------------------
GRANT SELECT ON ml_db.ml_feature_logs TO 'ml_reader'@'%';
GRANT SELECT ON ml_db.ml_predictions  TO 'ml_reader'@'%';


-- ---------------------------------------------------------------------
-- 4. 적용
-- ---------------------------------------------------------------------
FLUSH PRIVILEGES;


-- ---------------------------------------------------------------------
-- 5. 검증 (적용 후 확인용)
--
--   SHOW GRANTS FOR 'ml_writer'@'%';
--   SHOW GRANTS FOR 'ml_reader'@'%';
--
--   기대 결과
--     ml_writer : ml_db.ml_feature_logs / ml_db.ml_predictions 에 INSERT 만
--     ml_reader : ml_db.ml_feature_logs / ml_db.ml_predictions 에 SELECT 만
--     두 계정 모두 mfa_db 에 대한 권한이 없어야 함 (F-08 §1 물리적 분리)
-- ---------------------------------------------------------------------
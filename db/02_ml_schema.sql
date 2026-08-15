-- =====================================================================
-- ml_schema.sql
-- ML 학습용 피처 로그 저장소 스키마
--
-- 근거 문서 : F-07 v9.1 §5 ⑧ (테이블·컬럼 정의)
--             F-08 v2.1 §1   (접근통제 3요건 / 등급 분류)
--             F-09 v2.0 §3   (보존기간·파기)
-- 담당자     : 윤정인
-- 작성일     : 2026.07.29
--
-- [적용 방법] 서버 담당자 확인 필요
--   (A) docker-compose mysql 서비스에
--       volumes: - ./db:/docker-entrypoint-initdb.d  마운트 후 컨테이너 재생성
--   (B) 또는 수동 1회 실행:
--       docker exec -i auth_mysql mysql -uroot -p < db/ml_schema.sql
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. 스키마 생성
--    F-08 §1 통제요건 (2) : 원본 식별정보를 저장하는 사용자 테이블(mfa_db)과
--                           물리적으로 분리한다.
-- ---------------------------------------------------------------------
CREATE DATABASE IF NOT EXISTS ml_db
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE ml_db;


-- ---------------------------------------------------------------------
-- 2. ml_feature_logs — 입력 피처 벡터 (append-only)
--
--    쓰기 시점 : 로그인 이벤트 발생 즉시 1회 INSERT. 이후 갱신 없음.
--    컬럼 기준 : F-07 v9.1 「ml_feature_logs 컬럼 정의」표
--
--    NULL 정책 : F-08 v2.1 「ML 사용 여부」가 '채택' 으로 갱신된 항목만
--                실제 INSERT 대상이며, 나머지 컬럼은 스키마상 보존하되
--                NULL 을 허용한다. (F-07 v9.1 컬럼 정의표 단서 조항)
--
--    금지 사항 : 원본 IP·기기ID·해시값을 이 테이블에 직접 저장하지 않는다.
--                반드시 파생 피처(0/1, 집계값)로 변환 후 저장한다.
--                (F-08 §9 파생 피처 원칙)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_feature_logs (

  -- [메타]
  event_id                      VARCHAR(20)  NOT NULL
    COMMENT 'PK. 형식 evt_YYYYMMDD_NNNN. 로그인 시점 서버 생성. ml_predictions 연결 키',
  created_at                    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    COMMENT 'INSERT 시각. F-09 Sliding Window 삭제 쿼리 기준 컬럼',

  -- [식별자] 1등급 — 모델 입력 Feature 아님. 사용자별 그룹핑 전용
  user_id_hash                  CHAR(64)     NOT NULL
    COMMENT 'SHA-256 + 고정 Salt(USERID_SALT). F-08 규칙 5. 1등급',

  -- [B] Behavior
  login_frequency               INT          NULL
    COMMENT '0~100. 로그인 빈도 이상 탐지. 3등급',
  failed_login_count            INT          NULL
    COMMENT '0~10. 실패 패턴 이상 탐지. 3등급',
  challenge_response_time       FLOAT        NULL
    COMMENT 'ms. 자동화 공격(비정상 응답속도) 탐지. 3등급',
  authentication_method_changed TINYINT(1)   NULL
    COMMENT '0/1. 인증 수단 변경 탐지. 3등급',

  -- [N] Network
  ip_changed                    TINYINT(1)   NULL
    COMMENT '0/1. 네트워크 경로 변경 탐지 (IP 해시 비교 결과). 3등급',
  region_changed                TINYINT(1)   NULL
    COMMENT '0/1. 접속 지역 변경 탐지. BNDTC N 요소와 동일 컬럼 공유. 3등급',

  -- [D] Device
  sign_count_abnormal           TINYINT(1)   NULL
    COMMENT '0/1. FIDO2 리플레이 공격 탐지. 3등급',
  credential_mismatch           TINYINT(1)   NULL
    COMMENT '0/1. 인증기 불일치 탐지. 원본 credentialId 비교 결과값만 사용. 3등급',
  user_agent_changed            TINYINT(1)   NULL
    COMMENT '0/1. 기기·브라우저 변경 탐지 (UA 해시 비교 결과). 3등급',

  -- [T] Threat History
  consecutive_failure_count     INT          NULL
    COMMENT '0~10. 연속 공격 시도 탐지. 3등급',
  blacklist_ip_detected         TINYINT(1)   NULL
    COMMENT '0/1. 블랙리스트 IP 접속 탐지. 3등급',

  -- [C] Context
  login_hour                    TINYINT      NULL
    COMMENT '0~23. 비정상 시간대 탐지. KST 기준(F-07 v9.1 §5 ⑧). 3등급',
  day_of_week                   TINYINT      NULL
    COMMENT '0~6. 요일 패턴 학습. 3등급',
  login_region                  INT          NULL
    COMMENT 'Region ID. 지역 패턴 학습(현재 접속 지역 값). 3등급',

  PRIMARY KEY (event_id),

  -- F-09 §3 삭제 쿼리가 created_at 을 조건으로 사용하므로 인덱스 필수
  INDEX idx_created_at (created_at),

  -- 사용자별 시계열 조회(재학습 데이터 추출) 성능 확보
  INDEX idx_user_created (user_id_hash, created_at)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='ML 입력 피처 벡터. append-only. F-09 Sliding Window 90일';


-- ---------------------------------------------------------------------
-- 3. ml_predictions — Isolation Forest 추론 결과 (출력)
--
--    쓰기 시점 : 추론 완료 시점에 INSERT.
--    컬럼 기준 : F-07 v9.1 「ml_predictions 컬럼 정의」표
--
--    [중요] ml_feature_logs 와 FOREIGN KEY 를 걸지 않는다.
--           보존기간이 서로 다르기 때문이다.
--             ml_feature_logs :  90일 (F-09 §3)
--             ml_predictions  :  1년  (F-09 §3)
--           FK 를 걸면 90일 파기 이벤트가 참조 무결성 위반으로 실패한다.
--           두 테이블은 event_id 로 논리적으로만 연결한다.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ml_predictions (

  event_id             VARCHAR(20)  NOT NULL
    COMMENT 'PK. ml_feature_logs 연결 키. 형식 evt_YYYYMMDD_NNNN',
  anomaly_score        FLOAT        NULL
    COMMENT '0~100. 모델 원본 -1~1 범위를 변환한 값',
  anomaly_label        VARCHAR(16)  NULL
    COMMENT 'NORMAL / ANOMALY',
  model_version        VARCHAR(32)  NULL
    COMMENT '예: iforest-v1.0.0. 재학습 시마다 버전 증가',
  top_anomaly_features JSON         NULL
    COMMENT '이상 판단에 기여한 상위 피처 목록. 관리자 검토·감사 참고용',
  predicted_at         TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
    COMMENT '추론 시각. F-09 파기 쿼리 기준 컬럼',

  PRIMARY KEY (event_id),

  -- F-09 §3 삭제 쿼리가 predicted_at 을 조건으로 사용
  INDEX idx_predicted_at (predicted_at)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Isolation Forest 추론 결과. F-09 보존 1년';
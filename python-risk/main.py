import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import pymysql
import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.isolation_model import (
    load_metadata,
    predict_anomaly_score,
)


# ============================================================
# FastAPI
# ============================================================

app = FastAPI(
    title="Hybrid Risk Score API",
    description=(
        "B/N/D/T/C 기반 Rule-Based Trust Score와 "
        "Isolation Forest 이상 탐지를 이용해 "
        "로그인 위험도를 분석하고 "
        "ML Feature 및 Prediction을 저장합니다."
    ),
    version="2.2.0",
)


# ============================================================
# 기본 설정
# ============================================================

LOG_FILE = Path(
    "risk_logs.jsonl"
)

ELASTICSEARCH_URL = os.getenv(
    "ELASTICSEARCH_URL",
    "http://elasticsearch:9200/risk-logs/_doc",
)


# ============================================================
# MySQL 설정
# ============================================================

DB_HOST = os.getenv(
    "ML_DB_HOST",
    os.getenv(
        "DB_HOST",
        "mysql",
    ),
)

DB_PORT = int(
    os.getenv(
        "ML_DB_PORT",
        os.getenv(
            "DB_PORT",
            "3306",
        ),
    )
)

DB_USER = os.getenv(
    "ML_DB_USER",
    os.getenv(
        "DB_USER",
        "authuser",
    ),
)

DB_PASSWORD = os.getenv(
    "ML_DB_PASSWORD",
    os.getenv(
        "DB_PASSWORD",
    ),
)

DB_NAME = os.getenv(
    "ML_DB_NAME",
    os.getenv(
        "DB_NAME",
        "ml_db",
    ),
)


print(
    "ML DB 설정:",
    {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "database": DB_NAME,
        "has_password": bool(
            DB_PASSWORD
        ),
    }
)

print(
    "Elasticsearch 설정:",
    ELASTICSEARCH_URL,
)


# ============================================================
# Request Model
# ============================================================

class LogData(BaseModel):

    userIdHash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "USERID_SALT 기반 "
            "SHA-256 사용자 식별자 해시"
        ),
    )

    ipHash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "COMPARE_SALT 기반 "
            "SHA-256 IP 비교용 해시"
        ),
    )

    deviceType: str = Field(
        ...,
        min_length=1,
    )

    country: str = Field(
        default="KR",
        min_length=2,
    )

    # ========================================================
    # B - Behavior
    # ========================================================

    loginFrequency: int = Field(
        default=0,
        ge=0,
    )

    failedLoginCount: int = Field(
        default=0,
        ge=0,
    )

    challengeResponseTime: Optional[float] = Field(
        default=None,
        ge=0,
    )

    authenticationMethodChanged: bool = False

    hasPreviousContext: bool = False

    # ========================================================
    # N - Network
    # ========================================================

    ipChanged: bool = False

    regionChanged: bool = False

    # ========================================================
    # D - Device / Credential
    # ========================================================

    signCountAbnormal: bool = False

    credentialMismatch: bool = False

    userAgentChanged: bool = False

    isNewDevice: bool = False

    # ========================================================
    # T - Threat / History
    # ========================================================

    consecutiveFailureCount: int = Field(
        default=0,
        ge=0,
    )

    blacklistIpDetected: bool = False

    # ========================================================
    # C - Context
    # ========================================================

    loginHour: int = Field(
        default=12,
        ge=0,
        le=23,
    )

    dayOfWeek: int = Field(
        default=0,
        ge=0,
        le=6,
    )

    loginRegion: str = Field(
        default="KR",
        min_length=2,
        max_length=32,
    )


# ============================================================
# Response Model
# ============================================================

class RiskResponse(BaseModel):

    userIdHash: str

    ipHash: str

    deviceType: str

    risk_score: int

    risk_level: str

    authentication_action: str

    message: str

    triggers: List[str]

    feature_scores: Dict[str, int]

    ml_model_used: bool = False

    ml_model_type: Optional[str] = None

    ml_anomaly_score: Optional[float] = None

    ml_is_anomaly: Optional[bool] = None


# ============================================================
# Event ID
#
# 요청 1건당 딱 1번 생성한다.
#
# 동일 event_id를:
# - ml_feature_logs
# - ml_predictions
# - risk_logs
# 에 공통으로 사용한다.
# ============================================================

def generate_event_id() -> str:

    return datetime.now(
        timezone.utc
    ).strftime(
        "evt_%Y%m%d_%H%M%S%f"
    )


# ============================================================
# loginRegion ML Encoding
#
# DB:
#   KR 등의 문자열 그대로 저장
#
# ML:
#   KR = 0
#   기타 = 1
# ============================================================

def encode_login_region(
    login_region: str,
) -> int:

    if (
        login_region
        and
        login_region.upper()
        == "KR"
    ):
        return 0

    return 1


# ============================================================
# MySQL 연결 생성
# ============================================================

def create_ml_db_connection():

    if not DB_PASSWORD:

        raise RuntimeError(
            "ML_DB_PASSWORD 또는 "
            "DB_PASSWORD 환경변수가 없습니다."
        )

    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        connect_timeout=5,
        autocommit=True,
    )


# ============================================================
# MySQL REAL Feature 저장
# ============================================================

def save_ml_feature_log(
    data: LogData,
    event_id: str,
) -> None:

    if not DB_PASSWORD:

        print(
            "ML Feature MySQL 저장 건너뜀: "
            "ML DB 비밀번호 환경변수가 없습니다."
        )

        return

    connection = None

    try:

        connection = (
            create_ml_db_connection()
        )

        sql = """
            INSERT INTO ml_feature_logs (
                event_id,
                user_id_hash,

                login_frequency,
                failed_login_count,
                challenge_response_time,
                authentication_method_changed,

                ip_changed,
                region_changed,

                sign_count_abnormal,
                credential_mismatch,
                user_agent_changed,
                is_new_device,

                consecutive_failure_count,
                blacklist_ip_detected,

                login_hour,
                day_of_week,

                login_region,
                has_previous_context,

                data_source
            )
            VALUES (
                %s,
                %s,

                %s,
                %s,
                %s,
                %s,

                %s,
                %s,

                %s,
                %s,
                %s,
                %s,

                %s,
                %s,

                %s,
                %s,

                %s,
                %s,

                'REAL'
            )
        """

        values = (
            event_id,
            data.userIdHash,

            data.loginFrequency,
            data.failedLoginCount,
            data.challengeResponseTime,
            int(
                data.authenticationMethodChanged
            ),

            int(
                data.ipChanged
            ),
            int(
                data.regionChanged
            ),

            int(
                data.signCountAbnormal
            ),
            int(
                data.credentialMismatch
            ),
            int(
                data.userAgentChanged
            ),
            int(
                data.isNewDevice
            ),

            data.consecutiveFailureCount,
            int(
                data.blacklistIpDetected
            ),

            data.loginHour,
            data.dayOfWeek,

            data.loginRegion,
            int(
                data.hasPreviousContext
            ),
        )

        with connection.cursor() as cursor:

            cursor.execute(
                sql,
                values,
            )

        print(
            "ML Feature MySQL 저장 성공 "
            f"[REAL] event_id={event_id}"
        )

    except (
        pymysql.MySQLError,
        RuntimeError,
    ) as error:

        print(
            "ML Feature MySQL 저장 실패:",
            error,
        )

        print(
            "ML DB 접속 설정:",
            {
                "host":
                    DB_HOST,

                "port":
                    DB_PORT,

                "user":
                    DB_USER,

                "database":
                    DB_NAME,

                "has_password":
                    bool(
                        DB_PASSWORD
                    ),
            }
        )

    finally:

        if connection is not None:

            connection.close()


# ============================================================
# ML Prediction 저장
# ============================================================

def save_ml_prediction(
    event_id: str,
    ml_result: dict,
) -> None:

    if not DB_PASSWORD:

        print(
            "ML Prediction MySQL 저장 건너뜀: "
            "ML DB 비밀번호 환경변수가 없습니다."
        )

        return

    if not ml_result.get(
        "ml_model_used"
    ):

        print(
            "ML Prediction MySQL 저장 건너뜀: "
            "실제 ML 모델이 사용되지 않았습니다. "
            f"event_id={event_id}"
        )

        return

    anomaly_score = (
        ml_result.get(
            "ml_anomaly_score"
        )
    )

    is_anomaly = (
        ml_result.get(
            "ml_is_anomaly"
        )
    )

    anomaly_label = (
        "ANOMALY"
        if is_anomaly is True
        else "NORMAL"
    )

    model_version = (
        ml_result.get(
            "ml_model_version"
        )
        or "iforest-real-16f-v1"
    )

    connection = None

    try:

        connection = (
            create_ml_db_connection()
        )

        sql = """
            INSERT INTO ml_predictions (
                event_id,
                anomaly_score,
                anomaly_label,
                model_version,
                top_anomaly_features
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s
            )
        """

        values = (
            event_id,
            anomaly_score,
            anomaly_label,
            model_version,
            None,
        )

        with connection.cursor() as cursor:

            cursor.execute(
                sql,
                values,
            )

        print(
            "ML Prediction MySQL 저장 성공 "
            f"[{anomaly_label}] "
            f"event_id={event_id} "
            f"score={anomaly_score}"
        )

    except (
        pymysql.MySQLError,
        RuntimeError,
    ) as error:

        print(
            "ML Prediction MySQL 저장 실패:",
            error,
        )

    finally:

        if connection is not None:

            connection.close()


# ============================================================
# ML 추론
# ============================================================

def run_ml_analysis(
    data: LogData,
) -> dict:

    try:

        metadata = load_metadata()

    except Exception as error:

        print(
            "ML metadata 로드 실패:",
            error,
        )

        return {
            "ml_model_used":
                False,

            "ml_model_type":
                None,

            "ml_model_version":
                None,

            "ml_anomaly_score":
                None,

            "ml_is_anomaly":
                None,
        }

    if not metadata:

        print(
            "ML 추론 건너뜀: "
            "모델 metadata 없음"
        )

        return {
            "ml_model_used":
                False,

            "ml_model_type":
                None,

            "ml_model_version":
                None,

            "ml_anomaly_score":
                None,

            "ml_is_anomaly":
                None,
        }

    model_type = metadata.get(
        "model_type"
    )

    model_version = (
        metadata.get(
            "model_version"
        )
        or "iforest-real-16f-v1"
    )

    if model_type != "REAL":

        print(
            "ML 추론 건너뜀: "
            f"{model_type} 모델은 "
            "실제 판정에 사용하지 않음"
        )

        return {
            "ml_model_used":
                False,

            "ml_model_type":
                model_type,

            "ml_model_version":
                model_version,

            "ml_anomaly_score":
                None,

            "ml_is_anomaly":
                None,
        }

    # ========================================================
    # 최종 확정 16개 ML Feature
    #
    # B = 5
    # N = 2
    # D = 4
    # T = 2
    # C = 3
    #
    # 총 16개
    # ========================================================

    features = {

        # B - Behavior

        "loginFrequency":
            data.loginFrequency,

        "failedLoginCount":
            data.failedLoginCount,

        "challengeResponseTime":
            (
                data.challengeResponseTime
                if
                data.challengeResponseTime
                is not None
                else 0
            ),

        "authenticationMethodChanged":
            data.authenticationMethodChanged,

        "hasPreviousContext":
            data.hasPreviousContext,

        # N - Network

        "ipChanged":
            data.ipChanged,

        "regionChanged":
            data.regionChanged,

        # D - Device

        "signCountAbnormal":
            data.signCountAbnormal,

        "credentialMismatch":
            data.credentialMismatch,

        "userAgentChanged":
            data.userAgentChanged,

        "isNewDevice":
            data.isNewDevice,

        # T - Threat

        "consecutiveFailureCount":
            data.consecutiveFailureCount,

        "blacklistIpDetected":
            data.blacklistIpDetected,

        # C - Context

        "loginHour":
            data.loginHour,

        "dayOfWeek":
            data.dayOfWeek,

        "loginRegion":
            encode_login_region(
                data.loginRegion
            ),
    }

    print(
        "16개 Risk Feature 입력:",
        features,
    )

    try:

        result = (
            predict_anomaly_score(
                features
            )
        )

    except Exception as error:

        print(
            "ML 추론 실패:",
            error,
        )

        return {
            "ml_model_used":
                False,

            "ml_model_type":
                model_type,

            "ml_model_version":
                model_version,

            "ml_anomaly_score":
                None,

            "ml_is_anomaly":
                None,
        }

    if result is None:

        print(
            "ML 추론 결과 없음 "
            "-> Rule 기반 fallback"
        )

        return {
            "ml_model_used":
                False,

            "ml_model_type":
                model_type,

            "ml_model_version":
                model_version,

            "ml_anomaly_score":
                None,

            "ml_is_anomaly":
                None,
        }

    print(
        "ML 추론 성공:",
        {
            "model_type":
                model_type,

            "model_version":
                model_version,

            "anomaly_score":
                result[
                    "anomaly_score"
                ],

            "is_anomaly":
                result[
                    "is_anomaly"
                ],
        }
    )

    return {
        "ml_model_used":
            True,

        "ml_model_type":
            model_type,

        "ml_model_version":
            model_version,

        "ml_anomaly_score":
            result[
                "anomaly_score"
            ],

        "ml_is_anomaly":
            result[
                "is_anomaly"
            ],
    }


# ============================================================
# Risk 로그 저장
# ============================================================

def save_risk_log(
    event_id: str,
    data: LogData,
    risk_response: RiskResponse,
) -> None:

    log = {

        "event_id":
            event_id,

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "source":
            "python-risk-engine",

        "event_type":
            "risk_analysis",

        "userIdHash":
            data.userIdHash,

        "ipHash":
            data.ipHash,

        "deviceType":
            data.deviceType,

        "country":
            data.country,

        # B - Behavior

        "loginFrequency":
            data.loginFrequency,

        "failedLoginCount":
            data.failedLoginCount,

        "challengeResponseTime":
            data.challengeResponseTime,

        "authenticationMethodChanged":
            data.authenticationMethodChanged,

        "hasPreviousContext":
            data.hasPreviousContext,

        # N - Network

        "ipChanged":
            data.ipChanged,

        "regionChanged":
            data.regionChanged,

        # D - Device

        "signCountAbnormal":
            data.signCountAbnormal,

        "credentialMismatch":
            data.credentialMismatch,

        "userAgentChanged":
            data.userAgentChanged,

        "isNewDevice":
            data.isNewDevice,

        # T - Threat

        "consecutiveFailureCount":
            data.consecutiveFailureCount,

        "blacklistIpDetected":
            data.blacklistIpDetected,

        # C - Context

        "loginHour":
            data.loginHour,

        "dayOfWeek":
            data.dayOfWeek,

        "loginRegion":
            data.loginRegion,

        # 결과

        "risk_score":
            risk_response.risk_score,

        "risk_level":
            risk_response.risk_level,

        "authentication_action":
            risk_response.authentication_action,

        "triggers":
            risk_response.triggers,

        "feature_scores":
            risk_response.feature_scores,

        "ml_model_used":
            risk_response.ml_model_used,

        "ml_model_type":
            risk_response.ml_model_type,

        "ml_anomaly_score":
            risk_response.ml_anomaly_score,

        "ml_is_anomaly":
            risk_response.ml_is_anomaly,
    }

    try:

        with LOG_FILE.open(
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                json.dumps(
                    log,
                    ensure_ascii=False,
                )
                + "\n"
            )

        print(
            "Python 로컬 Risk 로그 저장 성공"
        )

    except OSError as error:

        print(
            "Python 로컬 로그 저장 실패:",
            error,
        )

    try:

        elasticsearch_response = (
            requests.post(
                ELASTICSEARCH_URL,
                json=log,
                timeout=3,
            )
        )

        elasticsearch_response.raise_for_status()

        print(
            "Python 로그 Elasticsearch 저장 성공"
        )

    except requests.RequestException as error:

        print(
            "Python 로그 Elasticsearch 저장 실패:",
            error,
        )


# ============================================================
# Root
# ============================================================

@app.get("/")
def read_root():

    try:

        metadata = load_metadata()

    except Exception:

        metadata = None

    return {
        "status":
            "Python 리스크 서버 실행 중",

        "api":
            "POST /analyze",

        "docs":
            "/docs",

        "rule_formula":
            (
                "TS = 0.30B + 0.20N + "
                "0.20D + 0.20T + 0.10C"
            ),

        "ml_feature_log":
            "MySQL ml_feature_logs",

        "ml_prediction":
            "MySQL ml_predictions",

        "ml_model_type":
            (
                metadata.get(
                    "model_type"
                )
                if metadata
                else None
            ),

        "ml_feature_count":
            (
                metadata.get(
                    "feature_count"
                )
                if metadata
                else None
            ),

        "db":
            {
                "host":
                    DB_HOST,

                "port":
                    DB_PORT,

                "database":
                    DB_NAME,

                "password_configured":
                    bool(
                        DB_PASSWORD
                    ),
            },

        "elasticsearch":
            ELASTICSEARCH_URL,
    }


# ============================================================
# B/N/D/T/C 기반 Rule-Based Trust Score
#
# TS = WB * B + WN * N + WD * D + WT * T + WC * C
#
# 가중치 우선순위:
#
# Behavior = 0.30
# Network  = 0.20
# Device   = 0.20
# Threat   = 0.20
# Context  = 0.10
#
# 합계 = 1.00
# ============================================================

WB = 0.30
WN = 0.20
WD = 0.20
WT = 0.20
WC = 0.10


def clamp_score(
    value: float,
) -> float:

    return max(
        0.0,
        min(
            float(value),
            100.0,
        ),
    )


# ============================================================
# Feature별 위험도 정규화
#
# 아래 값은 기존 프로젝트에서 사용하던 임계값을
# 0~100 영역 점수 계산용으로 변환한 것이다.
# ============================================================

def normalize_login_frequency(
    login_frequency: int,
) -> float:

    if login_frequency >= 10:
        return 100.0

    if login_frequency >= 5:
        return 67.0

    if login_frequency >= 3:
        return 33.0

    return 0.0


def normalize_login_failure(
    login_failures: int,
) -> float:

    if login_failures >= 5:
        return 100.0

    if login_failures >= 3:
        return 60.0

    if login_failures >= 1:
        return 20.0

    return 0.0


def normalize_response_time(
    challenge_response_time:
        Optional[float],
) -> float:

    if challenge_response_time is None:
        return 0.0

    # 지나치게 빠른 응답
    if (
        0
        < challenge_response_time
        < 300
    ):
        return 100.0

    # 지나치게 느린 응답
    if challenge_response_time > 5000:
        return 50.0

    return 0.0


def normalize_login_hour(
    login_hour: int,
) -> float:

    # 심야 시간대
    if (
        0
        <= login_hour
        <= 5
    ):
        return 100.0

    return 0.0


def normalize_day_of_week(
    day_of_week: int,
) -> float:

    # Python/프로젝트 값 기준:
    # 0~4 평일
    # 5~6 주말
    if day_of_week in (
        5,
        6,
    ):
        return 50.0

    return 0.0


def normalize_login_region(
    login_region: str,
) -> float:

    # 현재 서비스의 정상 기준 지역은 KR
    if (
        login_region
        and
        login_region.upper()
        == "KR"
    ):
        return 0.0

    return 100.0


def boolean_risk(
    value: bool,
) -> float:

    if value:
        return 100.0

    return 0.0


def inverse_boolean_risk(
    value: bool,
) -> float:

    # hasPreviousContext와 같이
    # False일 때 위험도가 증가하는 Feature용
    if value:
        return 0.0

    return 100.0


def average_score(
    values: List[float],
) -> float:

    if not values:
        return 0.0

    return (
        sum(values)
        / len(values)
    )


# ============================================================
# B / N / D / T / C 영역 점수 계산
#
# 최종 매핑
#
# B - Behavior (5)
#   loginFrequency
#   failedLoginCount
#   challengeResponseTime
#   authenticationMethodChanged
#   hasPreviousContext
#
# N - Network (2)
#   ipChanged
#   regionChanged
#
# D - Device (4)
#   signCountAbnormal
#   credentialMismatch
#   userAgentChanged
#   isNewDevice
#
# T - Threat (2)
#   consecutiveFailureCount
#   blacklistIpDetected
#
# C - Context (3)
#   loginHour
#   dayOfWeek
#   loginRegion
#
# 총 16개
# ============================================================

def calculate_trust_score(
    data: LogData,
) -> tuple[
    int,
    Dict[str, int],
    List[str],
]:

    # ========================================================
    # B - Behavior
    # ========================================================

    behavior_score = average_score(
        [
            normalize_login_frequency(
                data.loginFrequency
            ),

            normalize_login_failure(
                data.failedLoginCount
            ),

            normalize_response_time(
                data.challengeResponseTime
            ),

            boolean_risk(
                data.authenticationMethodChanged
            ),

            inverse_boolean_risk(
                data.hasPreviousContext
            ),
        ]
    )


    # ========================================================
    # N - Network
    # ========================================================

    network_score = average_score(
        [
            boolean_risk(
                data.ipChanged
            ),

            boolean_risk(
                data.regionChanged
            ),
        ]
    )


    # ========================================================
    # D - Device / Credential
    # ========================================================

    device_score = average_score(
        [
            boolean_risk(
                data.signCountAbnormal
            ),

            boolean_risk(
                data.credentialMismatch
            ),

            boolean_risk(
                data.userAgentChanged
            ),

            boolean_risk(
                data.isNewDevice
            ),
        ]
    )


    # ========================================================
    # T - Threat / History
    # ========================================================

    threat_score = average_score(
        [
            normalize_login_failure(
                data.consecutiveFailureCount
            ),

            boolean_risk(
                data.blacklistIpDetected
            ),
        ]
    )


    # ========================================================
    # C - Context
    # ========================================================

    context_score = average_score(
        [
            normalize_login_hour(
                data.loginHour
            ),

            normalize_day_of_week(
                data.dayOfWeek
            ),

            normalize_login_region(
                data.loginRegion
            ),
        ]
    )


    # ========================================================
    # B/N/D/T/C 가중합 공식
    #
    # TS =
    # 0.30B
    # + 0.20N
    # + 0.20D
    # + 0.20T
    # + 0.10C
    # ========================================================

    weighted_behavior = (
        WB
        * behavior_score
    )

    weighted_network = (
        WN
        * network_score
    )

    weighted_device = (
        WD
        * device_score
    )

    weighted_threat = (
        WT
        * threat_score
    )

    weighted_context = (
        WC
        * context_score
    )


    rule_score = (
        weighted_behavior
        + weighted_network
        + weighted_device
        + weighted_threat
        + weighted_context
    )


    rule_score = int(
        round(
            clamp_score(
                rule_score
            )
        )
    )


    # ========================================================
    # 영역별 점수 및 가중 점수
    # ========================================================

    feature_scores: Dict[str, int] = {

        "B_behavior":
            int(
                round(
                    behavior_score
                )
            ),

        "N_network":
            int(
                round(
                    network_score
                )
            ),

        "D_device":
            int(
                round(
                    device_score
                )
            ),

        "T_threat":
            int(
                round(
                    threat_score
                )
            ),

        "C_context":
            int(
                round(
                    context_score
                )
            ),

        "WB_B":
            int(
                round(
                    weighted_behavior
                )
            ),

        "WN_N":
            int(
                round(
                    weighted_network
                )
            ),

        "WD_D":
            int(
                round(
                    weighted_device
                )
            ),

        "WT_T":
            int(
                round(
                    weighted_threat
                )
            ),

        "WC_C":
            int(
                round(
                    weighted_context
                )
            ),
    }


    # ========================================================
    # Trigger 생성
    # ========================================================

    triggers: List[str] = []


    # B - Behavior

    if data.loginFrequency >= 3:

        triggers.append(
            "HIGH_LOGIN_FREQUENCY"
        )


    if data.failedLoginCount >= 1:

        triggers.append(
            "LOGIN_FAILURE"
        )


    if (
        data.challengeResponseTime
        is not None
        and
        (
            (
                0
                < data.challengeResponseTime
                < 300
            )
            or
            data.challengeResponseTime
            > 5000
        )
    ):

        triggers.append(
            "ABNORMAL_RESPONSE_TIME"
        )


    if data.authenticationMethodChanged:

        triggers.append(
            "AUTHENTICATION_METHOD_CHANGED"
        )


    if not data.hasPreviousContext:

        triggers.append(
            "NO_PREVIOUS_CONTEXT"
        )


    # N - Network

    if data.ipChanged:

        triggers.append(
            "IP_CHANGED"
        )


    if data.regionChanged:

        triggers.append(
            "REGION_CHANGED"
        )


    # D - Device

    if data.signCountAbnormal:

        triggers.append(
            "SIGN_COUNT_ABNORMAL"
        )


    if data.credentialMismatch:

        triggers.append(
            "CREDENTIAL_MISMATCH"
        )


    if data.userAgentChanged:

        triggers.append(
            "USER_AGENT_CHANGED"
        )


    if data.isNewDevice:

        triggers.append(
            "NEW_DEVICE"
        )


    # T - Threat

    if data.consecutiveFailureCount >= 1:

        triggers.append(
            "CONSECUTIVE_LOGIN_FAILURE"
        )


    if data.blacklistIpDetected:

        triggers.append(
            "BLACKLIST_IP"
        )


    # C - Context

    if (
        0
        <= data.loginHour
        <= 5
    ):

        triggers.append(
            "ODD_HOUR"
        )


    if data.dayOfWeek in (
        5,
        6,
    ):

        triggers.append(
            "WEEKEND_ACCESS"
        )


    if (
        data.loginRegion
        and
        data.loginRegion.upper()
        != "KR"
    ):

        triggers.append(
            "FOREIGN_LOGIN_REGION"
        )


    # ========================================================
    # 관리자 시연용 상세 로그
    # ========================================================

    print(
        "Rule-Based Trust Score:",
        {
            "formula":
                (
                    "TS = 0.30B + 0.20N + "
                    "0.20D + 0.20T + 0.10C"
                ),

            "B":
                round(
                    behavior_score,
                    2,
                ),

            "N":
                round(
                    network_score,
                    2,
                ),

            "D":
                round(
                    device_score,
                    2,
                ),

            "T":
                round(
                    threat_score,
                    2,
                ),

            "C":
                round(
                    context_score,
                    2,
                ),

            "WB_B":
                round(
                    weighted_behavior,
                    2,
                ),

            "WN_N":
                round(
                    weighted_network,
                    2,
                ),

            "WD_D":
                round(
                    weighted_device,
                    2,
                ),

            "WT_T":
                round(
                    weighted_threat,
                    2,
                ),

            "WC_C":
                round(
                    weighted_context,
                    2,
                ),

            "rule_score":
                rule_score,
        }
    )


    return (
        rule_score,
        feature_scores,
        triggers,
    )


# ============================================================
# 최종 인증 정책
#
# 0 ~ 30
#   ACTIVE
#
# 31 ~ 69
#   RE_AUTH
#
# 70 ~ 100
#   BLOCKED
# ============================================================

def determine_authentication_policy(
    score: int,
) -> tuple[str, str, str]:

    if score <= 30:

        return (
            "low",
            "ACTIVE",
            "로그인이 허용되었습니다.",
        )

    if score <= 69:

        return (
            "medium",
            "RE_AUTH",
            "추가 인증이 필요합니다.",
        )

    return (
        "high",
        "BLOCKED",
        "위험도가 높아 로그인이 차단되었습니다.",
    )


# ============================================================
# Risk 분석 API
# ============================================================

@app.post(
    "/analyze",
    response_model=RiskResponse,
)
def calculate_risk(
    data: LogData,
) -> RiskResponse:

    # ========================================================
    # 로그인 이벤트 ID
    # ========================================================

    event_id = (
        generate_event_id()
    )

    print(
        "Risk Event 생성:",
        event_id,
    )


    # ========================================================
    # B/N/D/T/C 기반 Rule-Based Trust Score
    #
    # TS =
    # 0.30B
    # + 0.20N
    # + 0.20D
    # + 0.20T
    # + 0.10C
    # ========================================================

    (
        score,
        feature_scores,
        triggers,
    ) = calculate_trust_score(
        data
    )


    print(
        "Rule-Based Risk Score 산출 완료:",
        score,
    )


    # ========================================================
    # Isolation Forest
    # ========================================================

    ml_result = (
        run_ml_analysis(
            data
        )
    )


    # ========================================================
    # Hybrid Risk
    #
    # NORMAL
    #   -> Rule Score 유지
    #
    # ANOMALY
    #   -> Rule Score + 20
    # ========================================================

    if (
        ml_result[
            "ml_model_used"
        ]
        and
        ml_result[
            "ml_is_anomaly"
        ] is True
    ):

        ml_risk_score = 20

        score += (
            ml_risk_score
        )

        score = min(
            score,
            100,
        )

        triggers.append(
            "ML_ANOMALY_DETECTED"
        )

        feature_scores[
            "mlAnomaly"
        ] = ml_risk_score


    # ========================================================
    # 최종 인증 정책
    # ========================================================

    (
        risk_level,
        authentication_action,
        message,
    ) = (
        determine_authentication_policy(
            score
        )
    )


    if not triggers:

        triggers.append(
            "NO_RISK_DETECTED"
        )


    # ========================================================
    # Response
    # ========================================================

    risk_response = RiskResponse(
        userIdHash=
            data.userIdHash,

        ipHash=
            data.ipHash,

        deviceType=
            data.deviceType,

        risk_score=
            score,

        risk_level=
            risk_level,

        authentication_action=
            authentication_action,

        message=
            message,

        triggers=
            triggers,

        feature_scores=
            feature_scores,

        ml_model_used=
            ml_result[
                "ml_model_used"
            ],

        ml_model_type=
            ml_result[
                "ml_model_type"
            ],

        ml_anomaly_score=
            ml_result[
                "ml_anomaly_score"
            ],

        ml_is_anomaly=
            ml_result[
                "ml_is_anomaly"
            ],
    )


    # ========================================================
    # REAL Feature 저장
    # ========================================================

    save_ml_feature_log(
        data,
        event_id,
    )


    # ========================================================
    # ML Prediction 저장
    # ========================================================

    save_ml_prediction(
        event_id,
        ml_result,
    )


    # ========================================================
    # Risk 로그 저장
    # ========================================================

    save_risk_log(
        event_id,
        data,
        risk_response,
    )


    # ========================================================
    # 최종 관리자 로그
    # ========================================================

    print(
        "Risk 분석 완료:",
        {
            "event_id":
                event_id,

            "formula":
                (
                    "TS = 0.30B + 0.20N + "
                    "0.20D + 0.20T + 0.10C"
                ),

            "risk_score":
                score,

            "risk_level":
                risk_level,

            "action":
                authentication_action,

            "ml_model_used":
                ml_result[
                    "ml_model_used"
                ],

            "ml_model_type":
                ml_result[
                    "ml_model_type"
                ],

            "ml_anomaly_score":
                ml_result[
                    "ml_anomaly_score"
                ],

            "ml_is_anomaly":
                ml_result[
                    "ml_is_anomaly"
                ],
        }
    )

    return risk_response
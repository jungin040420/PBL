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
        "Rule 기반 Risk Score와 Isolation Forest 이상 탐지를 이용해 "
        "로그인 위험도를 분석하고 ML Feature 및 Prediction을 저장합니다."
    ),
    version="2.0.0",
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
    # Time
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

    # ========================================================
    # Context
    # ========================================================

    loginRegion: str = Field(
        default="KR",
        min_length=2,
        max_length=32,
    )

    hasPreviousContext: bool = False


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
#
# event_id는 외부에서 전달받는다.
# 새 event_id를 여기서 생성하지 않는다.
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
#
# ml_feature_logs와 같은 event_id를 사용한다.
#
# top_anomaly_features:
# 현재 Isolation Forest에서 개별 Feature 기여도를
# 직접 산출하지 않으므로 NULL로 저장한다.
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

    model_type = (
        ml_result.get(
            "ml_model_type"
        )
    )

    anomaly_label = (
        "ANOMALY"
        if is_anomaly is True
        else "NORMAL"
    )

    # --------------------------------------------------------
    # Metadata에서 model_version이 존재하면 사용하고,
    # 없으면 현재 최종 16 Feature REAL 모델임을 나타내는
    # fallback 버전을 사용한다.
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # SYNTHETIC 모델은 실제 로그인 판정에 사용하지 않는다.
    # --------------------------------------------------------

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
    # isolation_model.py FEATURE_ORDER와
    # 반드시 동일한 이름을 사용한다.
    # ========================================================

    features = {

        # B
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

        # N
        "ipChanged":
            data.ipChanged,

        "regionChanged":
            data.regionChanged,

        # D
        "signCountAbnormal":
            data.signCountAbnormal,

        "credentialMismatch":
            data.credentialMismatch,

        "userAgentChanged":
            data.userAgentChanged,

        "isNewDevice":
            data.isNewDevice,

        # T
        "consecutiveFailureCount":
            data.consecutiveFailureCount,

        "blacklistIpDetected":
            data.blacklistIpDetected,

        # Time
        "loginHour":
            data.loginHour,

        "dayOfWeek":
            data.dayOfWeek,

        # Context
        "loginRegion":
            encode_login_region(
                data.loginRegion
            ),

        "hasPreviousContext":
            data.hasPreviousContext,
    }

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

        # B
        "loginFrequency":
            data.loginFrequency,

        "failedLoginCount":
            data.failedLoginCount,

        "challengeResponseTime":
            data.challengeResponseTime,

        "authenticationMethodChanged":
            data.authenticationMethodChanged,

        # N
        "ipChanged":
            data.ipChanged,

        "regionChanged":
            data.regionChanged,

        # D
        "signCountAbnormal":
            data.signCountAbnormal,

        "credentialMismatch":
            data.credentialMismatch,

        "userAgentChanged":
            data.userAgentChanged,

        "isNewDevice":
            data.isNewDevice,

        # T
        "consecutiveFailureCount":
            data.consecutiveFailureCount,

        "blacklistIpDetected":
            data.blacklistIpDetected,

        # Time
        "loginHour":
            data.loginHour,

        "dayOfWeek":
            data.dayOfWeek,

        # Context
        "loginRegion":
            data.loginRegion,

        "hasPreviousContext":
            data.hasPreviousContext,

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

    # ========================================================
    # JSONL 저장
    # ========================================================

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

    # ========================================================
    # Elasticsearch
    # ========================================================

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
# Rule Score
# ============================================================

def calculate_login_frequency_score(
    login_frequency: int,
) -> int:

    if login_frequency >= 10:
        return 15

    if login_frequency >= 5:
        return 10

    if login_frequency >= 3:
        return 5

    return 0


def calculate_login_failure_score(
    login_failures: int,
) -> int:

    if login_failures >= 5:
        return 25

    if login_failures >= 3:
        return 15

    if login_failures >= 1:
        return 5

    return 0


def calculate_response_time_score(
    challenge_response_time:
        Optional[float],
) -> int:

    if challenge_response_time is None:
        return 0

    if 0 < challenge_response_time < 300:
        return 10

    if challenge_response_time > 5000:
        return 5

    return 0


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
    #
    # 이 요청 전체에서 하나의 event_id만 사용한다.
    # ========================================================

    event_id = (
        generate_event_id()
    )

    print(
        "Risk Event 생성:",
        event_id,
    )

    score = 0

    triggers: List[str] = []

    feature_scores: Dict[str, int] = {}


    # ========================================================
    # 로그인 빈도
    # ========================================================

    login_frequency_score = (
        calculate_login_frequency_score(
            data.loginFrequency
        )
    )

    if login_frequency_score > 0:

        score += (
            login_frequency_score
        )

        triggers.append(
            "HIGH_LOGIN_FREQUENCY"
        )

        feature_scores[
            "loginFrequency"
        ] = login_frequency_score


    # ========================================================
    # 로그인 실패
    # ========================================================

    login_failure_score = (
        calculate_login_failure_score(
            data.failedLoginCount
        )
    )

    if login_failure_score > 0:

        score += (
            login_failure_score
        )

        triggers.append(
            "LOGIN_FAILURE"
        )

        feature_scores[
            "failedLoginCount"
        ] = login_failure_score


    # ========================================================
    # IP 변경
    # ========================================================

    if data.ipChanged:

        ip_score = 20

        score += ip_score

        triggers.append(
            "IP_CHANGED"
        )

        feature_scores[
            "ipChanged"
        ] = ip_score


    # ========================================================
    # User-Agent 변경
    # ========================================================

    if data.userAgentChanged:

        user_agent_score = 10

        score += (
            user_agent_score
        )

        triggers.append(
            "USER_AGENT_CHANGED"
        )

        feature_scores[
            "userAgentChanged"
        ] = user_agent_score


    # ========================================================
    # 신규 기기
    # ========================================================

    if data.isNewDevice:

        device_score = 20

        score += (
            device_score
        )

        triggers.append(
            "NEW_DEVICE"
        )

        feature_scores[
            "isNewDevice"
        ] = device_score


    # ========================================================
    # 지역 변경
    # ========================================================

    if data.regionChanged:

        region_score = 10

        score += (
            region_score
        )

        triggers.append(
            "REGION_CHANGED"
        )

        feature_scores[
            "regionChanged"
        ] = region_score


    # ========================================================
    # 해외 접속
    # ========================================================

    if (
        data.country.upper()
        != "KR"
    ):

        country_score = 10

        score += (
            country_score
        )

        triggers.append(
            "FOREIGN_COUNTRY"
        )

        feature_scores[
            "foreignCountry"
        ] = country_score


    # ========================================================
    # Challenge 응답 시간
    # ========================================================

    response_time_score = (
        calculate_response_time_score(
            data.challengeResponseTime
        )
    )

    if response_time_score > 0:

        score += (
            response_time_score
        )

        triggers.append(
            "ABNORMAL_RESPONSE_TIME"
        )

        feature_scores[
            "challengeResponseTime"
        ] = response_time_score


    # ========================================================
    # 새벽 로그인
    # ========================================================

    if (
        0
        <= data.loginHour
        <= 5
    ):

        odd_hour_score = 5

        score += (
            odd_hour_score
        )

        triggers.append(
            "ODD_HOUR"
        )

        feature_scores[
            "loginHour"
        ] = odd_hour_score


    # ========================================================
    # Rule Score 제한
    # ========================================================

    score = max(
        0,
        min(
            score,
            100,
        ),
    )


    # ========================================================
    # Isolation Forest
    # ========================================================

    ml_result = (
        run_ml_analysis(
            data
        )
    )


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
    #
    # 동일 event_id 사용
    # ========================================================

    save_ml_feature_log(
        data,
        event_id,
    )


    # ========================================================
    # ML Prediction 저장
    #
    # 동일 event_id 사용
    # ========================================================

    save_ml_prediction(
        event_id,
        ml_result,
    )


    # ========================================================
    # Risk 로그
    #
    # 동일 event_id 사용
    # ========================================================

    save_risk_log(
        event_id,
        data,
        risk_response,
    )


    print(
        "Risk 분석 완료:",
        {
            "event_id":
                event_id,

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
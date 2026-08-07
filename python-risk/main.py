import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import requests
from fastapi import FastAPI
from pydantic import BaseModel, Field


app = FastAPI(
    title="Rule-Based Risk Score API",
    description="로그인 Feature를 이용해 Risk Score와 인증 정책을 계산합니다.",
    version="1.2.0",
)


LOG_FILE = Path("risk_logs.jsonl")

ELASTICSEARCH_URL = (
    "http://localhost:9200/risk-logs/_doc"
)


# ============================================================
# Request Model
# ============================================================

class LogData(BaseModel):

    # F-08
    # Node에서 USERID_SALT 기반으로 생성
    # Python에서는 해싱하지 않고 전달받은 값 그대로 사용
    userIdHash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "USERID_SALT 기반 SHA-256 사용자 식별자 해시"
        ),
    )

    # F-08
    # Node에서 COMPARE_SALT 기반으로 생성
    # 동일 IP는 동일한 해시값을 생성
    # 원본 IP는 Python으로 전달하지 않는다.
    ipHash: str = Field(
        ...,
        min_length=64,
        max_length=64,
        description=(
            "COMPARE_SALT 기반 SHA-256 IP 비교용 해시"
        ),
    )

    deviceType: str = Field(
        ...,
        min_length=1,
        description=(
            "desktop, mobile, tablet 등의 기기 분류값"
        ),
    )

    country: str = Field(
        default="KR",
        min_length=2,
        description="접속 국가 코드",
    )

    loginFrequency: int = Field(
        default=0,
        ge=0,
        description="로그인 빈도",
    )

    failedLoginCount: int = Field(
        default=0,
        ge=0,
        description="로그인 실패 횟수",
    )

    ipChanged: bool = False

    userAgentChanged: bool = False

    isNewDevice: bool = False

    regionChanged: bool = False

    challengeResponseTime: Optional[float] = Field(
        default=None,
        ge=0,
        description=(
            "FIDO2 Challenge 응답시간(ms)"
        ),
    )

    loginHour: int = Field(
        default=12,
        ge=0,
        le=23,
        description=(
            "로그인 시간, 0~23"
        ),
    )

    dayOfWeek: int = Field(
        default=0,
        ge=0,
        le=6,
        description=(
            "요일, 일요일=0 ~ 토요일=6"
        ),
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


# ============================================================
# Risk Log 저장
# ============================================================

def save_risk_log(
    data: LogData,
    risk_response: RiskResponse,
) -> None:
    """
    F-08 개인정보 처리 기준

    - 원본 username 저장하지 않음
    - 원본 IP 저장하지 않음
    - 원본 User-Agent 저장하지 않음

    Node에서 생성한 userIdHash / ipHash와
    파생 Feature만 저장한다.
    """

    log = {

        "timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "source":
            "python-risk-engine",

        "event_type":
            "risk_analysis",

        # 비식별 사용자 식별자
        "userIdHash":
            data.userIdHash,

        # 비식별 IP 해시
        "ipHash":
            data.ipHash,

        "deviceType":
            data.deviceType,

        "country":
            data.country,

        "loginFrequency":
            data.loginFrequency,

        "failedLoginCount":
            data.failedLoginCount,

        "ipChanged":
            data.ipChanged,

        "userAgentChanged":
            data.userAgentChanged,

        "isNewDevice":
            data.isNewDevice,

        "regionChanged":
            data.regionChanged,

        "challengeResponseTime":
            data.challengeResponseTime,

        "loginHour":
            data.loginHour,

        "dayOfWeek":
            data.dayOfWeek,

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
    }


    # --------------------------------------------------------
    # 로컬 JSONL 로그
    # --------------------------------------------------------

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

    except OSError as error:

        print(
            "Python 로컬 로그 저장 실패:",
            error,
        )


    # --------------------------------------------------------
    # Elasticsearch 저장
    # --------------------------------------------------------

    try:

        elasticsearch_response = requests.post(
            ELASTICSEARCH_URL,
            json=log,
            timeout=3,
        )

        elasticsearch_response.raise_for_status()

        print(
            "Python 로그 Elasticsearch 저장 성공"
        )

    except requests.RequestException as error:

        # Elasticsearch 장애가
        # Risk API 자체를 중단시키지 않도록 한다.
        print(
            "Python 로그 Elasticsearch 저장 실패:",
            error,
        )


# ============================================================
# Root
# ============================================================

@app.get("/")
def read_root():

    return {
        "status":
            "Python 리스크 서버 실행 중",

        "api":
            "POST /analyze",

        "docs":
            "/docs",
    }


# ============================================================
# 로그인 빈도 점수
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


# ============================================================
# 로그인 실패 점수
# ============================================================

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


# ============================================================
# Challenge 응답시간 점수
# ============================================================

def calculate_response_time_score(
    challenge_response_time: Optional[float],
) -> int:

    if challenge_response_time is None:
        return 0

    # 비정상적으로 빠른 응답
    if 0 < challenge_response_time < 300:
        return 10

    # 비정상적으로 느린 응답
    if challenge_response_time > 5000:
        return 5

    return 0


# ============================================================
# 최종 인증 정책 결정
# ============================================================

def determine_authentication_policy(
    score: int,
) -> tuple[str, str, str]:

    # LOW
    if score <= 30:

        return (
            "low",
            "ACTIVE",
            "로그인이 허용되었습니다.",
        )

    # MEDIUM
    if score <= 69:

        return (
            "medium",
            "RE_AUTH",
            "추가 인증이 필요합니다.",
        )

    # HIGH
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

    score = 0

    triggers: List[str] = []

    feature_scores: Dict[str, int] = {}


    # --------------------------------------------------------
    # 1. 로그인 빈도
    # --------------------------------------------------------

    login_frequency_score = (
        calculate_login_frequency_score(
            data.loginFrequency
        )
    )

    if login_frequency_score > 0:

        score += login_frequency_score

        triggers.append(
            "HIGH_LOGIN_FREQUENCY"
        )

        feature_scores[
            "loginFrequency"
        ] = login_frequency_score


    # --------------------------------------------------------
    # 2. 로그인 실패 횟수
    # --------------------------------------------------------

    login_failure_score = (
        calculate_login_failure_score(
            data.failedLoginCount
        )
    )

    if login_failure_score > 0:

        score += login_failure_score

        triggers.append(
            "LOGIN_FAILURE"
        )

        feature_scores[
            "failedLoginCount"
        ] = login_failure_score


    # --------------------------------------------------------
    # 3. IP 변경
    # --------------------------------------------------------

    if data.ipChanged:

        ip_score = 20

        score += ip_score

        triggers.append(
            "IP_CHANGED"
        )

        feature_scores[
            "ipChanged"
        ] = ip_score


    # --------------------------------------------------------
    # 4. User-Agent 변경
    # --------------------------------------------------------

    if data.userAgentChanged:

        user_agent_score = 10

        score += user_agent_score

        triggers.append(
            "USER_AGENT_CHANGED"
        )

        feature_scores[
            "userAgentChanged"
        ] = user_agent_score


    # --------------------------------------------------------
    # 5. 신규 기기
    # --------------------------------------------------------

    if data.isNewDevice:

        device_score = 20

        score += device_score

        triggers.append(
            "NEW_DEVICE"
        )

        feature_scores[
            "isNewDevice"
        ] = device_score


    # --------------------------------------------------------
    # 6. 접속 지역 변경
    # --------------------------------------------------------

    if data.regionChanged:

        region_score = 10

        score += region_score

        triggers.append(
            "REGION_CHANGED"
        )

        feature_scores[
            "regionChanged"
        ] = region_score


    # --------------------------------------------------------
    # 7. 해외 접속
    # --------------------------------------------------------

    if data.country.upper() != "KR":

        country_score = 10

        score += country_score

        triggers.append(
            "FOREIGN_COUNTRY"
        )

        feature_scores[
            "foreignCountry"
        ] = country_score


    # --------------------------------------------------------
    # 8. Challenge 응답시간
    # --------------------------------------------------------

    response_time_score = (
        calculate_response_time_score(
            data.challengeResponseTime
        )
    )

    if response_time_score > 0:

        score += response_time_score

        triggers.append(
            "ABNORMAL_RESPONSE_TIME"
        )

        feature_scores[
            "challengeResponseTime"
        ] = response_time_score


    # --------------------------------------------------------
    # 9. 새벽 로그인
    # --------------------------------------------------------

    if 0 <= data.loginHour <= 5:

        odd_hour_score = 5

        score += odd_hour_score

        triggers.append(
            "ODD_HOUR"
        )

        feature_scores[
            "loginHour"
        ] = odd_hour_score


    # --------------------------------------------------------
    # 최종 점수 0 ~ 100 제한
    # --------------------------------------------------------

    score = max(
        0,
        min(
            score,
            100,
        ),
    )


    # --------------------------------------------------------
    # 인증 정책 결정
    # --------------------------------------------------------

    (
        risk_level,
        authentication_action,
        message,
    ) = determine_authentication_policy(
        score
    )


    if not triggers:

        triggers.append(
            "NO_RISK_DETECTED"
        )


    # --------------------------------------------------------
    # Response 생성
    # --------------------------------------------------------

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
    )


    # --------------------------------------------------------
    # 로그 저장
    # --------------------------------------------------------

    save_risk_log(
        data,
        risk_response,
    )


    return risk_response
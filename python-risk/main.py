
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from typing import Optional


app = FastAPI(
    title="Rule-Based Risk Score API",
    description="로그인 Feature를 이용해 Risk Score와 인증 정책을 계산합니다.",
    version="1.0.0",
)

class LogData(BaseModel):

    user_id: str = Field(..., min_length=1)
    ip: str = Field(..., min_length=1)
    device: str = Field(..., min_length=1)

    country: str = "KR"

    login_frequency: int = Field(default=0, ge=0)
    login_failures: int = Field(default=0, ge=0)

    ip_changed: bool = False
    user_agent_changed: bool = False
    is_new_device: bool = False
    location_changed: bool = False

    challenge_response_time: Optional[float] = Field(
        default=None,
        ge=0,
        description="FIDO2 Challenge 응답시간(ms)",
    )

    login_hour: int = Field(
        default=12,
        ge=0,
        le=23,
        description="로그인 시간, 0~23",
    )

    day_of_week: int = Field(
        default=0,
        ge=0,
        le=6,
        description="요일, 월요일=0 ~ 일요일=6",
    )

    is_phishing_url: bool = False


class RiskResponse(BaseModel):
    user_id: str
    ip: str
    device: str

    risk_score: int
    risk_level: str
    authentication_action: str
    message: str

    triggers: List[str]
    feature_scores: Dict[str, int]


@app.get("/")
def read_root():
    return {
        "status": "Python 리스크 서버 실행 중",
        "api": "POST /risk",
        "docs": "/docs",
    }


def calculate_login_frequency_score(login_frequency: int) -> int:
    if login_frequency >= 10:
        return 15

    if login_frequency >= 5:
        return 10

    if login_frequency >= 3:
        return 5

    return 0


def calculate_login_failure_score(login_failures: int) -> int:
    if login_failures >= 5:
        return 25

    if login_failures >= 3:
        return 15

    if login_failures >= 1:
        return 5

    return 0


def calculate_response_time_score(
    challenge_response_time: Optional[float],
) -> int:
    if challenge_response_time is None:
        return 0

    # 지나치게 빠른 응답
    if 0 < challenge_response_time < 300:
        return 10

    # 지나치게 느린 응답
    if challenge_response_time > 5000:
        return 5

    return 0


def determine_authentication_policy(score: int) -> tuple[str, str, str]:
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


@app.post("/risk", response_model=RiskResponse)
def calculate_risk(data: LogData):
    # 피싱 URL은 Risk Score Feature가 아니다.
    # 탐지되는 즉시 점수 계산 없이 차단한다.
    if data.is_phishing_url:
        return RiskResponse(
            user_id=data.user_id,
            ip=data.ip,
            device=data.device,
            risk_score=100,
            risk_level="critical",
            authentication_action="BLOCKED",
            message="위험 URL이 탐지되어 즉시 차단되었습니다.",
            triggers=["PHISHING_URL_BLOCKED"],
            feature_scores={},
        )

    score = 0
    triggers: List[str] = []
    feature_scores: Dict[str, int] = {}

    # 1. 로그인 빈도
    login_frequency_score = calculate_login_frequency_score(
        data.login_frequency
    )

    if login_frequency_score > 0:
        score += login_frequency_score
        triggers.append("HIGH_LOGIN_FREQUENCY")
        feature_scores["login_frequency"] = login_frequency_score

    # 2. 로그인 실패 횟수
    login_failure_score = calculate_login_failure_score(
        data.login_failures
    )

    if login_failure_score > 0:
        score += login_failure_score
        triggers.append("LOGIN_FAILURE")
        feature_scores["login_failures"] = login_failure_score

    # 3. IP 변경
    if data.ip_changed:
        ip_score = 20
        score += ip_score
        triggers.append("IP_CHANGED")
        feature_scores["ip_changed"] = ip_score

    # 4. User-Agent 변경
    if data.user_agent_changed:
        user_agent_score = 10
        score += user_agent_score
        triggers.append("USER_AGENT_CHANGED")
        feature_scores["user_agent_changed"] = user_agent_score

    # 5. 신규 기기
    if data.is_new_device:
        device_score = 20
        score += device_score
        triggers.append("NEW_DEVICE")
        feature_scores["is_new_device"] = device_score

    # 6. 접속 지역 변경
    if data.location_changed:
        location_score = 10
        score += location_score
        triggers.append("LOCATION_CHANGED")
        feature_scores["location_changed"] = location_score

    # 7. 해외 접속
    if data.country.upper() != "KR":
        country_score = 10
        score += country_score
        triggers.append("FOREIGN_COUNTRY")
        feature_scores["foreign_country"] = country_score

    # 8. Challenge 응답시간
    response_time_score = calculate_response_time_score(
        data.challenge_response_time
    )

    if response_time_score > 0:
        score += response_time_score
        triggers.append("ABNORMAL_RESPONSE_TIME")
        feature_scores["challenge_response_time"] = response_time_score

    # 9. 새벽 로그인
    if 0 <= data.login_hour <= 5:
        odd_hour_score = 5
        score += odd_hour_score
        triggers.append("ODD_HOUR")
        feature_scores["login_hour"] = odd_hour_score

    # 최종 점수는 0~100으로 제한
    score = max(0, min(score, 100))

    risk_level, authentication_action, message = (
        determine_authentication_policy(score)
    )

    if not triggers:
        triggers.append("NO_RISK_DETECTED")

    return RiskResponse(
        user_id=data.user_id,
        ip=data.ip,
        device=data.device,
        risk_score=score,
        risk_level=risk_level,
        authentication_action=authentication_action,
        message=message,
        triggers=triggers,
        feature_scores=feature_scores,
    )

    username: str
    ip: Optional[str] = None
    userAgent: Optional[str] = None
    deviceType: Optional[str] = None
    os: Optional[str] = None
    accessTime: Optional[str] = None
    isNightAccess: Optional[bool] = False
    loginFrequency: Optional[int] = 0
    failedLoginCount: Optional[int] = 0
    ipChanged: Optional[bool] = False
    userAgentChanged: Optional[bool] = False
    deviceChanged: Optional[bool] = False
    challengeResponseTime: Optional[int] = None

@app.get("/")
def read_root():
    return {"status": "Python 리스크 서버 실행중",
    "api: "POST /analyze",
    "docs": "/docs"
    }

@app.post("/analyze")
def calculate_risk(data: LogData):
    score = 0
    triggers = []

    # 기기 변경 여부 (+35점)
    if data.deviceChanged:
        score += 35
        triggers.append("DEVICE_CHANGED")

    # IP 변경 여부 (+30점)
    if data.ipChanged:
        score += 30
        triggers.append("IP_CHANGED")

    # User-Agent 변경 여부 (+20점)
    if data.userAgentChanged:
        score += 20
        triggers.append("UA_CHANGED")

    # 로그인 실패 횟수 (1회당 +20점)
    if data.failedLoginCount > 0:
        score += data.failedLoginCount * 20
        triggers.append("FAIL_LOGIN")

    # 로그인 빈도 (10회 이상 +15점)
    if data.loginFrequency >= 10:
        score += 15
        triggers.append("HIGH_FREQUENCY")

    # Challenge 응답 시간 (1초 미만 자동화 의심 +40점)
    if data.challengeResponseTime is not None:
        if data.challengeResponseTime < 1000:
            score += 40
            triggers.append("FAST_RESPONSE")

    # 야간 접속 (+15점)
    if data.isNightAccess:
        score += 15
        triggers.append("NIGHT_ACCESS")

    # 점수 최대 100점으로 제한
    score = min(score, 100)

    # 위험 등급 결정
    if score >= 70:
        level = "high"
        action = "BLOCKED"
    elif score >= 31:
        level = "medium"
        action = "RE_AUTH"
    else:
        level = "low"
        action = "ACTIVE"

    return {
        "username": data.username,
        "score": score,
        "level": level,
        "action": action,
        "triggers": triggers
    }


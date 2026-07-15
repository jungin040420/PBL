from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

app = FastAPI()

class LogData(BaseModel):
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
    return {"status": "Python 리스크 서버 실행중"}

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
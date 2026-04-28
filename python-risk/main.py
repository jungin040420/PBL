from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional


app = FastAPI()


class LogData(BaseModel):
    user_id: str
    ip: str
    device: str
    country: Optional[str] = "KR"
    login_failures: Optional[int] = 0
    is_phishing_url: Optional[bool] = False
    is_new_device: Optional[bool] = False


@app.get("/")
def read_root():
    return {"status": "Python 리스크 서버 실행중"}


@app.post("/risk")
def calculate_risk(data: LogData):
    score = 0
    triggers = []

    # 새로운 기기 접속 (+35점)
    if data.is_new_device:
        score += 35
        triggers.append("NEW_DEVICE")

    # 해외 접속 (+35점)
    if data.country != "KR":
        score += 35
        triggers.append("NEW_COUNTRY")

    # 피싱 URL 접속 감지 (+50점)
    if data.is_phishing_url:
        score += 50
        triggers.append("PHISHING_URL")

    # 로그인 실패 (1회당 +20점)
    if data.login_failures > 0:
        score += data.login_failures * 20
        triggers.append("FAIL_LOGIN")

    # 새벽 0시~5시 접속 (+15점)
    current_hour = datetime.utcnow().hour + 9
    if 0 <= current_hour % 24 <= 5:
        score += 15
        triggers.append("ODD_HOUR")

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
        "user_id": data.user_id,
        "ip": data.ip,
        "device": data.device,
        "score": score,
        "level": level,
        "action": action,
        "triggers": triggers
    }

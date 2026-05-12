from fastapi import FastAPI
from pydantic import BaseModel
from datetime import datetime

app = FastAPI()

class RiskRequest(BaseModel):
    user_id: str
    ip: str
    device: str
    country: str = "KR"
    login_failures: int = 0
    is_phishing_url: bool = False
    is_new_device: bool = False

@app.get("/")
def root():
    return {"status": "Python 리스크 서버 실행중"}

@app.post("/risk")
def calculate_risk(req: RiskRequest):
    score = 0
    triggers = []

    # 1. 로그인 실패 횟수
    if req.login_failures >= 3:
        score += 30
        triggers.append("로그인 실패 3회 이상")

    # 2. 새로운 기기
    if req.is_new_device:
        score += 20
        triggers.append("새로운 기기 접속")

    # 3. 피싱 URL
    if req.is_phishing_url:
        score += 40
        triggers.append("피싱 URL 감지")

    # 4. 한국 외 접속
    if req.country != "KR":
        score += 10
        triggers.append("해외 접속")

    # 5. 새벽 시간대 (0시~5시)
    hour = datetime.now().hour
    if hour >= 0 and hour <= 5:
        score += 10
        triggers.append("새벽 시간대 접속")

    score = min(score, 100)

    return {
        "user_id": req.user_id,
        "score": score,
        "triggers": triggers,
        "level": "high" if score >= 70 else "medium" if score >= 40 else "low"
    }

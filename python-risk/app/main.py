from fastapi import FastAPI
from pydantic import BaseModel
from feature import extract_features
from detector import detect_suspicious

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
    # 1. 데이터 가공 (feature.py)
    features = extract_features(req.dict())
    
    # 2. 위험도 판단 (detector.py)
    result = detect_suspicious(features)

    return {
        "user_id": req.user_id,
        "score": result["score"],
        "triggers": result["triggers"],
        "level": result["level"]
    }
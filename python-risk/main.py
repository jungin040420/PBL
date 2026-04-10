from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class LogData(BaseModel):
    user_id: str
    ip: str
    device: str


@app.get("/")
def read_root():
    return {"status": "Python 리스크 서버 실행중"}


@app.post("/risk")
def calculate_risk(data: LogData):
    score = 0

    known_ips = ["127.0.0.1", "localhost"]
    if data.ip not in known_ips:
        score += 50

    known_devices = ["Chrome", "Firefox", "Safari"]
    if not any(d in data.device for d in known_devices):
        score += 30

    return {
        "user_id": data.user_id,
        "ip": data.ip,
        "device": data.device,
        "score": score,
        "level": "high" if score >= 50 else "low"
    }
from datetime import datetime

def detect_suspicious(data: dict) -> dict:
    score = 0
    triggers = []

    # 1. 로그인 실패 횟수
    if data.get("login_failures", 0) >= 3:
        score += 30
        triggers.append("로그인 실패 3회 이상")

    # 2. 새로운 기기
    if data.get("is_new_device", False):
        score += 20
        triggers.append("새로운 기기 접속")

    # 3. 피싱 URL
    if data.get("is_phishing_url", False):
        score += 40
        triggers.append("피싱 URL 감지")

    # 4. 해외 접속
    if data.get("country", "KR") != "KR":
        score += 10
        triggers.append("해외 접속")

    # 5. 새벽 시간대
    hour = datetime.now().hour
    if 0 <= hour <= 5:
        score += 10
        triggers.append("새벽 시간대 접속")

    score = min(score, 100)

    return {
        "score": score,
        "triggers": triggers,
        "level": "high" if score >= 70 else "medium" if score >= 40 else "low"
    }
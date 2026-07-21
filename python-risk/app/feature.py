from datetime import datetime

def extract_features(data: dict) -> dict:
    return {
        "user_id": data.get("user_id", "unknown"),
        "ip": data.get("ip", "0.0.0.0"),
        "device": data.get("device", "unknown"),
        "country": data.get("country", "KR"),
        "login_failures": int(data.get("login_failures", 0)),
        "is_phishing_url": bool(data.get("is_phishing_url", False)),
        "is_new_device": bool(data.get("is_new_device", False)),
        "hour": datetime.now().hour,
        "is_night": 0 <= datetime.now().hour <= 5
    }
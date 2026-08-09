from typing import Any, Dict


def extract_features(data: Dict[str, Any]) -> Dict[str, float]:
    """
    Isolation Forest 입력용 Feature 추출.

    원본 개인정보는 ML Feature에 포함하지 않는다.
    Node/Python /analyze에서 사용하는 파생값만 숫자형으로 변환한다.
    """

    challenge_response_time = data.get(
        "challengeResponseTime"
    )

    if challenge_response_time is None:
        challenge_response_time = 0.0

    return {
        "loginFrequency": float(
            data.get("loginFrequency", 0)
        ),

        "failedLoginCount": float(
            data.get("failedLoginCount", 0)
        ),

        "ipChanged": float(
            bool(data.get("ipChanged", False))
        ),

        "userAgentChanged": float(
            bool(data.get("userAgentChanged", False))
        ),

        "isNewDevice": float(
            bool(data.get("isNewDevice", False))
        ),

        "regionChanged": float(
            bool(data.get("regionChanged", False))
        ),

        "challengeResponseTime": float(
            challenge_response_time
        ),

        "loginHour": float(
            data.get("loginHour", 12)
        ),

        "dayOfWeek": float(
            data.get("dayOfWeek", 0)
        ),
    }
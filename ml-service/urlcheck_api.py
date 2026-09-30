"""
url_check_api.py

index.html(AI URL Checker)의 `POST {API_BASE_URL}/check` 요청을 처리하는 FastAPI 서버.

요청:  { "url": "https://example.com" }
응답:  { "url", "blocked", "prediction", "probability", "verdict" }
        verdict  : "Legitimate" | "Suspicious" | "Malicious"
        probability : 피싱(위험) 확률 0~1

실행 (url_feature_extractor.py, model_artifacts/, index.html과 같은 폴더에서):

    pip install fastapi uvicorn
    uvicorn url_check_api:app --host 0.0.0.0 --port 8000

브라우저에서 http://localhost:8000 접속 -> 페이지가 바로 열립니다.
(nginx 등 리버스 프록시를 쓴다면 /urlcheck_api/ -> 이 서버로 전달하세요.)
"""

import ipaddress
import socket
import threading
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from pydantic import BaseModel, Field

from url_feature_extractor import normalize_url, predict_url

# ============================================================
# 설정
# ============================================================

API_PREFIX = "/urlcheck_api"      # index.html의 API_BASE_URL과 동일하게
INDEX_HTML = Path(__file__).resolve().parent / "index.html"

MALICIOUS_THRESHOLD = 0.5         # 모델이 PHISHING으로 판정하면 항상 Malicious
SUSPICIOUS_THRESHOLD = 0.3        # LEGIT이지만 피싱 확률이 이 이상이면 Suspicious

MAX_CONCURRENT_CHECKS = 2         # 동시에 띄울 브라우저 수
_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)


# ============================================================
# 요청/응답 스키마
# ============================================================

class CheckRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)


class CheckResponse(BaseModel):
    url: str
    blocked: bool
    prediction: int
    probability: float
    verdict: str
    # 참고용 추가 정보 (프론트는 사용하지 않아도 무방)
    final_url: str | None = None
    title: str | None = None
    official_domain: bool = False
    reason: str | None = None


# ============================================================
# 보안: 내부망 접근(SSRF) 차단
# ============================================================

def assert_public_url(url: str) -> None:
    """http/https 이고, 호스트가 공인 IP로만 해석될 때만 통과"""
    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise HTTPException(400, "http 또는 https 주소만 검사할 수 있습니다.")

    host = parsed.hostname
    if not host:
        raise HTTPException(400, "올바른 URL이 아닙니다.")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise HTTPException(400, "도메인을 찾을 수 없습니다.")

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise HTTPException(400, "내부 주소는 검사할 수 없습니다.")


# ============================================================
# 결과 -> 프론트 응답 변환
# ============================================================

def build_response(result: dict) -> CheckResponse:
    prediction = int(result["prediction"])
    prob = result.get("phishing_probability")

    # 확률을 못 구한 경우 prediction으로 대체
    if prob is None:
        prob = 0.0 if prediction == 1 else 1.0

    if result["verdict"] == "TRUSTED_SITE":
        verdict = "Legitimate"
    elif prediction == 0 or prob >= MALICIOUS_THRESHOLD:
        verdict = "Malicious"
    elif prob >= SUSPICIOUS_THRESHOLD:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return CheckResponse(
        url=result["url"],
        blocked=(verdict == "Malicious"),
        prediction=prediction,
        probability=float(prob),
        verdict=verdict,
        final_url=result.get("final_url"),
        title=result.get("title"),
        official_domain=bool(result.get("official_domain")),
        reason=result.get("verdict_reason"),
    )


# ============================================================
# 라우터
# ============================================================

router = APIRouter()


@router.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    # sync def 이므로 FastAPI가 스레드풀에서 실행 (Playwright sync API 사용 가능)
    url = normalize_url(req.url)
    assert_public_url(url)

    if not _slots.acquire(timeout=60):
        raise HTTPException(503, "요청이 많습니다. 잠시 후 다시 시도해주세요.")

    try:
        result = predict_url(url)
    except PlaywrightTimeoutError:
        raise HTTPException(504, "페이지 로딩 시간이 초과되었습니다.")
    except (FileNotFoundError, ValueError) as e:
        # 모델 파일 누락, 학습 때 없던 범주값(TLD 등)
        raise HTTPException(422, f"분석할 수 없는 URL입니다: {e}")
    except Exception as e:
        raise HTTPException(502, f"페이지 분석에 실패했습니다: {e}")
    finally:
        _slots.release()

    return build_response(result)


@router.get("/health")
def health():
    return {"status": "ok"}


# ============================================================
# 앱
# ============================================================

app = FastAPI(title="AI URL Checker API")

# 프론트를 다른 origin에서 열 때만 필요. 운영 시 allow_origins를 실제 도메인으로 제한하세요.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# /urlcheck_api/check (프론트용) 와 /check (직접 호출/프록시가 prefix를 제거하는 경우) 모두 지원
app.include_router(router, prefix=API_PREFIX)
app.include_router(router)


@app.get("/", include_in_schema=False)
def index():
    if INDEX_HTML.exists():
        return FileResponse(INDEX_HTML)
    raise HTTPException(404, "index.html이 없습니다.")
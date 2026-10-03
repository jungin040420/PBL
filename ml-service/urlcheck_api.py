"""
url_check_api.py

index.html(AI URL Checker)의 요청을 처리하는 FastAPI 서버.

전체 흐름
  index.html --POST /check--> 정상(Legitimate)이면 /login.html 로 이동
  login.html --POST /login--> 서버가 로그인 페이지를 한 번 더 검사한 뒤 인증

엔드포인트
  GET  /                : index.html
  GET  /login.html      : login.html (index.html이 정상 판정 시 이동하는 곳)
  POST /check           : URL 하나를 검사해 판정만 돌려줌
  POST /login           : 로그인 시도가 일어난 페이지를 검사한 뒤 판정에 따라 처리
                            Malicious  -> 403 (로그인 차단, 자격 증명도 검사하지 않음)
                            Suspicious -> 비밀번호 확인 후 FIDO2 재인증 요구
                            Legitimate -> 비밀번호 확인 후 로그인 성공
                          검사 대상 페이지는 body의 page_url, 없으면 브라우저가 보내는
                          Referer 헤더(= login.html 주소)를 사용한다.
  GET  /health          : 상태 확인

실행 (url_feature_extractor.py, model_artifacts/, index.html과 같은 폴더에서):

    pip install fastapi uvicorn
    uvicorn url_check_api:app --host 0.0.0.0 --port 8000

브라우저에서 http://localhost:8000 접속 -> 페이지가 바로 열립니다.
(nginx 등 리버스 프록시를 쓴다면 /urlcheck_api/ -> 이 서버로 전달하세요.)

주의: assert_public_url 때문에 localhost/내부 IP는 검사할 수 없습니다.
      로컬 테스트는 hosts 파일로 공인 IP에 해석되는 도메인을 만들어 사용하세요.
"""

import hashlib
import hmac
import ipaddress
import socket
import threading
from pathlib import Path
from urllib.parse import urlparse

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from pydantic import BaseModel, Field

from url_feature_extractor import get_domain, normalize_url, predict_url

# ============================================================
# 설정
# ============================================================

API_PREFIX = "/urlcheck_api"      # index.html의 API_BASE_URL과 동일하게
BASE_DIR = Path(__file__).resolve().parent
INDEX_HTML = BASE_DIR / "index.html"
LOGIN_HTML = BASE_DIR / "login.html"   # index.html이 정상 판정 시 이동하는 페이지

# /login 때 로그인 페이지를 한 번 더 검사할지 여부.
# index.html을 거치지 않고 /login.html 로 바로 들어오는 경우를 막기 위한 이중 확인이다.
# 요청마다 Playwright를 띄우므로 느리면 False로 끌 수 있지만, 그러면 /login 은 검사 없이 통과한다.
RECHECK_ON_LOGIN = True

MALICIOUS_THRESHOLD = 0.5         # 모델이 PHISHING으로 판정하면 항상 Malicious
SUSPICIOUS_THRESHOLD = 0.3        # LEGIT이지만 피싱 확률이 이 이상이면 Suspicious

MAX_CONCURRENT_CHECKS = 2         # 동시에 띄울 브라우저 수
_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CHECKS)

# /login 에서 Origin/Referer 헤더가 없을 때 거절할지 여부
# 브라우저의 fetch/XHR POST는 항상 Origin을 보내므로 운영에서는 True 권장.
# curl 등으로 테스트할 때만 False로 바꾸세요.
REQUIRE_ORIGIN_HEADER = True


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


class LoginRequest(BaseModel):
    id: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)
    # 로그인 시도가 일어난 페이지. 생략하면 Referer 헤더를 사용한다.
    page_url: str | None = Field(default=None, max_length=2048)
    fido2_token: str | None = None  # Suspicious일 때 FIDO2 재인증 후 받은 토큰


class LoginResponse(BaseModel):
    status: str          # "ok" | "fido2_required"
    verdict: str         # "Legitimate" | "Suspicious"
    probability: float
    message: str


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
# 보안: 요청 무결성 (page_url 위조 방지)
# ============================================================

def verify_request_origin(request: Request, page_url: str) -> None:
    """
    클라이언트가 보낸 page_url 은 위조할 수 있다.
    (피싱 페이지가 정상 URL을 page_url 로 보내면 검사를 우회 가능)
    브라우저가 직접 붙이는 Origin/Referer 의 호스트가 page_url 의 호스트와
    같은지 확인한다. 이 헤더는 페이지의 JS가 임의로 바꿀 수 없다.
    """
    header = request.headers.get("origin") or request.headers.get("referer")

    if not header:
        if REQUIRE_ORIGIN_HEADER:
            raise HTTPException(403, "요청 출처(Origin)를 확인할 수 없습니다.")
        return

    origin_host = get_domain(header)
    page_host = get_domain(page_url)

    if not origin_host or origin_host != page_host:
        raise HTTPException(403, "요청 출처와 page_url이 일치하지 않습니다.")


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
# 검사 로직 (/check 와 /login 이 공유)
# ============================================================

def run_check(raw_url: str) -> CheckResponse:
    """
    URL 검사 전체 과정. 실패하면 HTTPException 을 던진다.
    sync 함수이므로 FastAPI 엔드포인트(def)에서 스레드풀로 실행된다.
    (Playwright sync API 사용 가능)
    """
    url = normalize_url(raw_url)
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


# ============================================================
# 인증 (데모용 — 실제 DB/해시 검사로 교체하세요)
# ============================================================

_DEMO_SALT = b"demo-salt-change-me"


def _hash_password(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _DEMO_SALT, 100_000)


# TODO: 실제 사용자 DB로 교체. 지금은 데모 계정 하나뿐.
_DEMO_USERS = {"testuser": _hash_password("1234")}


def verify_user(user_id: str, password: str) -> bool:
    stored = _DEMO_USERS.get(user_id)
    # 존재하지 않는 계정이어도 같은 비용으로 해시를 계산해 타이밍 차이를 줄인다
    candidate = _hash_password(password)
    if stored is None:
        return False
    return hmac.compare_digest(stored, candidate)


def verify_fido2_token(token: str | None, user_id: str) -> bool:
    """
    TODO: FIDO2(WebAuthn) 검증으로 교체.
    서버가 발급한 challenge 에 대한 assertion 을 검증하고, 성공 시
    user_id 에 묶인 짧은 수명의 토큰을 발급/확인하는 방식이 일반적이다.
    구현 전까지는 항상 False 이므로 Suspicious 판정은 로그인이 되지 않는다.
    """
    return False


# ============================================================
# 라우터
# ============================================================

router = APIRouter()


@router.post("/check", response_model=CheckResponse)
def check(req: CheckRequest):
    return run_check(req.url)


@router.post("/login", response_model=LoginResponse)
def login(req: LoginRequest, request: Request):
    # 1) 검사할 페이지 결정: body의 page_url, 없으면 브라우저가 붙이는 Referer
    page_url = req.page_url or request.headers.get("referer")
    if not page_url:
        if RECHECK_ON_LOGIN and REQUIRE_ORIGIN_HEADER:
            raise HTTPException(403, "요청 출처(Referer)를 확인할 수 없습니다.")
        page_url = None
    else:
        page_url = normalize_url(page_url)
        # page_url 위조 여부 확인 (Origin/Referer 호스트와 비교)
        verify_request_origin(request, page_url)

    # 2) 로그인 시도가 일어난 페이지 검사
    if RECHECK_ON_LOGIN and page_url:
        check_result = run_check(page_url)
    else:
        # 재검사를 끈 경우: 페이지 검사는 index.html 단계에서 이미 끝났다고 가정
        check_result = CheckResponse(
            url=page_url or "", blocked=False, prediction=1,
            probability=0.0, verdict="Legitimate",
        )

    # 3) Malicious: 자격 증명을 확인하지 않고 바로 차단
    if check_result.verdict == "Malicious":
        raise HTTPException(403, "피싱 사이트로 의심되어 로그인을 차단합니다.")

    # 4) 비밀번호 확인
    if not verify_user(req.id, req.password):
        raise HTTPException(401, "아이디 또는 비밀번호가 올바르지 않습니다.")

    # 5) Suspicious: FIDO2 재인증이 끝난 요청만 통과
    if check_result.verdict == "Suspicious":
        if not verify_fido2_token(req.fido2_token, req.id):
            return LoginResponse(
                status="fido2_required",
                verdict=check_result.verdict,
                probability=check_result.probability,
                message="의심스러운 사이트입니다. FIDO2 재인증이 필요합니다.",
            )

    # 6) Legitimate (또는 FIDO2 통과한 Suspicious)
    return LoginResponse(
        status="ok",
        verdict=check_result.verdict,
        probability=check_result.probability,
        message="로그인에 성공했습니다.",
    )


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


# index.html이 정상 판정 후 이동하는 페이지 (window.location.href = "/login.html")
@app.get("/login.html", include_in_schema=False)
def login_page():
    if LOGIN_HTML.exists():
        return FileResponse(LOGIN_HTML)
    raise HTTPException(404, "login.html이 없습니다.")
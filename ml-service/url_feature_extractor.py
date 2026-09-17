"""
feature_extractor.py
─────────────────────────────────────────────────────────
train.py 에서 학습에 사용한 59개 피처(SELECTED_FEATURES)를
"실시간으로" 그대로 재현하기 위한 모듈.

  ① URL 정적 피처        : urllib.parse / 정규식 만으로 계산 (스캔 불필요)
  ② phish_* 휴리스틱 피처 : URL 문자열 분석만으로 계산 (스캔 불필요)
  ③ web_*  DOM/스캔 피처  : Playwright로 실제 페이지에 접속해서 계산

주의:
  원본 CSV(final_dataset_with_all_features_v3_1.csv)를 만든 원본 피처
  엔지니어링 코드가 없으므로, phish_*/web_* 항목은 컬럼명과 데이터 분포
  (예: web_security_score 0~4 = csp+xframe+hsts+xcontent 합)를 근거로
  "동일한 의미가 되도록" 최대한 합리적으로 재구성한 것입니다.
  실제 운영 전에는 브랜드 리스트/의심 TLD/키워드 목록을 프로젝트 요구사항에
  맞게 조정하세요.
"""

import re
import asyncio
import ipaddress
from urllib.parse import urlparse, parse_qs

from playwright.async_api import async_playwright


# ─────────────────────────────────────────────
# 참조 리스트 (필요에 따라 자유롭게 확장/수정)
# ─────────────────────────────────────────────

SHORTENER_PATTERN = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|"
    r"is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|"
    r"su\.pr|twurl\.nl|snipurl\.com|short\.to|budurl\.com|ping\.fm|post\.ly|"
    r"just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|"
    r"kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|"
    r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|"
    r"bc\.vc|rb\.gy|shrtco\.de",
    re.IGNORECASE,
)

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "loan", "download", "review", "country", "science", "gdn", "men",
}

BRAND_LIST = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook", "netflix",
    "bank", "chase", "wellsfargo", "instagram", "whatsapp", "outlook", "office365",
    "naver", "kakao", "samsung", "coupang", "toss", "kb국민", "shinhan",
    "netflix", "steam", "binance", "coinbase", "dropbox", "adobe", "linkedin",
]

URGENCY_WORDS = [
    "urgent", "verify", "suspend", "suspended", "immediately", "expire",
    "expires", "limited", "action required", "warning", "restricted",
    "confirm now", "24 hours", "locked",
]

SECURITY_WORDS = [
    "password", "login", "signin", "account", "security", "ssn", "credential",
]

PATH_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "webscr", "banking",
]

HACKED_TERMS = [
    "hacked", "deface", "defaced", "shell", "c99", "r57", "backdoor", "owned",
    "pwned", "cracked",
]

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".apk", ".zip", ".rar", ".js", ".vbs", ".msi",
    ".jar", ".php.exe",
)


def _get_hostname(url: str) -> str:
    hostname = urlparse(url).hostname
    return (hostname or "").lower()


def _get_domain_parts(hostname: str):
    """서브도메인 개수를 대략적으로 계산 (등록 도메인 기준 2 label 제외)."""
    if not hostname:
        return []
    labels = hostname.split(".")
    return labels


# ─────────────────────────────────────────────
# ① URL 정적 피처 (스캔 불필요)
# ─────────────────────────────────────────────

def extract_static_url_features(url: str) -> dict:
    feat = {}

    feat["url_len"] = len(url)
    feat["@"] = url.count("@")
    feat["?"] = url.count("?")
    feat["-"] = url.count("-")
    feat["="] = url.count("=")
    feat["."] = url.count(".")
    feat["#"] = url.count("#")
    feat["%"] = url.count("%")
    feat["+"] = url.count("+")
    feat["$"] = url.count("$")
    feat["!"] = url.count("!")
    feat["*"] = url.count("*")
    feat[","] = url.count(",")
    feat["//"] = url.count("//")
    feat["digits"] = sum(c.isdigit() for c in url)
    feat["letters"] = sum(c.isalpha() for c in url)

    hostname = _get_hostname(url)

    # abnormal_url: hostname이 url 문자열에 실제로 포함돼 있는지 확인
    try:
        parsed = urlparse(url)

        abnormal = 0

        # hostname이 없으면 비정상
        if not parsed.hostname:
            abnormal = 1

        # @가 있으면 사용자정보(userinfo)를 이용한 위장 가능성
        elif parsed.username or parsed.password:
            abnormal = 1

        feat["abnormal_url"] = abnormal

    except Exception:
        feat["abnormal_url"] = 1

    feat["https"] = 1 if urlparse(url).scheme == "https" else 0
    feat["Shortining_Service"] = 1 if SHORTENER_PATTERN.search(url) else 0

    # IP 주소 형태의 호스트인지 확인
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False
    feat["having_ip_address"] = 1 if is_ip else 0

    path = urlparse(url).path or ""
    feat["path_underscore_count"] = path.count("_")

    return feat


# ─────────────────────────────────────────────
# ② phish_* 휴리스틱 피처 (스캔 불필요, URL 문자열 기반)
# ─────────────────────────────────────────────

def extract_phish_heuristic_features(url: str) -> dict:
    feat = {}

    parsed = urlparse(url)
    hostname = _get_hostname(url)
    path = (parsed.path or "").lower()
    query = parsed.query or ""
    full_url_lower = url.lower()

    labels = _get_domain_parts(hostname)
    subdomain_count = max(len(labels) - 2, 0)
    tld = labels[-1] if labels else ""

    query_params = parse_qs(query)

    # ── 기본 휴리스틱 ──────────────────────────
    feat["phish_urgency_words"] = sum(
        1 for w in URGENCY_WORDS if w in full_url_lower
    )
    feat["phish_security_words"] = sum(
        1 for w in SECURITY_WORDS if w in full_url_lower
    )

    brand_hits = [b for b in BRAND_LIST if b in full_url_lower]
    feat["phish_brand_mentions"] = len(brand_hits)

    # 브랜드명이 도메인에 등장하지만, 실제 등록 도메인(SLD)이 그 브랜드명과
    # 정확히 일치하지 않으면(=서브도메인/하이픈 조합 등으로 흉내) hijack으로 간주
    sld = labels[-2] if len(labels) >= 2 else hostname
    hijack = 0
    for b in brand_hits:
        if b in hostname and b != sld:
            hijack = 1
            break
    feat["phish_brand_hijack"] = hijack

    feat["phish_multiple_subdomains"] = 1 if subdomain_count > 2 else 0
    feat["phish_long_path"] = 1 if len(path) > 75 else 0
    feat["phish_many_params"] = 1 if len(query_params) > 3 else 0
    feat["phish_suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0

    # ── adv_* (조금 더 세분화된 버전) ────────────
    feat["phish_adv_exact_brand_match"] = 1 if any(
        hostname == f"{b}.{tld}" for b in brand_hits
    ) else 0
    feat["phish_adv_brand_in_subdomain"] = 1 if any(
        b in ".".join(labels[:-2]) for b in brand_hits
    ) else 0
    feat["phish_adv_brand_in_path"] = 1 if any(b in path for b in brand_hits) else 0

    feat["phish_adv_hyphen_count"] = hostname.count("-")
    feat["phish_adv_number_count"] = sum(c.isdigit() for c in hostname)
    feat["phish_adv_suspicious_tld"] = feat["phish_suspicious_tld"]
    feat["phish_adv_long_domain"] = 1 if len(hostname) > 30 else 0
    feat["phish_adv_many_subdomains"] = 1 if subdomain_count > 3 else 0
    feat["phish_adv_encoded_chars"] = url.count("%")
    feat["phish_adv_path_keywords"] = sum(1 for k in PATH_KEYWORDS if k in path)
    feat["phish_adv_has_redirect"] = 1 if (
        "redirect" in query.lower() or full_url_lower.rfind("http") > 8
    ) else 0
    feat["phish_adv_many_params"] = len(query_params)

    # ── 경로/기타 ──────────────────────────────
    feat["path_has_hacked_terms"] = 1 if any(t in path for t in HACKED_TERMS) else 0
    feat["suspicious_extension"] = 1 if path.endswith(SUSPICIOUS_EXTENSIONS) else 0
    feat["is_gov_edu"] = 1 if tld in ("gov", "edu") else 0

    return feat


# ─────────────────────────────────────────────
# ③ web_* DOM/실시간 스캔 피처 (Playwright 필요)
# ─────────────────────────────────────────────

async def extract_web_scan_features(url: str, page) -> dict:
    feat = {}

    response = None
    is_live = 1

    try:
        response = await page.goto(url, timeout=15000, wait_until="domcontentloaded")
    except Exception:
        is_live = 0

    feat["web_is_live"] = is_live

    if response is None:
        # 접속 실패 시 안전한 기본값(모두 위험 쪽으로 기울지 않는 0)으로 채움
        feat.update({
            "web_http_status": 0,
            "web_ext_ratio": 0.0,
            "web_unique_domains": 0,
            "web_favicon": 0,
            "web_csp": 0,
            "web_xframe": 0,
            "web_hsts": 0,
            "web_xcontent": 0,
            "web_security_score": 0,
            "web_forms_count": 0,
            "web_password_fields": 0,
            "web_hidden_inputs": 0,
            "web_has_login": 0,
            "web_ssl_valid": 0,
        })
        return feat

    feat["web_http_status"] = response.status

    headers = {k.lower(): v for k, v in (response.headers or {}).items()}

    feat["web_csp"] = 1 if "content-security-policy" in headers else 0
    feat["web_xframe"] = 1 if "x-frame-options" in headers else 0
    feat["web_hsts"] = 1 if "strict-transport-security" in headers else 0
    feat["web_xcontent"] = 1 if "x-content-type-options" in headers else 0

    feat["web_security_score"] = (
        feat["web_csp"] + feat["web_xframe"] + feat["web_hsts"] + feat["web_xcontent"]
    )

    # SSL 유효성: https 접속이 오류 없이 응답을 받았는지로 판단
    feat["web_ssl_valid"] = 1 if urlparse(url).scheme == "https" and response.ok else 0

    # DOM 요소 분석
    try:
        favicon_count = await page.locator(
            "link[rel='icon'], link[rel='shortcut icon']"
        ).count()
        feat["web_favicon"] = 1 if favicon_count > 0 else 0

        feat["web_forms_count"] = await page.locator("form").count()
        feat["web_password_fields"] = await page.locator("input[type='password']").count()
        feat["web_hidden_inputs"] = await page.locator("input[type='hidden']").count()

        feat["web_has_login"] = 1 if (
            feat["web_password_fields"] > 0
        ) else 0

        # 외부 리소스 비율 / 참조 도메인 수 (script/img/link 태그의 src, href 기준)
        hostname = _get_hostname(url)
        srcs = await page.eval_on_selector_all(
            "script[src], img[src], link[href]",
            "els => els.map(e => e.src || e.href).filter(Boolean)"
        )

        total = len(srcs)
        ext_domains = set()
        ext_count = 0

        for s in srcs:
            try:
                d = urlparse(s).hostname or ""
            except Exception:
                d = ""
            if d and d != hostname:
                ext_count += 1
                ext_domains.add(d)

        feat["web_ext_ratio"] = round(ext_count / total, 4) if total > 0 else 0.0
        feat["web_unique_domains"] = len(ext_domains)

    except Exception:
        feat.setdefault("web_favicon", 0)
        feat.setdefault("web_forms_count", 0)
        feat.setdefault("web_password_fields", 0)
        feat.setdefault("web_hidden_inputs", 0)
        feat.setdefault("web_has_login", 0)
        feat.setdefault("web_ext_ratio", 0.0)
        feat.setdefault("web_unique_domains", 0)

    return feat


# ─────────────────────────────────────────────
# 통합 인터페이스
# ─────────────────────────────────────────────

async def extract_features(url: str, page) -> dict:
    """
    train.py의 SELECTED_FEATURES(59개)와 동일한 key를 갖는 dict를 반환한다.
    page: playwright의 browser context에서 만든 Page 객체 (호출부에서 생성/종료 관리)
    """
    feature = {}
    feature.update(extract_static_url_features(url))
    feature.update(extract_phish_heuristic_features(url))
    feature.update(await extract_web_scan_features(url, page))
    return feature


async def extract_features_standalone(url: str) -> dict:
    """단독 테스트/디버깅용: 자체적으로 브라우저를 띄우고 닫는다."""
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        try:
            feature = await extract_features(url, page)
        finally:
            await context.close()
            await browser.close()
        return feature


if __name__ == "__main__":
    import json
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "https://www.google.com"
    result = asyncio.run(extract_features_standalone(test_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))
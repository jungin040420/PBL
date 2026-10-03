"""
url_feature_extractor.py

URL + 실제 웹페이지 DOM/HTML 기반 피싱 탐지

동작 방식
1. 현재 URL을 실제 브라우저로 접속
2. 최종 URL의 도메인이 공식 도메인이면 AI 모델 없이 TRUSTED_SITE
3. 공식 도메인이 아닌데 도메인/제목/본문이 공식 브랜드를 사칭하면
   AI 모델 없이 PHISHING (BRAND_KEYWORDS 기준)
4. 그 외에는 AI 모델 실행
   - prediction == 1 -> LEGIT
   - prediction == 0 -> PHISHING

실행:
    python url_feature_extractor.py https://myfido2mfa.com

필수 설치:
    pip install playwright beautifulsoup4 joblib pandas numpy scikit-learn
    python -m playwright install chromium   # 최초 1회
"""

import argparse
import ipaddress
import json
import math
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

# ============================================================
# 설정
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model_artifacts"

TRUSTED_DOMAINS = {"myfido2mfa.com"}

# True면 login.myfido2mfa.com 같은 서브도메인도 신뢰
ALLOW_TRUSTED_SUBDOMAINS = True

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "confirm", "password", "credential", "wallet",
    "bank", "payment", "recover", "unlock", "authenticate",
    "authentication", "mfa", "2fa",
}

SOCIAL_DOMAINS = {
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "tiktok.com",
}

# 브랜드 사칭 탐지: 공식 도메인이 아닌데 이 이름을 쓰면 AI 판단 없이 PHISHING 처리
BRAND_KEYWORDS = {"myfido2mfa"}

# 도메인 라벨이 브랜드명과 이 비율 이상 비슷하면 오타 도메인(typosquatting)으로 판단 (0~1)
BRAND_SIMILARITY_THRESHOLD = 0.85

# 키릴/그리스 문자 등 라틴 문자와 비슷하게 생긴 문자 -> 라틴 문자
CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0501": "d",
    "\u03bf": "o", "\u03bd": "v", "\u0251": "a", "\u0131": "i",
}

# 숫자/기호로 글자를 흉내내는 경우 (0->o, 1/l->i ...)
LOOKALIKE_TABLE = str.maketrans(
    {"0": "o", "1": "i", "l": "i", "3": "e", "5": "s", "$": "s"}
)


# ============================================================
# 유틸
# ============================================================

def normalize_url(url: str) -> str:
    """scheme이 없으면 https:// 추가"""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    return url


def get_domain(url: str) -> str:
    """URL에서 hostname 추출 (소문자, 끝의 '.' 제거)"""
    try:
        return (urlparse(url).hostname or "").lower().strip().rstrip(".")
    except Exception:
        return ""


def is_trusted_domain(url: str) -> bool:
    """
    공식 도메인 여부 확인.
    myfido2mfa.com.evil.com, evil-myfido2mfa.com 은 False.
    """
    domain = get_domain(url)
    if not domain:
        return False
    if domain in TRUSTED_DOMAINS:
        return True
    if ALLOW_TRUSTED_SUBDOMAINS:
        return any(domain.endswith("." + t) for t in TRUSTED_DOMAINS)
    return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    return float(
        -sum((c / length) * math.log2(c / length) for c in Counter(value).values())
    )


def safe_ratio(a, b) -> float:
    return float(a / b) if b else 0.0


# ============================================================
# URL feature
# ============================================================

def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    domain = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    n = len(url)

    letters = sum(ch.isalpha() for ch in url)
    digits = sum(ch.isdigit() for ch in url)
    special_chars = sum(not ch.isalnum() and not ch.isspace() for ch in url)

    try:
        ipaddress.ip_address(domain)
        is_domain_ip = 1
    except ValueError:
        is_domain_ip = 0

    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    no_subdomain = max(0, len(domain.split(".")) - 2)

    no_obfuscated_char = sum(1 for ch in url if ch in {"%", "@", "\\", "^"})

    url_lower = url.lower()
    suspicious_count = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url_lower)

    return {
        # PhiUSIIL 계열 URL feature
        "URLLength": n,
        "DomainLength": len(domain),
        "IsDomainIP": is_domain_ip,
        "TLD": tld,
        "TLDLength": len(tld),
        "NoOfSubDomain": no_subdomain,
        "HasObfuscation": int(no_obfuscated_char > 0),
        "NoOfObfuscatedChar": no_obfuscated_char,
        "ObfuscationRatio": safe_ratio(no_obfuscated_char, n),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": safe_ratio(letters, n),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": safe_ratio(digits, n),
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": safe_ratio(special_chars, n),
        "IsHTTPS": int(parsed.scheme.lower() == "https"),
        # 추가 URL feature
        "PathLength": len(path),
        "QueryLength": len(query),
        "NoOfQueryComponents": len([x for x in query.split("&") if x]),
        "NoOfDots": url.count("."),
        "NoOfHyphens": url.count("-"),
        "NoOfUnderscores": url.count("_"),
        "NoOfAtSigns": url.count("@"),
        "NoOfColons": url.count(":"),
        "NoOfSlashes": url.count("/"),
        "NoOfPercentSigns": url.count("%"),
        "NoOfHash": url.count("#"),
        "URLShannonEntropy": shannon_entropy(url),
        "DomainShannonEntropy": shannon_entropy(domain),
        "HasSuspiciousKeyword": int(suspicious_count > 0),
        "SuspiciousKeywordCount": suspicious_count,
        "HasDoubleSlashInPath": int("//" in path),
        "HasUserInfo": int(parsed.username is not None),
        "HasPort": int(parsed.port is not None),
    }


# ============================================================
# DOM / HTML feature
# ============================================================

def extract_page_features(url: str, timeout_ms: int = 30000):
    """Playwright로 실제 페이지를 열어 DOM/HTML feature 추출"""
    print("[INFO] Playwright로 페이지 접속 중...")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 900})
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            try:
                page.wait_for_load_state("networkidle", timeout=7000)
            except PlaywrightTimeoutError:
                print("[WARNING] networkidle 대기 시간 초과. 현재 HTML로 계속 진행합니다.")

            final_url = page.url
            title = page.title() or ""
            html = page.content()
        finally:
            browser.close()

    soup = BeautifulSoup(html, "html.parser")
    final_domain = get_domain(final_url)

    # --- 링크 / reference ---
    external_ref = self_ref = empty_ref = 0

    for tag in soup.find_all(["a", "link", "script", "img", "iframe", "form"]):
        ref = tag.get("href") or tag.get("src") or tag.get("action")
        if ref is None:
            continue
        ref = ref.strip()

        if not ref or ref == "#" or ref.lower() in {"javascript:void(0)", "javascript:;"}:
            empty_ref += 1
        elif ref.startswith(("#", "/", "./", "../", "mailto:", "tel:", "javascript:")):
            self_ref += 1
        else:
            ref_domain = get_domain(ref)
            if not ref_domain or ref_domain == final_domain or ref_domain.endswith("." + final_domain):
                self_ref += 1
            else:
                external_ref += 1

    # --- HTML 구조 ---
    html_lines = html.splitlines()
    largest_line_length = max((len(line) for line in html_lines), default=0)

    no_of_css = sum(
        1
        for link in soup.find_all("link")
        if "stylesheet" in [str(x).lower() for x in link.get("rel", [])]
    )

    hidden_fields = soup.find_all(
        "input", attrs={"type": lambda v: v and v.lower() == "hidden"}
    )

    has_submit = any(
        (tag.get("type") or "").lower() == "submit"
        for tag in soup.find_all(["input", "button"])
    )

    has_description = int(
        soup.find("meta", attrs={"name": re.compile("^description$", re.IGNORECASE)})
        is not None
    )

    has_social_net = 0
    for a in soup.find_all("a", href=True):
        d = get_domain(a["href"])
        if any(d == s or d.endswith("." + s) for s in SOCIAL_DOMAINS):
            has_social_net = 1
            break

    visible_text = soup.get_text(" ", strip=True)
    has_copyright = int(
        re.search(r"(copyright|©|\(c\))", visible_text, re.IGNORECASE) is not None
    )

    # --- DomainTitleMatchScore (0~100 스케일) ---
    domain_words = {w.lower() for w in re.findall(r"[a-zA-Z]{2,}", final_domain)}
    title_words = set(re.findall(r"[a-zA-Z]{2,}", title.lower()))
    if domain_words:
        match_score = len(domain_words & title_words) / len(domain_words) * 100
    else:
        match_score = 0.0

    features = {
        "NoOfExternalRef": external_ref,
        "LineOfCode": len(html_lines),
        "NoOfSelfRef": self_ref,
        "NoOfImage": len(soup.find_all("img")),
        "NoOfJS": len(soup.find_all("script")),
        "HasSocialNet": has_social_net,
        "NoOfCSS": no_of_css,
        "HasCopyrightInfo": has_copyright,
        "HasDescription": has_description,
        "HasSubmitButton": int(has_submit),
        "LargestLineLength": largest_line_length,
        "DomainTitleMatchScore": match_score,
        "NoOfiFrame": len(soup.find_all("iframe")),
        "NoOfEmptyRef": empty_ref,
        "HasHiddenFields": int(len(hidden_fields) > 0),
    }

    return features, final_url, title, visible_text


# ============================================================
# 학습 preprocessing과 동일하게 적용
# ============================================================

def preprocess_features(features: dict):
    meta_path = MODEL_DIR / "training_meta.json"
    preprocessing_path = MODEL_DIR / "preprocessing_meta.json"
    scaler_path = MODEL_DIR / "scaler.joblib"
    encoder_path = MODEL_DIR / "categorical_encoders.joblib"

    if not meta_path.exists():
        raise FileNotFoundError(f"training_meta.json이 없습니다:\n{meta_path}")

    if not preprocessing_path.exists():
        raise FileNotFoundError(
            "\npreprocessing_meta.json이 없습니다.\n"
            "기존 모델은 학습 preprocessing 정보를 저장하지 않았습니다.\n\n"
            "먼저 수정된 url_train.py로 모델을 다시 학습하세요."
        )

    if not scaler_path.exists():
        raise FileNotFoundError(f"scaler.joblib이 없습니다:\n{scaler_path}")

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    with open(preprocessing_path, "r", encoding="utf-8") as f:
        preprocessing_meta = json.load(f)

    selected_features = meta["selected_features"]
    print("[INFO] 모델이 요구하는 feature 수:", len(selected_features))

    missing = [f for f in selected_features if f not in features]
    if missing:
        raise ValueError(
            "\n실시간 extractor가 training_meta.json의 feature를 생성하지 못했습니다:\n"
            + "\n".join(f"  - {f}" for f in missing)
        )

    X = pd.DataFrame([{f: features[f] for f in selected_features}])

    # --- categorical encoding ---
    if encoder_path.exists():
        encoders = joblib.load(encoder_path)
        for column, encoder in encoders.items():
            if column not in X.columns:
                continue
            value = str(X.at[0, column])
            if value not in {str(c) for c in encoder.classes_}:
                raise ValueError(
                    f"\n범주형 feature '{column}'에서 "
                    f"학습 시 없었던 값 '{value}'가 발견되었습니다."
                )
            X[column] = encoder.transform([value])

    # --- numeric: 결측 대체 ---
    medians = preprocessing_meta.get("numeric_medians", {})
    for column in meta.get("numeric_cols_used", []):
        if column not in X.columns:
            continue
        X[column] = pd.to_numeric(X[column], errors="coerce")
        X[column] = X[column].fillna(float(medians.get(column, 0.0)))

    # --- log1p ---
    for column in preprocessing_meta.get("log1p_columns", []):
        if column in X.columns:
            X[column] = np.log1p(np.maximum(X[column].astype(float), 0))

    # --- clipping ---
    for column, (lower, upper) in preprocessing_meta.get("clip_bounds", {}).items():
        if column in X.columns:
            X[column] = X[column].clip(float(lower), float(upper))

    # --- 정확한 feature 순서 + StandardScaler ---
    X = X[selected_features]
    scaler = joblib.load(scaler_path)
    X_scaled = pd.DataFrame(scaler.transform(X), columns=selected_features)

    return X_scaled, meta


# ============================================================
# AI prediction
# ============================================================

def run_ai_prediction(X, meta: dict) -> dict:
    """
    공식 도메인이 아닌 경우에만 실행.
    prediction == 1 -> LEGIT, prediction == 0 -> PHISHING
    """
    model_path = MODEL_DIR / "phishing_model.joblib"
    if not model_path.exists():
        raise FileNotFoundError(f"모델 파일이 없습니다:\n{model_path}")

    model = joblib.load(model_path)
    prediction = int(model.predict(X)[0])

    # 데이터셋 기준 0 = PHISHING 이므로 class 0의 확률을 사용
    phishing_probability = None
    if hasattr(model, "predict_proba"):
        classes = list(model.classes_)
        if 0 in classes:
            phishing_probability = float(model.predict_proba(X)[0][classes.index(0)])

    if prediction == 1:
        verdict, is_phishing = "LEGIT", False
        reason = "공식 도메인은 아니지만 AI 모델이 정상 사이트로 분류했습니다."
    else:
        verdict, is_phishing = "PHISHING", True
        reason = "공식 도메인이 아니며 AI 모델이 피싱 사이트로 분류했습니다."

    return {
        "prediction": prediction,
        "is_phishing": is_phishing,
        "verdict": verdict,
        "verdict_reason": reason,
        "phishing_probability": phishing_probability,
        "model": model.__class__.__name__,
        "test_f1": meta.get("test_f1"),
        "selected_features": meta.get("selected_features"),
    }


# ============================================================
# 브랜드 사칭 탐지 (규칙 기반)
# ============================================================

def _normalize_for_brand(text: str) -> str:
    """
    비교용 정규화: 소문자화, 악센트 제거, 유사 문자 치환,
    rn->m / vv->w, 0->o / 1->i 등. 브랜드명에도 똑같이 적용한다.
    """
    text = unicodedata.normalize("NFKD", text.lower())
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    text = "".join(CONFUSABLES.get(ch, ch) for ch in text)
    text = text.replace("rn", "m").replace("vv", "w")
    return text.translate(LOOKALIKE_TABLE)


def _decode_label(label: str) -> str:
    """punycode(xn--) 라벨을 유니코드로 복원"""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except Exception:
            return label
    return label


def check_brand_domain(url: str):
    """
    도메인이 공식 브랜드를 흉내 내는지 검사. 의심되면 사유(str), 아니면 None.
    공식 도메인 여부는 호출 전에 이미 걸러졌다고 가정한다.

    잡는 예:
      myfido2mfa-login.com      (브랜드명 포함)
      login.myfido2mfa.evil.com (서브도메인에 브랜드명)
      myfid02mfa.com            (0 <-> o)
      myfido2rnfa.com           (rn <-> m)
      myfido2mfaa.com           (오타)
      xn--...                   (키릴 문자 등 유사 문자)
    """
    host = get_domain(url)
    if not host:
        return None

    labels = [_decode_label(label) for label in host.split(".")]
    compact = _normalize_for_brand("".join(labels)).replace("-", "").replace("_", "")

    for brand in BRAND_KEYWORDS:
        target = _normalize_for_brand(brand)

        if target in compact:
            return f"공식 도메인이 아닌데 도메인에 브랜드명 '{brand}'이(가) 포함되어 있습니다: {host}"

        for label in labels:
            normalized = _normalize_for_brand(label).replace("-", "").replace("_", "")
            if not normalized:
                continue
            ratio = SequenceMatcher(None, normalized, target).ratio()
            if ratio >= BRAND_SIMILARITY_THRESHOLD:
                return (
                    f"도메인이 공식 브랜드 '{brand}'과(와) 매우 비슷합니다 "
                    f"(유사도 {ratio:.2f}): {host}"
                )

    return None


def check_brand_in_page(title: str, visible_text: str):
    """
    공식 도메인이 아닌 페이지의 제목/본문에 브랜드명이 있으면 사유(str), 없으면 None.
    공백/기호를 제거한 뒤 비교하므로 'MyFIDO2 MFA' 같은 표기도 잡힌다.
    """
    def squash(text: str) -> str:
        return re.sub(r"[^a-z0-9]", "", text.lower())

    title_squashed = squash(title)
    body_squashed = squash(visible_text)

    for brand in BRAND_KEYWORDS:
        target = squash(brand)
        if target in title_squashed:
            return f"공식 도메인이 아닌 페이지의 제목에 브랜드명 '{brand}'이(가) 있습니다."
        if target in body_squashed:
            return f"공식 도메인이 아닌 페이지 본문에 브랜드명 '{brand}'이(가) 있습니다."

    return None


# ============================================================
# 전체 파이프라인
# ============================================================

def predict_url(url: str) -> dict:
    url = normalize_url(url)

    print("\n" + "=" * 60)
    print("[INFO] 분석 URL:", url)

    print("\n[1/3] URL feature 추출...")
    features = extract_url_features(url)

    print("[2/3] 실제 웹페이지 분석...")
    page_features, final_url, title, visible_text = extract_page_features(url)
    features.update(page_features)

    print("[INFO] 최종 URL:", final_url)
    print("[INFO] 페이지 제목:", title)

    # 공식 도메인이면 AI 모델을 실행하지 않는다
    if is_trusted_domain(final_url):
        print("[INFO] 등록된 공식 도메인입니다. AI 모델 예측을 건너뜁니다.")
        return {
            "url": url,
            "final_url": final_url,
            "title": title,
            "official_domain": True,
            "prediction": 1,
            "label": "TRUSTED_SITE",
            "verdict": "TRUSTED_SITE",
            "is_phishing": False,
            "phishing_probability": 0.0,
            "model": "DOMAIN_ALLOWLIST",
            "test_f1": None,
            "selected_features": [],
            "verdict_reason": "등록된 공식 도메인과 일치합니다.",
        }

    # 공식 도메인이 아닌데 브랜드를 사칭하면 AI 판단 없이 바로 PHISHING
    impersonation_reason = (
        check_brand_domain(final_url)
        or check_brand_domain(url)
        or check_brand_in_page(title, visible_text)
    )

    if impersonation_reason:
        print("[INFO] 브랜드 사칭 규칙에 해당합니다. AI 모델 예측을 건너뜁니다.")
        print("[INFO] 사유:", impersonation_reason)
        return {
            "url": url,
            "final_url": final_url,
            "title": title,
            "official_domain": False,
            "prediction": 0,
            "label": "PHISHING",
            "verdict": "PHISHING",
            "is_phishing": True,
            "phishing_probability": 1.0,
            "model": "BRAND_IMPERSONATION_RULE",
            "test_f1": None,
            "selected_features": [],
            "verdict_reason": impersonation_reason,
        }

    print("[INFO] 공식 도메인이 아닙니다. AI 모델을 실행합니다.")

    print("[3/3] 학습과 동일한 preprocessing...")
    X, meta = preprocess_features(features)

    print("[INFO] AI 모델 예측...")
    ai = run_ai_prediction(X, meta)

    return {
        "url": url,
        "final_url": final_url,
        "title": title,
        "official_domain": False,
        "prediction": ai["prediction"],
        "label": ai["verdict"],
        "verdict": ai["verdict"],
        "is_phishing": ai["is_phishing"],
        "phishing_probability": ai["phishing_probability"],
        "model": ai["model"],
        "test_f1": ai["test_f1"],
        "selected_features": ai["selected_features"],
        "verdict_reason": ai["verdict_reason"],
    }


# ============================================================
# 결과 출력
# ============================================================

def print_result(result: dict):
    print("\n" + "=" * 60)
    print("                     분석 결과")
    print("=" * 60)
    print(f"URL             : {result['url']}")
    print(f"최종 URL        : {result['final_url']}")
    print(f"페이지 제목     : {result['title']}")
    print("공식 도메인     : " + ("YES" if result["official_domain"] else "NO"))

    if result["verdict"] == "TRUSTED_SITE":
        print("판정            : TRUSTED_SITE")
        print("설명            : 등록된 공식 사이트입니다.")
        print("AI 모델         : 실행하지 않음")
    else:
        print(f"모델            : {result['model']}")
        print(f"Test F1         : {result['test_f1']}")
        print(f"예측 label      : {result['prediction']}")
        print(f"판정            : {result['verdict']}")
        if result["phishing_probability"] is not None:
            print(f"피싱 확률       : {result['phishing_probability']:.8f}")
        print(f"설명            : {result['verdict_reason']}")

    print("=" * 60)


# ============================================================
# main
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="URL + DOM 기반 실시간 피싱 사이트 탐지")
    parser.add_argument(
        "url", nargs="?", default=None,
        help="분석할 URL. 생략하면 실행 후 입력받습니다.",
    )
    parser.add_argument("--json", action="store_true", help="JSON 형태로 결과 출력")
    args = parser.parse_args()

    url = args.url or input("\n분석할 URL을 입력하세요: ").strip()
    if not url:
        print("[ERROR] URL이 입력되지 않았습니다.")
        return 1

    try:
        result = predict_url(url)
        print_result(result)

        if args.json:
            print("\n[JSON RESULT]")
            print(json.dumps(result, ensure_ascii=False, indent=2))

        return 0

    except Exception as error:
        print("\n[ERROR]", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
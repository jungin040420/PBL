"""
url_predict.py

Random Forest 모델과
url_feature_extractor.py의 실시간 Feature 추출을 이용하여
URL을 정상 / 의심 / 악성으로 판정한다.

사용 예:
    python url_predict.py https://myfido2mfa.com/login.html
"""
import asyncio
import os
import sys

import joblib
import numpy as np
import pandas as pd

from playwright.async_api import async_playwright
from url_feature_extractor import extract_features


# ============================================================
# OUTPUT_DIR: 이 파일(url_predict.py) 위치 기준 절대경로로 고정
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

# ============================================================
# 모델 및 전처리 객체 로드
# ============================================================

def load_artifacts(output_dir=OUTPUT_DIR):

    model = joblib.load(
        os.path.join(output_dir, "rf_model.pkl")
    )

    scaler = joblib.load(
        os.path.join(output_dir, "scaler.pkl")
    )

    scale_cols = joblib.load(
        os.path.join(output_dir, "scale_cols.pkl")
    )

    selected_features = joblib.load(
        os.path.join(output_dir, "selected_features.pkl")
    )

    log_cols = joblib.load(
        os.path.join(output_dir, "log_cols.pkl")
    )

    clip_upper = joblib.load(
        os.path.join(output_dir, "clip_upper.pkl")
    )

    return {
        "model": model,
        "scaler": scaler,
        "scale_cols": scale_cols,
        "selected_features": selected_features,
        "log_cols": log_cols,
        "clip_upper": clip_upper,
    }


# ============================================================
# Feature → DataFrame
# ============================================================

def build_feature_row(raw_feature, artifacts):

    selected_features = artifacts["selected_features"]

    # 학습할 때 사용했던 Feature 순서 그대로 맞춤
    row = {
        feature: raw_feature.get(feature, 0)
        for feature in selected_features
    }

    X = pd.DataFrame(
        [row],
        columns=selected_features
    )

    # --------------------------------------------------------
    # 1. Log Transform
    # --------------------------------------------------------

    for col in artifacts["log_cols"]:

        if col in X.columns:

            X[col] = np.log1p(
                X[col].clip(lower=0)
            )

    # --------------------------------------------------------
    # 2. Clipping
    # --------------------------------------------------------

    for col, upper in artifacts["clip_upper"].items():

        if col in X.columns:

            X[col] = X[col].clip(
                upper=upper
            )

    # --------------------------------------------------------
    # 3. Scaling
    # --------------------------------------------------------

    scale_cols = artifacts["scale_cols"]

    X[scale_cols] = artifacts["scaler"].transform(
        X[scale_cols]
    )

    return X


# ============================================================
# URL 분석
# ============================================================

async def predict_url(url, artifacts):

    async with async_playwright() as p:

        browser = await p.chromium.launch(
            headless=True
        )

        context = await browser.new_context(
            ignore_https_errors=True
        )

        page = await context.new_page()

        try:

            print(f"[1] URL 접속 및 Feature 분석")
            print(f"    {url}")

            # ------------------------------------------------
            # URL + DOM Feature 추출
            # ------------------------------------------------

            raw_feature = await extract_features(
                url,
                page
            )

        finally:

            await context.close()
            await browser.close()

    # ========================================================
    # Feature → ML 입력 데이터
    # ========================================================

    X = build_feature_row(
        raw_feature,
        artifacts
    )

    # ========================================================
    # Random Forest 예측
    # ========================================================

    model = artifacts["model"]

    prob = float(
        model.predict_proba(X)[0, 1]
    )

    # ========================================================
    # 판정
    # ========================================================

    if prob >= 0.90:

        prediction = 1
        verdict = "Malicious"

    elif prob >= 0.70:

        prediction = 0
        verdict = "Suspicious"

    else:

        prediction = 0
        verdict = "Legitimate"

    return {

        "prediction": prediction,

        "prob": round(prob, 4),

        "verdict": verdict,

        "raw_feature": raw_feature

    }


# ============================================================
# 직접 실행용
# ============================================================

async def main():

    if len(sys.argv) < 2:

        print()
        print("사용법:")
        print(
            "python url_predict.py "
            "https://myfido2mfa.com/login.html"
        )
        print()

        return

    url = sys.argv[1]

    print("=" * 60)
    print("AI URL / DOM 피싱 탐지")
    print("=" * 60)

    # --------------------------------------------------------
    # 모델 로드
    # --------------------------------------------------------

    artifacts = load_artifacts()

    # --------------------------------------------------------
    # URL 분석
    # --------------------------------------------------------

    result = await predict_url(
        url,
        artifacts
    )

    # --------------------------------------------------------
    # 결과 출력
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("검사 URL :", url)
    print(
        "판정     :",
        result["verdict"]
    )
    print(
        "악성 확률:",
        result["prob"]
    )
    print("=" * 60)

    # --------------------------------------------------------
    # 인증 정책
    # --------------------------------------------------------

    if result["prediction"] == 1:

        print()
        print("🚨 피싱 사이트가 탐지되었습니다.")
        print("❌ 로그인을 차단합니다.")

    elif result["verdict"] == "Suspicious":

        print()
        print("⚠ 의심스러운 사이트입니다.")
        print("🔐 추가 인증을 요구할 수 있습니다.")

    else:

        print()
        print("✅ 정상 사이트로 판단되었습니다.")
        print("🔓 로그인을 허용할 수 있습니다.")


# ============================================================
# 실행
# ============================================================

if __name__ == "__main__":

    asyncio.run(main())
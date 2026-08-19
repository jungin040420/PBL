"""
predict.py
─────────────────────────────────────────────────────────
train.py 로 학습/저장된 모델(output/ 폴더)과
feature_extractor.py 의 실시간 피처 추출을 결합해서
임의의 URL 하나를 "정상 / 악성"으로 판별한다.

사용법:
    python predict.py https://example.com
"""

import asyncio
import sys
import os
from urllib import response
import joblib
import numpy as np
import pandas as pd
import requests

from playwright.async_api import async_playwright
from url_feature_extractor import extract_features

OUTPUT_DIR = "output"

# 로그인 서버 주소
LOGIN_API = "http://localhost:8000/login"


####################################################
# 모델 로드
####################################################

def load_artifacts(output_dir=OUTPUT_DIR):

    model = joblib.load(os.path.join(output_dir, "rf_model.pkl"))
    scaler = joblib.load(os.path.join(output_dir, "scaler.pkl"))
    scale_cols = joblib.load(os.path.join(output_dir, "scale_cols.pkl"))
    selected_features = joblib.load(os.path.join(output_dir, "selected_features.pkl"))
    log_cols = joblib.load(os.path.join(output_dir, "log_cols.pkl"))
    clip_upper = joblib.load(os.path.join(output_dir, "clip_upper.pkl"))

    return {
        "model": model,
        "scaler": scaler,
        "scale_cols": scale_cols,
        "selected_features": selected_features,
        "log_cols": log_cols,
        "clip_upper": clip_upper,
    }


####################################################
# Feature -> DataFrame
####################################################

def build_feature_row(raw_feature, artifacts):

    row = {
        f: raw_feature.get(f, 0)
        for f in artifacts["selected_features"]
    }

    X = pd.DataFrame([row])

    # log1p
    for col in artifacts["log_cols"]:
        if col in X.columns:
            X[col] = np.log1p(X[col].clip(lower=0))

    # clipping
    for col, upper in artifacts["clip_upper"].items():
        if col in X.columns:
            X[col] = X[col].clip(upper=upper)

    # scaling
    X[artifacts["scale_cols"]] = artifacts["scaler"].transform(
        X[artifacts["scale_cols"]]
    )

    return X


####################################################
# 로그인 서버 호출
####################################################

def login_server(user_id, password):

    try:

        response = requests.post(
            LOGIN_API,
            json={
                "id": user_id,
                "password": password
            }
        )

        return response.json()

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }


####################################################
# 예측
####################################################

async def predict_url(url, artifacts):

    async with async_playwright() as p:

        browser = await p.chromium.launch(headless=True)

        context = await browser.new_context(
            ignore_https_errors=True
        )

        page = await context.new_page()

        try:
            raw_feature = await extract_features(url, page)

        finally:
            await context.close()
            await browser.close()

    X = build_feature_row(raw_feature, artifacts)

    model = artifacts["model"]

    # 악성 확률
    prob = float(model.predict_proba(X)[0, 1])

    ####################################################
    # 3단계 판정
    ####################################################

    if prob >= 0.90:

        prediction = 1          # 로그인 차단
        verdict = "🚨 Malicious"

    elif prob >= 0.70:

        prediction = 0          # 로그인은 차단하지 않음
        verdict = "⚠ Suspicious"

    else:

        prediction = 0
        verdict = "✅ Legitimate"

    return {

        "prediction": prediction,

        "prob": round(prob, 4),

        "verdict": verdict,

        "raw_feature": raw_feature
    }



####################################################
# MAIN
####################################################

async def main():

    if len(sys.argv) < 2:

        print("사용법")
        print("python predict.py https://사이트주소")

        return

    url = sys.argv[1]

    artifacts = load_artifacts()

    result = await predict_url(url, artifacts)

    print("=" * 60)
    print("URL :", url)
    print("판정 :", result["verdict"])
    print("악성 확률 :", round(result["prob"], 4))
    print("=" * 60)

    ##############################################
    # 피싱이면 로그인 차단
    ##############################################

    if result["verdict"] == "🚨 Malicious":

        print("\n🚨 피싱 사이트입니다.")
        print("❌ 로그인을 차단합니다.")
        return

    elif result["verdict"] == "⚠ Suspicious":

        print("\n⚠ 의심 사이트입니다.")
        print("추가 인증(FIDO2 재인증)을 수행합니다.")

    else:

        print("\n✅ 정상 사이트입니다.")
        print("로그인을 진행합니다.")

    response = login_server(
    "testuser",
    "1234"
)

print(response)


if __name__ == "__main__":

    asyncio.run(main())
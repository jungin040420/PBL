from fastapi import FastAPI
from pydantic import BaseModel

import asyncio
import os
import joblib
import numpy as np
import pandas as pd

from playwright.async_api import async_playwright

from url_feature_extractor import extract_features

app = FastAPI(
    title="AI URL Checker"
)

####################################################
# 모델 로드
####################################################

OUTPUT_DIR = "output"

model = joblib.load(
    os.path.join(OUTPUT_DIR, "rf_model.pkl")
)

scaler = joblib.load(
    os.path.join(OUTPUT_DIR, "scaler.pkl")
)

scale_cols = joblib.load(
    os.path.join(OUTPUT_DIR, "scale_cols.pkl")
)

selected_features = joblib.load(
    os.path.join(OUTPUT_DIR, "selected_features.pkl")
)

log_cols = joblib.load(
    os.path.join(OUTPUT_DIR, "log_cols.pkl")
)

clip_upper = joblib.load(
    os.path.join(OUTPUT_DIR, "clip_upper.pkl")
)

####################################################
# 요청 모델
####################################################

class CheckRequest(BaseModel):
    url: str

####################################################
# Feature -> DataFrame
####################################################

def build_feature_row(raw_feature):

    row = {
        feature: raw_feature.get(feature, 0)
        for feature in selected_features
    }

    X = pd.DataFrame([row])

    # log1p
    for col in log_cols:
        if col in X.columns:
            X[col] = np.log1p(
                X[col].clip(lower=0)
            )

    # clipping
    for col, upper in clip_upper.items():
        if col in X.columns:
            X[col] = X[col].clip(
                upper=upper
            )

    # scaling
    X[scale_cols] = scaler.transform(
        X[scale_cols]
    )

    return X

####################################################
# URL 검사
####################################################

async def analyze_url(url):

    async with async_playwright() as p:

        browser = await p.chromium.launch(
            headless=True
        )

        context = await browser.new_context(
            ignore_https_errors=True
        )

        page = await context.new_page()

        try:

            ################################################
            # Feature 추출
            ################################################

            raw_feature = await extract_features(
                url,
                page
            )

        finally:

            await context.close()
            await browser.close()

    ####################################################
    # DataFrame 생성
    ####################################################

    X = build_feature_row(raw_feature)

    ####################################################
    # 머신러닝 예측
    ####################################################

    probability = model.predict_proba(X)[0][1]

    prediction = int(probability >= 0.5)

    return {

        "prediction": prediction,

        "probability": float(probability)

    }

####################################################
# API
####################################################

@app.get("/")
def root():

    return {

        "message": "AI URL Checker"

    }

####################################################
# login.html에서 호출
####################################################

@app.post("/check")
async def check(req: CheckRequest):

    result = await analyze_url(req.url)

    return {

        "blocked": result["prediction"] == 1,

        "probability": round(
            result["probability"],
            4
        )

    }
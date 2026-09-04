from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
# CORS 설정
####################################################

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
# 판정 임계값
####################################################

MALICIOUS_THRESHOLD = 0.90
SUSPICIOUS_THRESHOLD = 0.70

####################################################
# 요청 모델
####################################################

class CheckRequest(BaseModel):
    url: str

class LoginRequest(BaseModel):
    id: str
    password: str

####################################################
# Feature -> DataFrame
####################################################

def build_feature_row(raw_feature):

    row = {
        feature: raw_feature.get(feature, 0)
        for feature in selected_features
    }

    X = pd.DataFrame([row])

    for col in log_cols:
        if col in X.columns:
            X[col] = np.log1p(
                X[col].clip(lower=0)
            )

    for col, upper in clip_upper.items():
        if col in X.columns:
            X[col] = X[col].clip(
                upper=upper
            )

    X[scale_cols] = scaler.transform(
        X[scale_cols]
    )

    return X

####################################################
# 판정 로직
####################################################

def classify(probability: float):

    if probability >= MALICIOUS_THRESHOLD:
        return {
            "blocked": True,
            "verdict": "Malicious",
        }

    elif probability >= SUSPICIOUS_THRESHOLD:
        return {
            "blocked": False,
            "verdict": "Suspicious",
        }

    else:
        return {
            "blocked": False,
            "verdict": "Legitimate",
        }

####################################################
# URL 검사 (디버그용 raw_feature 반환 포함)
####################################################

async def analyze_url(url):

    async with async_playwright() as p:

        browser = None
        context = None

        try:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-gpu",
                ]
            )

            context = await browser.new_context(
                ignore_https_errors=True
            )

            page = await context.new_page()

            raw_feature = await extract_features(
                url,
                page
            )

        finally:
            if context is not None:
                try:
                    await context.close()
                except Exception:
                    pass

            if browser is not None:
                try:
                    await browser.close()
                except Exception:
                    pass

    X = build_feature_row(raw_feature)

    probability = float(
        model.predict_proba(X)[0][1]
    )

    return probability, raw_feature


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

    probability, raw_feature = await analyze_url(req.url)

    result = classify(probability)

    safe_feature = {
        k: (v.item() if hasattr(v, "item") else v)
        for k, v in raw_feature.items()
    }

    return {
        "url": req.url,
        "blocked": result["blocked"],
        "verdict": result["verdict"],
        "prediction": int(result["blocked"]),
        "probability": round(probability, 4),
        "debug_features": safe_feature,
    }

####################################################
# 로그인 처리 (데모용)
####################################################

@app.post("/login")
async def login(req: LoginRequest):

    if req.id == "testuser" and req.password == "1234":
        return {
            "status": "success",
            "message": "로그인 성공",
        }

    return {
        "status": "fail",
        "message": "아이디 또는 비밀번호가 올바르지 않습니다.",
    }
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
# CORS 설정
#   - 프론트엔드(index.html)가 API와 다른 포트/도메인에서
#     서빙되는 경우 브라우저가 요청을 막는 것을 방지.
#   - 운영 환경에서는 allow_origins를 실제 프론트 주소로
#     제한하는 것을 권장 (예: ["http://13.193.119.242:3000"])
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
# 판정 임계값 (predict.py와 동일한 기준으로 통일)
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
# 판정 로직 (3단계: Malicious / Suspicious / Legitimate)
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
# URL 검사
####################################################

async def analyze_url(url):

    async with async_playwright() as p:

        browser = None
        context = None

        try:
            browser = await p.chromium.launch(
                headless=True
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

    return probability
    ####################################################
    # DataFrame 생성
    ####################################################

    X = build_feature_row(raw_feature)

    ####################################################
    # 머신러닝 예측
    ####################################################

    probability = float(model.predict_proba(X)[0][1])

    return probability

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

    probability = await analyze_url(req.url)

    result = classify(probability)

    return {

        "url": req.url,

        "blocked": result["blocked"],

        "verdict": result["verdict"],

        "prediction": int(result["blocked"]),

        "probability": round(probability, 4),

    }

####################################################
# 로그인 처리
#   - predict.py / login_server()가 호출하는 LOGIN_API가
#     이 엔드포인트를 가리키도록 통일 (기존에는 /login이
#     존재하지 않아 항상 404가 발생했음)
#   - 데모 목적의 최소 구현이며, 실제 서비스에서는 반드시
#     DB 조회 + 비밀번호 해시 검증 로직으로 교체할 것
####################################################

@app.post("/login")
async def login(req: LoginRequest):

    # TODO: 실제 사용자 인증 로직으로 교체 (DB 조회, 해시 비교 등)
    if req.id == "testuser" and req.password == "1234":
        return {
            "status": "success",
            "message": "로그인 성공",
        }

    return {
        "status": "fail",
        "message": "아이디 또는 비밀번호가 올바르지 않습니다.",
    }
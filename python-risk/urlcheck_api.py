from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from url_predict import load_artifacts, predict_url


app = FastAPI(
    title="AI URL Checker",
    description="URL + DOM 기반 피싱 사이트 탐지 API",
    version="1.0.0"
)


# ============================================================
# 모델 로드
# ============================================================

try:

    artifacts = load_artifacts()

    print("✅ AI 모델 로드 완료")

except Exception as e:

    artifacts = None

    print("❌ AI 모델 로드 실패")
    print(e)


# ============================================================
# 요청 데이터
# ============================================================

class CheckRequest(BaseModel):

    url: str


# ============================================================
# 기본 API
# ============================================================

@app.get("/")
def root():

    return {
        "status": "running",
        "message": "AI URL Checker",
        "api": "/check"
    }


# ============================================================
# URL 검사 API
# ============================================================

@app.post("/check")
async def check(req: CheckRequest):

    # --------------------------------------------------------
    # 모델 확인
    # --------------------------------------------------------

    if artifacts is None:

        raise HTTPException(
            status_code=500,
            detail="AI 모델이 로드되지 않았습니다."
        )


    # --------------------------------------------------------
    # URL 검사
    # --------------------------------------------------------

    try:

        result = await predict_url(
            req.url,
            artifacts
        )

    except Exception as e:

        print("❌ URL 검사 실패:", e)

        raise HTTPException(
            status_code=500,
            detail=f"URL 검사 실패: {str(e)}"
        )


    # --------------------------------------------------------
    # 결과
    # --------------------------------------------------------

    return {

        "url": req.url,

        "blocked": result["prediction"] == 1,

        "prediction": result["prediction"],

        "probability": result["prob"],

        "verdict": result["verdict"]

    }
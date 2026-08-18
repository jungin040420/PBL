import json
import os
from datetime import datetime, timezone
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


# ============================================================
# Model 경로
# ============================================================

BASE_DIR = os.path.dirname(__file__)

MODEL_DIR = os.path.abspath(
    os.path.join(
        BASE_DIR,
        "..",
        "model",
    )
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "isolation_forest.joblib",
)

MODEL_META_PATH = os.path.join(
    MODEL_DIR,
    "isolation_forest_meta.json",
)


# ============================================================
# Isolation Forest Feature 순서
#
# 학습 / 추론에서 반드시 동일한 순서를 사용한다.
#
# Feature Freeze 기준:
# 1. loginFrequency
# 2. failedLoginCount
# 3. ipChanged
# 4. userAgentChanged
# 5. isNewDevice
# 6. regionChanged
# 7. challengeResponseTime
# 8. loginHour
# 9. dayOfWeek
# 10. hasPreviousContext
# ============================================================

FEATURE_ORDER = [
    "loginFrequency",
    "failedLoginCount",
    "ipChanged",
    "userAgentChanged",
    "isNewDevice",
    "regionChanged",
    "challengeResponseTime",
    "loginHour",
    "dayOfWeek",
    "hasPreviousContext",
]


# ============================================================
# Feature Vector 생성
# ============================================================

def build_feature_vector(
    features: dict,
) -> np.ndarray:

    row = [
        float(
            features.get(
                key,
                0,
            )
        )
        for key in FEATURE_ORDER
    ]

    feature_vector = np.array(
        [row],
        dtype=float,
    )

    if feature_vector.shape[1] != len(
        FEATURE_ORDER
    ):
        raise ValueError(
            "추론 Feature 개수가 "
            "FEATURE_ORDER와 일치하지 않습니다."
        )

    return feature_vector


# ============================================================
# Isolation Forest 학습
# ============================================================

def train(
    feature_matrix: np.ndarray,
    contamination: float = 0.05,
) -> IsolationForest:

    feature_matrix = np.asarray(
        feature_matrix,
        dtype=float,
    )

    if feature_matrix.ndim != 2:

        raise ValueError(
            "학습 데이터는 2차원 Matrix여야 합니다."
        )

    if feature_matrix.shape[1] != len(
        FEATURE_ORDER
    ):

        raise ValueError(
            "Feature 개수가 FEATURE_ORDER와 "
            "일치하지 않습니다."
        )

    if feature_matrix.shape[0] == 0:

        raise ValueError(
            "학습 데이터가 없습니다."
        )

    if not 0 < contamination <= 0.5:

        raise ValueError(
            "contamination 값은 "
            "0보다 크고 0.5 이하여야 합니다."
        )

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        feature_matrix
    )

    return model


# ============================================================
# Model 저장
# ============================================================

def save(
    model: IsolationForest,
) -> None:

    os.makedirs(
        MODEL_DIR,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    print(
        "Isolation Forest 모델 저장 완료:",
        MODEL_PATH,
    )


# ============================================================
# Model 로드
# ============================================================

def load() -> Optional[IsolationForest]:

    if not os.path.exists(
        MODEL_PATH
    ):

        print(
            "Isolation Forest 모델 파일 없음:",
            MODEL_PATH,
        )

        return None

    try:

        model = joblib.load(
            MODEL_PATH
        )

        return model

    except Exception as error:

        print(
            "Isolation Forest 모델 로드 실패:",
            error,
        )

        return None


# ============================================================
# Metadata 저장
# ============================================================

def save_metadata(
    model_type: str,
    training_rows: int,
    contamination: float,
) -> None:

    os.makedirs(
        MODEL_DIR,
        exist_ok=True,
    )

    metadata = {

        "model_type":
            model_type,

        "training_rows":
            int(
                training_rows
            ),

        "contamination":
            float(
                contamination
            ),

        "feature_count":
            len(
                FEATURE_ORDER
            ),

        "feature_order":
            FEATURE_ORDER,

        "anomaly_score_type":
            "raw_score_samples",

        "anomaly_score_description":
            (
                "Isolation Forest score_samples() "
                "raw output. No 0-100 normalization."
            ),

        "trained_at":
            datetime.now(
                timezone.utc
            ).isoformat(),
    }

    with open(
        MODEL_META_PATH,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            ensure_ascii=False,
            indent=2,
        )

    print(
        "Isolation Forest metadata 저장 완료:",
        MODEL_META_PATH,
    )


# ============================================================
# Metadata 로드
# ============================================================

def load_metadata() -> Optional[dict]:

    if not os.path.exists(
        MODEL_META_PATH
    ):

        return None

    try:

        with open(
            MODEL_META_PATH,
            "r",
            encoding="utf-8",
        ) as file:

            return json.load(
                file
            )

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:

        print(
            "Isolation Forest metadata 로드 실패:",
            error,
        )

        return None


# ============================================================
# Metadata 검증
# ============================================================

def validate_metadata(
    metadata: Optional[dict],
) -> None:

    if not metadata:

        return

    metadata_feature_order = (
        metadata.get(
            "feature_order"
        )
    )

    if (
        metadata_feature_order is not None
        and
        metadata_feature_order != FEATURE_ORDER
    ):

        raise ValueError(
            "저장된 모델 Feature 순서와 "
            "현재 FEATURE_ORDER가 일치하지 않습니다. "
            "모델을 다시 학습해야 합니다."
        )

    metadata_feature_count = (
        metadata.get(
            "feature_count"
        )
    )

    if (
        metadata_feature_count is not None
        and
        int(
            metadata_feature_count
        ) != len(
            FEATURE_ORDER
        )
    ):

        raise ValueError(
            "저장된 모델 Feature 개수와 "
            "현재 FEATURE_ORDER가 일치하지 않습니다. "
            "모델을 다시 학습해야 합니다."
        )


# ============================================================
# Isolation Forest 추론
#
# 중요:
#
# anomaly_score는 sklearn IsolationForest의
# score_samples() 원시 반환값을 그대로 사용한다.
#
# 0~100 정규화를 수행하지 않는다.
#
# score_samples() 값은 고정된 -1~1 범위를 보장하지 않으므로
# DB / 문서에서도 단순 FLOAT 원시 모델 점수로 관리한다.
#
# model.predict():
#    1  = 정상
#   -1  = 이상치
# ============================================================

def predict_anomaly_score(
    features: dict,
) -> Optional[dict]:

    model = load()

    if model is None:

        print(
            "Isolation Forest 모델 없음"
        )

        return None

    metadata = load_metadata()

    validate_metadata(
        metadata
    )

    feature_vector = build_feature_vector(
        features
    )

    prediction = model.predict(
        feature_vector
    )[0]

    # --------------------------------------------------------
    # 원시 Isolation Forest 점수
    #
    # 절대 0~100으로 변환하지 않는다.
    # DB ml_predictions.anomaly_score에도 이 값을 그대로 사용한다.
    # --------------------------------------------------------

    raw_anomaly_score = model.score_samples(
        feature_vector
    )[0]

    result = {

        "anomaly_score":
            float(
                raw_anomaly_score
            ),

        "is_anomaly":
            bool(
                int(
                    prediction
                ) == -1
            ),
    }

    return result
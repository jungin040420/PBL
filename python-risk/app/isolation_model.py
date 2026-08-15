import json
import os
from datetime import datetime, timezone
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


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


def build_feature_vector(
    features: dict,
) -> np.ndarray:

    row = [
        float(features.get(key, 0))
        for key in FEATURE_ORDER
    ]

    return np.array(
        [row],
        dtype=float,
    )


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
            "Feature 개수가 FEATURE_ORDER와 일치하지 않습니다."
        )

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(feature_matrix)

    return model


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


def load() -> Optional[IsolationForest]:

    if not os.path.exists(MODEL_PATH):
        return None

    try:
        return joblib.load(
            MODEL_PATH
        )

    except Exception as error:
        print(
            "Isolation Forest 모델 로드 실패:",
            error,
        )
        return None


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
        "model_type": model_type,
        "training_rows": int(training_rows),
        "contamination": float(contamination),
        "feature_count": len(FEATURE_ORDER),
        "feature_order": FEATURE_ORDER,
        "trained_at": datetime.now(
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
            return json.load(file)

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:

        print(
            "Isolation Forest metadata 로드 실패:",
            error,
        )

        return None


def validate_metadata(
    metadata: Optional[dict],
) -> None:

    if not metadata:
        return

    if (
        metadata.get("feature_order") is not None
        and
        metadata.get("feature_order")
        != FEATURE_ORDER
    ):
        raise ValueError(
            "저장된 모델 Feature 순서와 "
            "현재 FEATURE_ORDER가 일치하지 않습니다. "
            "모델을 다시 학습해야 합니다."
        )

    if (
        metadata.get("feature_count") is not None
        and
        int(metadata.get("feature_count"))
        != len(FEATURE_ORDER)
    ):
        raise ValueError(
            "저장된 모델 Feature 개수와 "
            "현재 FEATURE_ORDER가 일치하지 않습니다. "
            "모델을 다시 학습해야 합니다."
        )


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

    anomaly_score = model.score_samples(
        feature_vector
    )[0]

    return {
        "anomaly_score":
            float(anomaly_score),

        "is_anomaly":
            bool(
                int(prediction) == -1
            ),
    }
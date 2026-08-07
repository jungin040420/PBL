import json
import os
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


BASE_DIR = os.path.dirname(__file__)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "..",
    "model",
    "isolation_forest.joblib",
)

MODEL_META_PATH = os.path.join(
    BASE_DIR,
    "..",
    "model",
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
]


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

    return np.array(
        row,
        dtype=float,
    ).reshape(1, -1)


def train(
    feature_matrix: np.ndarray,
    contamination: float = 0.05,
) -> IsolationForest:
    if feature_matrix.ndim != 2:
        raise ValueError(
            "feature_matrix는 2차원 배열이어야 합니다."
        )

    if feature_matrix.shape[1] != len(
        FEATURE_ORDER
    ):
        raise ValueError(
            "Feature 개수가 FEATURE_ORDER와 일치하지 않습니다."
        )

    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        feature_matrix
    )

    return model


def save(
    model: IsolationForest,
    path: str = MODEL_PATH,
) -> None:
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    joblib.dump(
        model,
        path,
    )


def save_metadata(
    model_type: str,
    training_rows: int,
    contamination: float,
    path: str = MODEL_META_PATH,
) -> None:
    """
    model_type:
        REAL
        SYNTHETIC
    """

    model_type = model_type.upper()

    if model_type not in {
        "REAL",
        "SYNTHETIC",
    }:
        raise ValueError(
            "model_type은 REAL 또는 SYNTHETIC이어야 합니다."
        )

    metadata = {
        "model_type": model_type,
        "training_rows": int(
            training_rows
        ),
        "contamination": float(
            contamination
        ),
        "feature_order": FEATURE_ORDER,
    }

    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metadata,
            file,
            ensure_ascii=False,
            indent=2,
        )


def load(
    path: str = MODEL_PATH,
) -> Optional[IsolationForest]:
    if not os.path.exists(path):
        return None

    try:
        return joblib.load(
            path
        )

    except Exception as error:
        print(
            "Isolation Forest 모델 로드 실패:",
            error,
        )

        return None


def load_metadata(
    path: str = MODEL_META_PATH,
) -> Optional[dict]:
    if not os.path.exists(path):
        return None

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as file:
            metadata = json.load(
                file
            )

        return metadata

    except (
        OSError,
        json.JSONDecodeError,
    ) as error:
        print(
            "Isolation Forest 메타데이터 로드 실패:",
            error,
        )

        return None


def is_real_model() -> bool:
    metadata = load_metadata()

    if not metadata:
        return False

    return (
        metadata.get(
            "model_type"
        )
        == "REAL"
    )


def predict_anomaly_score(
    features: dict,
    model: Optional[
        IsolationForest
    ] = None,
) -> Optional[dict]:
    """
    REAL 모델인 경우에만 실제 추론에 사용한다.

    모델 파일이 없거나,
    metadata가 없거나,
    SYNTHETIC 모델이면 None 반환.
    """

    metadata = load_metadata()

    if not metadata:
        return None

    if (
        metadata.get(
            "model_type"
        )
        != "REAL"
    ):
        return None

    if (
        metadata.get(
            "feature_order"
        )
        != FEATURE_ORDER
    ):
        print(
            "Isolation Forest Feature 순서 불일치"
        )
        return None

    if model is None:
        model = load()

    if model is None:
        return None

    vector = build_feature_vector(
        features
    )

    raw_score = float(
        model.score_samples(
            vector
        )[0]
    )

    prediction = int(
        model.predict(
            vector
        )[0]
    )

    return {
        "anomaly_score":
            raw_score,

        "is_anomaly":
            prediction == -1,

        "model_type":
            "REAL",
    }
"""
Isolation Forest 기반 이상 탐지 모델 틀 (skeleton).

detector.py의 규칙 기반 점수(detect_suspicious)는 "이 조건이면 위험하다"를
사람이 직접 정한 규칙이고, 이 파일은 "과거 로그와 패턴이 다른 요청"을 통계적으로
찾아내는 비지도 학습(Isolation Forest) 쪽을 담당합니다. 서로 대체 관계가 아니라
detect_suspicious()의 규칙 기반 트리거에 하나 더 얹는 방식으로 씁니다.

지금은 실제 학습 데이터(F-28에서 버전 관리될 로그 데이터셋)가 아직 없어서
모델 파일이 없는 상태입니다. load()가 None을 반환하면 predict_anomaly_score()도
None을 반환하도록 만들어서, 모델이 없어도 서버가 죽지 않고 규칙 기반 점수만으로
동작하게 했습니다. F-28 데이터가 준비되면 train() -> save()로 모델을 만들고,
그 이후부터는 자동으로 predict_anomaly_score()가 활성화됩니다.
"""
import os
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "model", "isolation_forest.joblib")

# 학습/추론에 쓰는 피처 순서. feature.py의 extract_features() 출력 키와 맞춰야 합니다.
FEATURE_ORDER = [
    "login_failures",
    "is_new_device",
    "is_phishing_url",
    "hour",
    "is_night",
]


def build_feature_vector(features: dict) -> np.ndarray:
    """feature.py의 extract_features() 결과를 모델 입력 벡터(숫자 배열)로 변환합니다."""
    row = [float(features.get(key, 0)) for key in FEATURE_ORDER]
    return np.array(row).reshape(1, -1)


def train(feature_matrix: np.ndarray, contamination: float = 0.05) -> IsolationForest:
    """
    feature_matrix: shape (n_samples, len(FEATURE_ORDER)) — 과거 로그 데이터.
    contamination: 전체 데이터 중 이상치로 볼 것으로 추정하는 비율 (기본 5%).

    F-28 데이터셋이 준비되면 이 함수로 학습 -> save()로 모델 파일 저장.
    (지금은 틀만 잡아둔 상태이고, ci.yml의 F-29 학습 트리거가 이 함수를 호출하게 됩니다.)
    """
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(feature_matrix)
    return model


def save(model: IsolationForest, path: str = MODEL_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)


def load(path: str = MODEL_PATH) -> Optional[IsolationForest]:
    """학습된 모델 파일이 있으면 불러오고, 없으면 None을 반환합니다 (에러를 던지지 않음)."""
    if not os.path.exists(path):
        return None
    return joblib.load(path)


def predict_anomaly_score(features: dict, model: Optional[IsolationForest] = None) -> Optional[dict]:
    """
    반환값: {"anomaly_score": float, "is_anomaly": bool}
    모델이 없으면 None을 반환합니다 — 호출부(detector.py)는 None이면 이 트리거를
    건너뛰고 규칙 기반 점수만 쓰도록 처리해야 합니다.

    score_samples(): 값이 작을수록(음수로 갈수록) 이상치에 가깝습니다.
    predict(): 1(정상) / -1(이상치)을 반환합니다.
    """
    if model is None:
        model = load()
    if model is None:
        return None

    vector = build_feature_vector(features)
    raw_score = model.score_samples(vector)[0]
    is_anomaly = model.predict(vector)[0] == -1

    return {
        "anomaly_score": float(raw_score),
        "is_anomaly": bool(is_anomaly),
    }

"""
url_train.py
------------
PhiUSIIL 기반 피싱 URL 탐지 모델 학습 파이프라인 (처음부터 재구성)

흐름:
  1) CSV 로드 및 스키마 점검 (실제 컬럼이 UCI 원본과 어떻게 다른지 자동 확인)
  2) 라벨/피처 자동 분리, 결측치 처리
  3) 범주형(TLD 등) 인코딩, 왜도 높은 수치형에 log1p, 이상치 클리핑
  4) 1차 RandomForest로 "전체 피처" 중요도 분석 -> 상위 피처 자동 선정
  5) 선정된 피처로 Logistic Regression / Random Forest / HistGradientBoosting
     3개 모델을 StratifiedKFold 교차검증 + 홀드아웃 테스트로 비교
  6) 가장 좋은 모델(F1 기준)을 최종 선택, 전처리기와 함께 joblib으로 저장

사용법:
  python url_train.py --csv PhiUSIIL_Phishing_URL_Dataset.csv --label-col label
  (label 컬럼 이름이 다르면 --label-col 로 지정. 모르면 자동 추정 시도)
"""

import argparse
import json
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")

RANDOM_STATE = 42
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "model_artifacts"
OUTPUT_DIR.mkdir(exist_ok=True)

# URL 원문/식별자 성격이라 피처로 쓰면 안 되는 컬럼 후보 (있으면 자동 제거)
ID_LIKE_COLUMNS = {
    "FILENAME", "URL", "Domain", "Title", "url", "domain", "title", "index", "Index", "id", "ID",
}

# 이 목록에 있는 이름이 라벨 컬럼일 가능성이 높음 (자동 추정용)
LABEL_CANDIDATES = {"label", "Label", "LABEL", "class", "Class", "target", "Target"}

# PhiUSIIL 논문 기준 "기존 피처에서 파생된" 값들. 정상 사이트 DB / 전체 코퍼스 통계를
# 참조해야 계산되는 값이라, 실시간으로 URL 하나만 보고 똑같이 재현하기 사실상 불가능하다.
# (학습-서빙 간 피처 불일치 = 오탐/미탐의 주 원인으로 확인됨 -> 자동 제거)
LEAKY_COLUMNS = {"URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb"}


def load_and_inspect(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    print(f"[1/6] 데이터 로드 완료: {df.shape[0]}행 x {df.shape[1]}열")
    print("컬럼 목록:")
    print(list(df.columns))
    print("\n결측치가 있는 컬럼:")
    na_counts = df.isna().sum()
    print(na_counts[na_counts > 0] if na_counts.sum() > 0 else "  (없음)")
    return df


def resolve_label_column(df: pd.DataFrame, given: str | None) -> str:
    if given and given in df.columns:
        return given
    for cand in LABEL_CANDIDATES:
        if cand in df.columns:
            print(f"라벨 컬럼을 자동으로 '{cand}'(으)로 추정했습니다.")
            return cand
    raise ValueError(
        "라벨 컬럼을 찾지 못했습니다. --label-col 옵션으로 정확한 컬럼명을 지정해주세요.\n"
        f"현재 컬럼: {list(df.columns)}"
    )


def clean_and_split_columns(df: pd.DataFrame, label_col: str):
    y_raw = df[label_col]
    # 라벨이 문자열(legit/phish 등)이면 숫자로 변환
    if y_raw.dtype == object:
        le_label = LabelEncoder()
        y = le_label.fit_transform(y_raw)
        print(f"라벨 인코딩: {dict(zip(le_label.classes_, le_label.transform(le_label.classes_)))}")
    else:
        y = y_raw.to_numpy()
        le_label = None

    X = df.drop(columns=[label_col])
    drop_cols = [c for c in X.columns if c in ID_LIKE_COLUMNS]
    if drop_cols:
        print(f"식별자/원문 성격 컬럼 제거: {drop_cols}")
        X = X.drop(columns=drop_cols)

    leaky_present = [c for c in X.columns if c in LEAKY_COLUMNS]
    if leaky_present:
        print(
            f"실시간 재현 불가능한 leaky 피처 제거: {leaky_present} "
            "(정상 사이트 DB/전체 코퍼스 통계 필요 -> 실서비스 피처 추출기와 불일치 유발)"
        )
        X = X.drop(columns=leaky_present)

    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    categorical_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()
    print(f"수치형 피처 {len(numeric_cols)}개, 범주형 피처 {len(categorical_cols)}개")
    return X, y, numeric_cols, categorical_cols, le_label


def encode_categoricals(X: pd.DataFrame, categorical_cols: list[str]):
    encoders = {}
    for col in categorical_cols:
        X[col] = X[col].fillna("__missing__").astype(str)
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        encoders[col] = le
    return X, encoders


def transform_numeric(X: pd.DataFrame, numeric_cols: list[str]):
    """
    학습용 numeric preprocessing.
    inference에서 동일하게 재현할 수 있도록
    median / log1p / clipping 정보를 반환한다.
    """
    X = X.copy()

    medians = {}
    log1p_columns = []
    clip_bounds = {}

    # 1. median 저장 + 결측치 처리
    for col in numeric_cols:
        X[col] = pd.to_numeric(X[col], errors="coerce")

        median = float(X[col].median())
        medians[col] = median

        X[col] = X[col].fillna(median)

    # 2. log1p 적용 여부 저장
    for col in numeric_cols:
        col_min = X[col].min()
        skew = X[col].skew()

        if (
            col_min >= 0
            and abs(skew) > 1.0
        ):
            X[col] = np.log1p(X[col])
            log1p_columns.append(col)

    # 3. clipping 경계 저장
    for col in numeric_cols:
        lo = float(X[col].quantile(0.01))
        hi = float(X[col].quantile(0.99))

        clip_bounds[col] = [lo, hi]

        X[col] = X[col].clip(lo, hi)

    preprocessing_meta = {
        "numeric_medians": medians,
        "log1p_columns": log1p_columns,
        "clip_bounds": clip_bounds,
    }

    return X, preprocessing_meta


def select_top_features(X: pd.DataFrame, y: np.ndarray, top_ratio: float = 0.95):
    """전체 피처로 1차 RandomForest를 학습해 중요도 상위 피처를 선정."""
    print("\n[3/6] 전체 피처 중요도 분석 중 (1차 RandomForest)...")
    rf_probe = RandomForestClassifier(
        n_estimators=150, max_depth=20, random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced"
    )
    rf_probe.fit(X, y)
    importances = pd.Series(rf_probe.feature_importances_, index=X.columns).sort_values(ascending=False)

    cumulative = importances.cumsum() / importances.sum()
    n_selected = int((cumulative <= top_ratio).sum()) + 1
    n_selected = max(min(n_selected, len(importances)), min(15, len(importances)))
    selected = importances.index[:n_selected].tolist()

    print(f"중요도 상위 {n_selected}개 피처 선정 (누적 중요도 {top_ratio*100:.0f}% 기준)")
    print(importances.head(15).to_string())
    return selected, importances


def train_and_compare(X_train, X_test, y_train, y_test):
    models = {
        "LogisticRegression": LogisticRegression(
            max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=150, max_depth=20, random_state=RANDOM_STATE, n_jobs=-1, class_weight="balanced"
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=200, random_state=RANDOM_STATE
        ),
    }

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    results = {}

    print("\n[5/6] 모델별 5-fold 교차검증 + 홀드아웃 테스트 평가")
    for name, model in models.items():
        cv_scores = cross_val_score(model, X_train, y_train, cv=skf, scoring="f1", n_jobs=-1)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        test_f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        print(f"\n--- {name} ---")
        print(f"CV F1 (train, 5-fold): {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        print(f"Test F1 (holdout):     {test_f1:.4f}")
        print("Confusion Matrix (row=실제, col=예측) [0=phishing, 1=legit 기준은 라벨 인코딩에 따름]:")
        print(cm)
        print(classification_report(y_test, y_pred, digits=4))

        results[name] = {
            "model": model,
            "cv_f1_mean": cv_scores.mean(),
            "cv_f1_std": cv_scores.std(),
            "test_f1": test_f1,
            "confusion_matrix": cm.tolist(),
        }

    return results


def main():
    parser = argparse.ArgumentParser()
    SCRIPT_DIR = Path(__file__).parent
    default_csv = SCRIPT_DIR / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"
    parser.add_argument("--csv", default=str(default_csv), help="PhiUSIIL CSV 파일 경로")
    parser.add_argument("--label-col", default=None, help="라벨 컬럼명 (미지정 시 자동 추정)")
    parser.add_argument("--top-ratio", type=float, default=0.95, help="피처 중요도 누적 비율 기준")
    args = parser.parse_args()

    df = load_and_inspect(args.csv)
    label_col = resolve_label_column(df, args.label_col)

    X, y, numeric_cols, categorical_cols, label_encoder = clean_and_split_columns(df, label_col)

    print("\n[2/6] 전처리 시작 (범주형 인코딩, log1p, 이상치 클리핑)")
    X, cat_encoders = encode_categoricals(X, categorical_cols)
    X, numeric_preprocessing_meta = transform_numeric(X, numeric_cols)

    selected_features, importances = select_top_features(X, y, top_ratio=args.top_ratio)
    X_selected = X[selected_features]

    X_train, X_test, y_train, y_test = train_test_split(
        X_selected, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    print("\n[4/6] StandardScaler 학습 (train 기준)")
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns, index=X_test.index
    )

    results = train_and_compare(X_train_scaled, X_test_scaled, y_train, y_test)

    best_name = max(results, key=lambda k: results[k]["test_f1"])
    best_model = results[best_name]["model"]
    print(f"\n[6/6] 최종 선택 모델: {best_name} (Test F1: {results[best_name]['test_f1']:.4f})")

    joblib.dump(best_model, OUTPUT_DIR / "phishing_model.joblib")
    joblib.dump(scaler, OUTPUT_DIR / "scaler.joblib")
    joblib.dump(cat_encoders, OUTPUT_DIR / "categorical_encoders.joblib")
    if label_encoder is not None:
        joblib.dump(label_encoder, OUTPUT_DIR / "label_encoder.joblib")

    meta = {
        "best_model": best_name,
        "selected_features": selected_features,
        "numeric_cols_used": [c for c in numeric_cols if c in selected_features],
        "categorical_cols_used": [c for c in categorical_cols if c in selected_features],
        "test_f1": results[best_name]["test_f1"],
        "all_model_scores": {
            k: {"cv_f1_mean": v["cv_f1_mean"], "test_f1": v["test_f1"]} for k, v in results.items()
        },
    }
    with open(OUTPUT_DIR / "training_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    with open(
        OUTPUT_DIR / "preprocessing_meta.json",
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            numeric_preprocessing_meta,
            f,
            ensure_ascii=False,
            indent=2
        )

    print(f"\n저장 완료: {OUTPUT_DIR.resolve()}")
    print(" - phishing_model.joblib      : 최종 선택된 모델")
    print(" - scaler.joblib              : StandardScaler (실시간 추론 시 반드시 동일 순서/피처로 사용)")
    print(" - categorical_encoders.joblib: TLD 등 범주형 인코더")
    print(" - training_meta.json         : 선정된 피처 목록, 각 모델 성능 요약")
    print(
        "\n주의: url_feature_extractor.py에서 실시간으로 만드는 피처가 여기서 선정된 "
        f"{len(selected_features)}개 피처와 '이름/순서/전처리 방식'까지 정확히 같아야 합니다. "
        "training_meta.json의 selected_features 리스트를 실시간 추출 코드와 대조하세요."
    )


if __name__ == "__main__":
    main()
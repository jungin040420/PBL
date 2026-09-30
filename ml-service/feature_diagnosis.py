import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# ============================================================
# 경로
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model_artifacts"
DATASET_PATH = BASE_DIR / "data" / "PhiUSIIL_Phishing_URL_Dataset.csv"

TRAIN_META_PATH = MODEL_DIR / "training_meta.json"
PREPROCESS_META_PATH = MODEL_DIR / "preprocessing_meta.json"
ENCODER_PATH = MODEL_DIR / "categorical_encoders.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"


# ============================================================
# 설정
# ============================================================

# 비교할 정상 사이트
DEFAULT_URLS = [
    "https://www.google.com/",
    "https://www.microsoft.com/",
    "https://www.apple.com/",
    "https://github.com/",
    "https://www.amazon.com/",
    "https://www.kakao.com/",
    "https://www.naver.com/",
]


# ============================================================
# 파일 로드
# ============================================================

def load_training_meta():
    if not TRAIN_META_PATH.exists():
        raise FileNotFoundError(
            f"training_meta.json이 없습니다:\n{TRAIN_META_PATH}"
        )

    with open(TRAIN_META_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_preprocessing_meta():
    if not PREPROCESS_META_PATH.exists():
        print(
            "[WARNING] preprocessing_meta.json이 없습니다."
        )
        return {}

    with open(PREPROCESS_META_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_encoders():
    if not ENCODER_PATH.exists():
        print(
            "[WARNING] categorical_encoders.joblib가 없습니다."
        )
        return {}

    return joblib.load(ENCODER_PATH)


# ============================================================
# Dataset 분석
# ============================================================

def load_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset가 없습니다:\n{DATASET_PATH}"
        )

    print(f"[INFO] Dataset 로딩: {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)

    print(f"[INFO] Dataset shape: {df.shape}")
    print(f"[INFO] Columns: {len(df.columns)}")

    return df


# ============================================================
# 학습 feature 확인
# ============================================================

def print_training_features(meta):
    selected_features = meta.get("selected_features", [])

    print("\n" + "=" * 70)
    print("1. 모델이 실제로 사용하는 feature")
    print("=" * 70)

    print(f"총 feature 수: {len(selected_features)}")

    for i, feature in enumerate(selected_features, start=1):
        print(f"{i:2d}. {feature}")

    return selected_features


# ============================================================
# Dataset feature 존재 여부
# ============================================================

def check_dataset_features(df, selected_features):

    print("\n" + "=" * 70)
    print("2. Dataset에 selected feature가 존재하는지 확인")
    print("=" * 70)

    missing = []
    existing = []

    for feature in selected_features:

        if feature in df.columns:
            existing.append(feature)
            print(f"[OK]      {feature}")
        else:
            missing.append(feature)
            print(f"[MISSING] {feature}")

    print()
    print(f"존재: {len(existing)}")
    print(f"누락: {len(missing)}")

    return missing


# ============================================================
# Dataset feature 통계
# ============================================================

def print_dataset_statistics(df, selected_features):

    print("\n" + "=" * 70)
    print("3. 학습 Dataset feature 통계")
    print("=" * 70)

    rows = []

    for feature in selected_features:

        if feature not in df.columns:
            continue

        series = df[feature]

        numeric = pd.to_numeric(
            series,
            errors="coerce"
        )

        numeric_count = numeric.notna().sum()

        if numeric_count > 0:

            rows.append({
                "feature": feature,
                "type": "numeric",
                "min": numeric.min(),
                "median": numeric.median(),
                "mean": numeric.mean(),
                "p01": numeric.quantile(0.01),
                "p99": numeric.quantile(0.99),
                "max": numeric.max(),
                "unique": series.nunique(),
            })

        else:

            rows.append({
                "feature": feature,
                "type": "categorical",
                "min": "-",
                "median": "-",
                "mean": "-",
                "p01": "-",
                "p99": "-",
                "max": "-",
                "unique": series.nunique(),
            })

    stats = pd.DataFrame(rows)

    if not stats.empty:
        print(stats.to_string(index=False))

    return stats


# ============================================================
# preprocessing metadata
# ============================================================

def print_preprocessing_info(
    preprocessing_meta,
    selected_features
):

    print("\n" + "=" * 70)
    print("4. 학습 당시 preprocessing 정보")
    print("=" * 70)

    numeric_meta = preprocessing_meta.get(
        "numeric",
        preprocessing_meta
    )

    for feature in selected_features:

        info = numeric_meta.get(feature)

        if info is None:
            continue

        print(f"\n[{feature}]")

        print(
            f"  median  : {info.get('median')}"
        )

        print(
            f"  log1p   : {info.get('log1p')}"
        )

        print(
            f"  clip_lo : {info.get('clip_lo')}"
        )

        print(
            f"  clip_hi : {info.get('clip_hi')}"
        )


# ============================================================
# URL extractor import
# ============================================================

def load_live_extractor():

    print("\n[INFO] url_feature_extractor.py 로딩...")

    sys.path.insert(0, str(BASE_DIR))

    import url_feature_extractor

    return url_feature_extractor


# ============================================================
# 실제 웹 feature 추출
# ============================================================

def extract_live_features(extractor, url):

    print("\n" + "=" * 70)
    print(f"5. 실제 웹페이지 feature 추출")
    print("=" * 70)

    print(f"URL: {url}")

    # URL feature
    url_features = extractor.extract_url_features(url)

    # 페이지 feature
    page_features, final_url, title = (
        extractor.extract_page_features(url)
    )

    features = {}

    features.update(url_features)
    features.update(page_features)

    print(f"\n최종 URL: {final_url}")
    print(f"페이지 제목: {title}")

    return features


# ============================================================
# Feature 값 비교
# ============================================================

def compare_feature_values(
    df,
    selected_features,
    live_features,
    url
):

    print("\n" + "=" * 70)
    print("6. Dataset vs 실제 웹페이지 feature 비교")
    print("=" * 70)

    print(f"URL: {url}")

    rows = []

    for feature in selected_features:

        dataset_value = None
        live_value = None

        if feature in df.columns:

            series = df[feature]

            numeric = pd.to_numeric(
                series,
                errors="coerce"
            )

            if numeric.notna().sum() > 0:

                dataset_value = {
                    "median": numeric.median(),
                    "p01": numeric.quantile(0.01),
                    "p99": numeric.quantile(0.99),
                }

        if feature in live_features:
            live_value = live_features[feature]

        rows.append({
            "feature": feature,
            "dataset_median": (
                dataset_value["median"]
                if dataset_value
                else None
            ),
            "dataset_p01": (
                dataset_value["p01"]
                if dataset_value
                else None
            ),
            "dataset_p99": (
                dataset_value["p99"]
                if dataset_value
                else None
            ),
            "live_value": live_value,
        })

    result = pd.DataFrame(rows)

    print(
        result.to_string(index=False)
    )

    return result


# ============================================================
# 범위 이탈 검사
# ============================================================

def check_out_of_distribution(
    comparison,
    selected_features
):

    print("\n" + "=" * 70)
    print("7. 학습 Dataset 범위를 벗어난 feature")
    print("=" * 70)

    found = []

    for _, row in comparison.iterrows():

        feature = row["feature"]

        live = row["live_value"]
        p01 = row["dataset_p01"]
        p99 = row["dataset_p99"]

        if live is None:
            print(
                f"[MISSING] {feature}: "
                f"실시간 feature가 생성되지 않음"
            )

            found.append(feature)
            continue

        try:
            live_num = float(live)
            p01_num = float(p01)
            p99_num = float(p99)
        except (TypeError, ValueError):
            continue

        if live_num < p01_num:

            print(
                f"[LOW]     {feature}: "
                f"live={live_num:.4f}, "
                f"dataset P01={p01_num:.4f}"
            )

            found.append(feature)

        elif live_num > p99_num:

            print(
                f"[HIGH]    {feature}: "
                f"live={live_num:.4f}, "
                f"dataset P99={p99_num:.4f}"
            )

            found.append(feature)

        else:

            print(
                f"[OK]      {feature}: "
                f"live={live_num:.4f}"
            )

    print()
    print(
        f"범위 이탈/누락 feature: {len(found)}"
    )

    return found


# ============================================================
# Encoder 검사
# ============================================================

def check_encoders(
    live_features,
    selected_features,
    encoders
):

    print("\n" + "=" * 70)
    print("8. 범주형 feature encoder 검사")
    print("=" * 70)

    for feature in selected_features:

        if feature not in encoders:
            continue

        if feature not in live_features:
            print(
                f"[MISSING] {feature}: "
                "실시간 feature 없음"
            )
            continue

        value = str(
            live_features[feature]
        )

        encoder = encoders[feature]

        classes = set(
            map(str, encoder.classes_)
        )

        if value in classes:

            encoded = encoder.transform(
                [value]
            )[0]

            print(
                f"[OK] {feature}: "
                f"{value!r} -> {encoded}"
            )

        else:

            print(
                f"[ERROR] {feature}: "
                f"{value!r}가 학습 encoder에 없음"
            )


# ============================================================
# Main
# ============================================================

def diagnose_url(url):

    print("\n")
    print("#" * 70)
    print(" FEATURE GENERATION DIAGNOSTIC")
    print("#" * 70)

    print(f"\nBASE_DIR  : {BASE_DIR}")
    print(f"MODEL_DIR : {MODEL_DIR}")
    print(f"DATASET   : {DATASET_PATH}")

    # --------------------------------------------------------
    # 1. metadata
    # --------------------------------------------------------

    meta = load_training_meta()

    selected_features = print_training_features(
        meta
    )

    # --------------------------------------------------------
    # 2. dataset
    # --------------------------------------------------------

    df = load_dataset()

    check_dataset_features(
        df,
        selected_features
    )

    # --------------------------------------------------------
    # 3. dataset statistics
    # --------------------------------------------------------

    print_dataset_statistics(
        df,
        selected_features
    )

    # --------------------------------------------------------
    # 4. preprocessing
    # --------------------------------------------------------

    preprocessing_meta = (
        load_preprocessing_meta()
    )

    print_preprocessing_info(
        preprocessing_meta,
        selected_features
    )

    # --------------------------------------------------------
    # 5. live extractor
    # --------------------------------------------------------

    extractor = load_live_extractor()

    live_features = extract_live_features(
        extractor,
        url
    )

    # --------------------------------------------------------
    # 6. compare
    # --------------------------------------------------------

    comparison = compare_feature_values(
        df,
        selected_features,
        live_features,
        url
    )

    # --------------------------------------------------------
    # 7. OOD
    # --------------------------------------------------------

    out_of_distribution = (
        check_out_of_distribution(
            comparison,
            selected_features
        )
    )

    # --------------------------------------------------------
    # 8. encoder
    # --------------------------------------------------------

    encoders = load_encoders()

    check_encoders(
        live_features,
        selected_features,
        encoders
    )

    # --------------------------------------------------------
    # 9. summary
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("9. 진단 요약")
    print("=" * 70)

    missing_live = [
        f
        for f in selected_features
        if f not in live_features
    ]

    print(
        f"모델 selected feature 수 : "
        f"{len(selected_features)}"
    )

    print(
        f"실시간 생성 feature 수    : "
        f"{len(live_features)}"
    )

    print(
        f"실시간 누락 feature 수    : "
        f"{len(missing_live)}"
    )

    print(
        f"Dataset 범위 이탈 수      : "
        f"{len(out_of_distribution)}"
    )

    if missing_live:

        print("\n[CRITICAL]")
        print(
            "학습 모델이 요구하는 feature 중 "
            "실시간 extractor가 생성하지 못하는 feature가 있습니다."
        )

        for feature in missing_live:
            print(f"  - {feature}")

    elif out_of_distribution:

        print("\n[WARNING]")
        print(
            "실시간 feature 중 학습 Dataset의 "
            "P01~P99 범위를 벗어나는 값이 있습니다."
        )

        print(
            "이 경우 실제 웹페이지와 학습 데이터의 "
            "분포 차이가 모델 오판의 원인일 수 있습니다."
        )

    else:

        print("\n[OK]")
        print(
            "feature 이름과 기본적인 값 범위는 "
            "큰 문제 없이 보입니다."
        )

    print("\n진단 완료.")


# ============================================================
# Entry
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) >= 2:

        target_url = sys.argv[1]

    else:

        print(
            "[INFO] URL 인자가 없으므로 "
            "기본 테스트 URL을 사용합니다."
        )

        target_url = DEFAULT_URLS[0]

    diagnose_url(target_url)
"""
F-29: Isolation Forest 모델 학습 스크립트.

python-risk/data/ 안의 로그 데이터(csv)를 읽어서 Isolation Forest를 학습시키고
model/isolation_forest.joblib 로 저장합니다.

F-28(데이터 버전 관리)에서 관리되는 데이터셋 경로가 확정되면 --data 옵션만 맞추면 됩니다.
아직 실전 데이터가 없는 경우(파일 없음/빈 파일) CI가 무작정 실패하지 않도록,
--allow-synthetic 옵션을 주면 무작위 합성 데이터로 학습해서 "파이프라인 자체가
정상 동작하는지"만 검증합니다. 이 옵션으로 만든 모델은 실제 배포에 쓰면 안 됩니다.
"""
import argparse
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "app"))
from isolation_model import FEATURE_ORDER, train, save, MODEL_PATH  # noqa: E402

DEFAULT_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "login_logs.csv")


def load_training_data(data_path: str) -> np.ndarray:
    if not os.path.exists(data_path) or os.path.getsize(data_path) == 0:
        raise FileNotFoundError(f"학습 데이터가 없습니다: {data_path}")

    df = pd.read_csv(data_path)
    missing = [c for c in FEATURE_ORDER if c not in df.columns]
    if missing:
        raise ValueError(f"데이터에 필요한 컬럼이 없습니다: {missing}")

    return df[FEATURE_ORDER].to_numpy(dtype=float)


def generate_synthetic_data(n: int = 200) -> np.ndarray:
    rng = np.random.default_rng(42)
    return rng.random((n, len(FEATURE_ORDER)))


def main():
    parser = argparse.ArgumentParser(description="Isolation Forest 학습 (F-29)")
    parser.add_argument("--data", default=DEFAULT_DATA_PATH, help="학습용 CSV 경로")
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        help="진짜 데이터가 없을 때 합성 데이터로 대신 학습 (CI 파이프라인 검증용, 실제 배포 금지)",
    )
    args = parser.parse_args()

    try:
        feature_matrix = load_training_data(args.data)
        print(f"실제 데이터 {feature_matrix.shape[0]}건으로 학습합니다: {args.data}")
    except (FileNotFoundError, ValueError) as e:
        if not args.allow_synthetic:
            print(f"[에러] {e}")
            print("실제 데이터 없이 학습을 건너뜁니다. CI 파이프라인만 검증하려면 --allow-synthetic 옵션을 쓰세요.")
            sys.exit(1)
        print(f"[경고] {e} -> 합성 데이터로 파이프라인만 검증합니다 (이 모델은 배포 금지)")
        feature_matrix = generate_synthetic_data()

    model = train(feature_matrix, contamination=args.contamination)
    save(model)
    print(f"모델 저장 완료: {MODEL_PATH}")


if __name__ == "__main__":
    main()

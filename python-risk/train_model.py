import argparse
import os
import sys

import numpy as np
import pymysql

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(__file__),
        "app",
    ),
)

from isolation_model import (  # noqa: E402
    FEATURE_ORDER,
    MODEL_PATH,
    MODEL_META_PATH,
    save,
    save_metadata,
    train,
)


DB_HOST = os.getenv(
    "DB_HOST",
    "localhost",
)

DB_PORT = int(
    os.getenv(
        "DB_PORT",
        "3307",
    )
)

DB_USER = os.getenv(
    "DB_USER",
    "authuser",
)

DB_PASSWORD = os.getenv(
    "DB_PASSWORD",
)

DB_NAME = os.getenv(
    "DB_NAME",
    "mfa_db",
)


MIN_TRAINING_ROWS = 30


def load_training_data_from_mysql() -> np.ndarray:
    """
    ml_feature_logs에서 REAL 데이터만 조회한다.
    """

    if not DB_PASSWORD:
        raise RuntimeError(
            "DB_PASSWORD 환경변수가 설정되지 않았습니다."
        )

    connection = None

    try:
        connection = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            charset="utf8mb4",
            connect_timeout=3,
        )

        sql = """
            SELECT
                login_frequency,
                failed_login_count,
                ip_changed,
                user_agent_changed,
                is_new_device,
                region_changed,
                COALESCE(
                    challenge_response_time,
                    0
                ) AS challenge_response_time,
                login_hour,
                day_of_week
            FROM ml_feature_logs
            WHERE data_source = 'REAL'
            ORDER BY id ASC
        """

        with connection.cursor() as cursor:
            cursor.execute(sql)
            rows = cursor.fetchall()

    finally:
        if connection is not None:
            connection.close()

    if not rows:
        raise ValueError(
            "ml_feature_logs에 REAL 학습 데이터가 없습니다."
        )

    feature_matrix = np.array(
        rows,
        dtype=float,
    )

    if feature_matrix.shape[1] != len(
        FEATURE_ORDER
    ):
        raise ValueError(
            "DB Feature 개수와 FEATURE_ORDER가 일치하지 않습니다."
        )

    return feature_matrix


def generate_synthetic_data(
    n: int = 200,
) -> np.ndarray:
    """
    CI/파이프라인 검증용 합성 데이터.
    실제 배포 모델 학습에는 사용하지 않는다.
    """

    rng = np.random.default_rng(42)

    login_frequency = rng.integers(
        1,
        8,
        size=n,
    )

    failed_login_count = rng.choice(
        [0, 0, 0, 0, 1, 2],
        size=n,
    )

    ip_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.9, 0.1],
    )

    user_agent_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.9, 0.1],
    )

    is_new_device = rng.choice(
        [0, 1],
        size=n,
        p=[0.9, 0.1],
    )

    region_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.95, 0.05],
    )

    challenge_response_time = rng.normal(
        1800,
        500,
        size=n,
    )

    challenge_response_time = np.clip(
        challenge_response_time,
        300,
        5000,
    )

    login_hour = rng.integers(
        7,
        23,
        size=n,
    )

    day_of_week = rng.integers(
        0,
        7,
        size=n,
    )

    return np.column_stack(
        [
            login_frequency,
            failed_login_count,
            ip_changed,
            user_agent_changed,
            is_new_device,
            region_changed,
            challenge_response_time,
            login_hour,
            day_of_week,
        ]
    ).astype(float)


def print_feature_order() -> None:
    print("학습 Feature 순서:")

    for index, feature_name in enumerate(
        FEATURE_ORDER,
        start=1,
    ):
        print(
            f"  {index}. {feature_name}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "ml_feature_logs REAL 데이터 기반 "
            "Isolation Forest 학습"
        )
    )

    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
    )

    parser.add_argument(
        "--min-rows",
        type=int,
        default=MIN_TRAINING_ROWS,
    )

    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
    )

    args = parser.parse_args()

    if not 0 < args.contamination <= 0.5:
        print(
            "[학습 중단] contamination은 "
            "0보다 크고 0.5 이하여야 합니다."
        )
        sys.exit(1)

    print_feature_order()

    model_type = "REAL"

    try:
        feature_matrix = (
            load_training_data_from_mysql()
        )

        row_count = feature_matrix.shape[0]

        print(
            f"MySQL REAL 학습 데이터: "
            f"{row_count}건"
        )

        if row_count < args.min_rows:
            raise ValueError(
                f"REAL 학습 데이터 부족: "
                f"{row_count}건 / "
                f"최소 {args.min_rows}건"
            )

    except (
        RuntimeError,
        ValueError,
        pymysql.MySQLError,
    ) as error:

        if not args.allow_synthetic:
            print(
                f"[학습 중단] {error}"
            )

            print(
                "REAL 데이터가 충분히 쌓인 뒤 "
                "다시 실행하세요."
            )

            sys.exit(1)

        model_type = "SYNTHETIC"

        print(
            f"[경고] {error}"
        )

        print(
            "합성 데이터로 ML 파이프라인만 "
            "검증합니다."
        )

        print(
            "이 모델은 실제 배포에 사용하면 안 됩니다."
        )

        feature_matrix = (
            generate_synthetic_data()
        )

    print(
        "학습 Matrix shape:",
        feature_matrix.shape,
    )

    model = train(
        feature_matrix,
        contamination=args.contamination,
    )

    save(model)

    save_metadata(
        model_type=model_type,
        training_rows=feature_matrix.shape[0],
        contamination=args.contamination,
    )

    print(
        "Isolation Forest 학습 완료"
    )

    prin: {MODEL_META_PATH}"
    )


if __name__ == "__main__":
    main()
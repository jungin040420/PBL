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


# ============================================================
# DB 설정
# ============================================================

DB_HOST = os.getenv(
    "ML_DB_HOST",
    os.getenv("DB_HOST", "localhost"),
)

DB_PORT = int(
    os.getenv(
        "ML_DB_PORT",
        os.getenv("DB_PORT", "3307"),
    )
)

DB_USER = os.getenv(
    "ML_DB_USER",
    os.getenv("DB_USER", "ml_reader"),
)

DB_PASSWORD = os.getenv(
    "ML_DB_PASSWORD",
    os.getenv("DB_PASSWORD"),
)

DB_NAME = os.getenv(
    "ML_DB_NAME",
    "ml_db",
)


MIN_TRAINING_ROWS = 30


# ============================================================
# loginRegion 인코딩
#
# main.py와 반드시 동일한 기준 사용
#
# KR       -> 0
# KR 이외  -> 1
# ============================================================

def encode_login_region(
    login_region,
) -> int:

    if (
        login_region
        and str(login_region).upper() == "KR"
    ):
        return 0

    return 1


# ============================================================
# MySQL REAL 학습 데이터 로드
#
# 최종 확정 Feature: 16개
# ============================================================

def load_training_data_from_mysql() -> np.ndarray:

    if not DB_PASSWORD:
        raise RuntimeError(
            "ML DB 비밀번호 환경변수가 설정되지 않았습니다."
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

        # ----------------------------------------------------
        # 순서 중요
        #
        # 아래 SELECT 순서는 isolation_model.py의
        # FEATURE_ORDER와 반드시 동일해야 한다.
        # ----------------------------------------------------

        sql = """
            SELECT
                COALESCE(login_frequency, 0),
                COALESCE(failed_login_count, 0),
                COALESCE(challenge_response_time, 0),
                COALESCE(authentication_method_changed, 0),
                COALESCE(ip_changed, 0),
                COALESCE(region_changed, 0),
                COALESCE(sign_count_abnormal, 0),
                COALESCE(credential_mismatch, 0),
                COALESCE(user_agent_changed, 0),
                COALESCE(is_new_device, 0),
                COALESCE(consecutive_failure_count, 0),
                COALESCE(blacklist_ip_detected, 0),
                COALESCE(login_hour, 0),
                COALESCE(day_of_week, 0),
                login_region,
                COALESCE(has_previous_context, 0)
            FROM ml_feature_logs
            WHERE data_source = 'REAL'
            ORDER BY event_id ASC
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


    # --------------------------------------------------------
    # loginRegion 문자열 -> 숫자 인코딩
    #
    # DB의 15번째 값(index 14)이 login_region
    # --------------------------------------------------------

    encoded_rows = []

    for row in rows:

        row = list(row)

        row[14] = encode_login_region(
            row[14]
        )

        encoded_rows.append(
            row
        )


    feature_matrix = np.array(
        encoded_rows,
        dtype=float,
    )


    # --------------------------------------------------------
    # Matrix 검증
    # --------------------------------------------------------

    if feature_matrix.ndim != 2:

        raise ValueError(
            "DB 학습 데이터가 2차원 Matrix가 아닙니다."
        )


    if feature_matrix.shape[1] != len(
        FEATURE_ORDER
    ):

        raise ValueError(
            "DB Feature 개수와 FEATURE_ORDER가 "
            "일치하지 않습니다."
        )


    if feature_matrix.shape[1] != 16:

        raise ValueError(
            "최종 ML Feature는 반드시 16개여야 합니다."
        )


    return feature_matrix


# ============================================================
# SYNTHETIC 테스트 데이터
#
# 실제 모델 학습용이 아님.
# CI / ML 파이프라인 검증용.
#
# 역시 16 Feature 구조를 유지한다.
# ============================================================

def generate_synthetic_data(
    n: int = 200,
) -> np.ndarray:

    rng = np.random.default_rng(42)


    # 1
    login_frequency = rng.integers(
        0,
        8,
        size=n,
    )


    # 2
    failed_login_count = rng.choice(
        [0, 0, 0, 0, 1, 2],
        size=n,
    )


    # 3
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


    # 4
    authentication_method_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.97, 0.03],
    )


    # 5
    ip_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.9, 0.1],
    )


    # 6
    region_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.95, 0.05],
    )


    # 7
    sign_count_abnormal = rng.choice(
        [0, 1],
        size=n,
        p=[0.98, 0.02],
    )


    # 8
    credential_mismatch = rng.choice(
        [0, 1],
        size=n,
        p=[0.97, 0.03],
    )


    # 9
    user_agent_changed = rng.choice(
        [0, 1],
        size=n,
        p=[0.9, 0.1],
    )


    # 10
    is_new_device = rng.choice(
        [0, 1],
        size=n,
        p=[0.9, 0.1],
    )


    # 11
    consecutive_failure_count = rng.choice(
        [0, 0, 0, 1, 2, 3],
        size=n,
    )


    # 12
    blacklist_ip_detected = rng.choice(
        [0, 1],
        size=n,
        p=[0.99, 0.01],
    )


    # 13
    login_hour = rng.integers(
        0,
        24,
        size=n,
    )


    # 14
    day_of_week = rng.integers(
        0,
        7,
        size=n,
    )


    # 15
    # KR=0 / 해외=1
    login_region = rng.choice(
        [0, 1],
        size=n,
        p=[0.95, 0.05],
    )


    # 16
    has_previous_context = rng.choice(
        [0, 1],
        size=n,
        p=[0.15, 0.85],
    )


    feature_matrix = np.column_stack(
        [
            login_frequency,
            failed_login_count,
            challenge_response_time,
            authentication_method_changed,
            ip_changed,
            region_changed,
            sign_count_abnormal,
            credential_mismatch,
            user_agent_changed,
            is_new_device,
            consecutive_failure_count,
            blacklist_ip_detected,
            login_hour,
            day_of_week,
            login_region,
            has_previous_context,
        ]
    ).astype(float)


    if feature_matrix.shape[1] != len(
        FEATURE_ORDER
    ):

        raise ValueError(
            "SYNTHETIC Feature 개수와 "
            "FEATURE_ORDER가 일치하지 않습니다."
        )


    return feature_matrix


# ============================================================
# Feature 순서 출력
# ============================================================

def print_feature_order() -> None:

    print(
        f"학습 Feature 순서 "
        f"(총 {len(FEATURE_ORDER)}개):"
    )

    for index, feature_name in enumerate(
        FEATURE_ORDER,
        start=1,
    ):

        print(
            f"  {index}. {feature_name}"
        )


# ============================================================
# Main
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "ml_feature_logs REAL 데이터 기반 "
            "16 Feature Isolation Forest 학습"
        )
    )

    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Isolation Forest 이상치 예상 비율",
    )

    parser.add_argument(
        "--min-rows",
        type=int,
        default=MIN_TRAINING_ROWS,
        help="REAL 모델 학습에 필요한 최소 데이터 수",
    )

    parser.add_argument(
        "--allow-synthetic",
        action="store_true",
        help=(
            "REAL 데이터 부족 시 합성 데이터로 "
            "ML 파이프라인만 검증"
        ),
    )

    args = parser.parse_args()


    # --------------------------------------------------------
    # contamination 검증
    # --------------------------------------------------------

    if not 0 < args.contamination <= 0.5:

        print(
            "[학습 중단] contamination은 "
            "0보다 크고 0.5 이하여야 합니다."
        )

        sys.exit(1)


    # --------------------------------------------------------
    # Feature 검증
    # --------------------------------------------------------

    if len(FEATURE_ORDER) != 16:

        print(
            "[학습 중단] FEATURE_ORDER가 "
            f"{len(FEATURE_ORDER)}개입니다. "
            "최종 Feature는 반드시 16개여야 합니다."
        )

        sys.exit(1)


    print_feature_order()

    model_type = "REAL"


    # --------------------------------------------------------
    # REAL 데이터 로드
    # --------------------------------------------------------

    try:

        feature_matrix = (
            load_training_data_from_mysql()
        )

        row_count = (
            feature_matrix.shape[0]
        )

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


    # --------------------------------------------------------
    # REAL 데이터 로드 실패 / 부족
    # --------------------------------------------------------

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
            "이 모델은 실제 로그인 위험 판정에 "
            "사용하면 안 됩니다."
        )

        feature_matrix = (
            generate_synthetic_data()
        )


    # --------------------------------------------------------
    # 최종 Matrix 검증
    # --------------------------------------------------------

    print(
        "학습 Matrix shape:",
        feature_matrix.shape,
    )


    if feature_matrix.shape[1] != 16:

        print(
            "[학습 중단] 학습 Matrix가 "
            "16 Feature가 아닙니다."
        )

        sys.exit(1)


    # --------------------------------------------------------
    # Isolation Forest 학습
    # --------------------------------------------------------

    model = train(
        feature_matrix,
        contamination=args.contamination,
    )


    # --------------------------------------------------------
    # 모델 저장
    # --------------------------------------------------------

    save(
        model
    )


    # --------------------------------------------------------
    # Metadata 저장
    # --------------------------------------------------------

    save_metadata(
        model_type=model_type,
        training_rows=feature_matrix.shape[0],
        contamination=args.contamination,
    )


    # --------------------------------------------------------
    # 완료
    # --------------------------------------------------------

    print(
        "Isolation Forest 학습 완료"
    )

    print(
        f"모델 유형: {model_type}"
    )

    print(
        f"학습 행 수: "
        f"{feature_matrix.shape[0]}"
    )

    print(
        f"Feature 수: "
        f"{feature_matrix.shape[1]}"
    )

    print(
        f"모델 저장 완료: "
        f"{MODEL_PATH}"
    )

    print(
        f"메타데이터 저장 완료: "
        f"{MODEL_META_PATH}"
    )


if __name__ == "__main__":
    main()
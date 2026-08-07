import argparse
import hashlib
import os
import random
import uuid

import pymysql


DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3307"))
DB_USER = os.getenv("DB_USER", "authuser")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME", "mfa_db")


def make_test_hash(prefix: str, index: int) -> str:
    value = f"synthetic-test:{prefix}:{index}:{uuid.uuid4()}"
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def generate_row(index: int) -> tuple:
    # 약 80% 정상 형태
    if random.random() < 0.80:
        login_frequency = random.randint(1, 6)

        failed_login_count = random.choices(
            [0, 1, 2],
            weights=[80, 15, 5],
        )[0]

        ip_changed = random.choices(
            [0, 1],
            weights=[95, 5],
        )[0]

        user_agent_changed = random.choices(
            [0, 1],
            weights=[95, 5],
        )[0]

        is_new_device = random.choices(
            [0, 1],
            weights=[95, 5],
        )[0]

        region_changed = random.choices(
            [0, 1],
            weights=[98, 2],
        )[0]

        challenge_response_time = random.randint(
            800,
            3000,
        )

        login_hour = random.randint(
            7,
            23,
        )

    # 약 20% 이상 형태
    else:
        login_frequency = random.randint(
            7,
            20,
        )

        failed_login_count = random.randint(
            2,
            8,
        )

        ip_changed = random.randint(0, 1)
        user_agent_changed = random.randint(0, 1)
        is_new_device = random.randint(0, 1)
        region_changed = random.randint(0, 1)

        challenge_response_time = random.choice(
            [
                random.randint(50, 299),
                random.randint(5001, 10000),
            ]
        )

        login_hour = random.randint(
            0,
            5,
        )

    day_of_week = random.randint(0, 6)

    user_id_hash = make_test_hash(
        "user",
        index,
    )

    ip_hash = make_test_hash(
        "ip",
        index,
    )

    return (
        user_id_hash,
        ip_hash,
        login_frequency,
        failed_login_count,
        ip_changed,
        user_agent_changed,
        is_new_device,
        region_changed,
        challenge_response_time,
        login_hour,
        day_of_week,
        "SYNTHETIC",
    )


def insert_test_data(count: int) -> None:
    if not DB_PASSWORD:
        raise RuntimeError(
            "DB_PASSWORD 환경변수가 설정되지 않았습니다."
        )

    connection = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        autocommit=False,
    )

    sql = """
        INSERT INTO ml_feature_logs (
            user_id_hash,
            ip_hash,
            login_frequency,
            failed_login_count,
            ip_changed,
            user_agent_changed,
            is_new_device,
            region_changed,
            challenge_response_time,
            login_hour,
            day_of_week,
            data_source
        )
        VALUES (
            %s, %s, %s, %s,
            %s, %s, %s, %s,
            %s, %s, %s, %s
        )
    """

    try:
        rows = [
            generate_row(index)
            for index in range(count)
        ]

        with connection.cursor() as cursor:
            cursor.executemany(
                sql,
                rows,
            )

        connection.commit()

        print(
            f"SYNTHETIC ML 테스트 데이터 "
            f"{count}건 저장 완료"
        )

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "ML 파이프라인 검증용 "
            "SYNTHETIC 데이터 생성"
        )
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
    )

    args = parser.parse_args()

    if args.count <= 0:
        raise ValueError(
            "--count는 1 이상이어야 합니다."
        )

    random.seed(42)

    insert_test_data(
        args.count
    )


if __name__ == "__main__":
    main()
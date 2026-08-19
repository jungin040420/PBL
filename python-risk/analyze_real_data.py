import os
from collections import Counter

import pymysql


# ============================================================
# MySQL 설정
#
# ML 분석/학습 데이터 조회는 SELECT 전용 ml_reader 사용
#
# Docker 내부 기본값:
#   host     = mysql
#   port     = 3306
#   user     = ml_reader
#   database = ml_db
#
# 비밀번호는 코드에 직접 작성하지 않고 환경변수로 전달한다.
# ============================================================

DB_HOST = os.getenv(
    "ML_DB_HOST",
    os.getenv(
        "DB_HOST",
        "mysql",
    ),
)

DB_PORT = int(
    os.getenv(
        "ML_DB_PORT",
        os.getenv(
            "DB_PORT",
            "3306",
        ),
    )
)

DB_USER = os.getenv(
    "ML_READER_USER",
    "ml_reader",
)

DB_PASSWORD = os.getenv(
    "ML_READER_PASSWORD",
    os.getenv(
        "ML_DB_PASSWORD",
    ),
)

DB_NAME = os.getenv(
    "ML_DB_NAME",
    "ml_db",
)


# ============================================================
# Isolation Forest 학습 Numeric Feature
# ============================================================

NUMERIC_FEATURES = [
    "login_frequency",
    "failed_login_count",
    "challenge_response_time",
    "login_hour",
    "day_of_week",
]


# ============================================================
# Isolation Forest 학습 Boolean Feature
#
# 최종 학습 Feature 중 Boolean Feature
# ============================================================

ML_BOOLEAN_FEATURES = [
    "ip_changed",
    "user_agent_changed",
    "is_new_device",
    "region_changed",
    "has_previous_context",
]


# ============================================================
# 추가 수집/분석 Feature
#
# sign_count_abnormal은 DB에는 저장하지만
# 현재 Isolation Forest 학습 Feature에는 포함하지 않는다.
# ============================================================

COLLECTED_BOOLEAN_FEATURES = [
    "sign_count_abnormal",
]


# 전체 Boolean 분석 대상
BOOLEAN_FEATURES = (
    ML_BOOLEAN_FEATURES
    + COLLECTED_BOOLEAN_FEATURES
)


# ============================================================
# 범주형 수집 Feature
#
# login_region은 문자열이므로 현재 Isolation Forest의
# 숫자 Feature에는 직접 포함하지 않는다.
# ============================================================

CATEGORICAL_FEATURES = [
    "login_region",
]


# ============================================================
# MySQL 연결
# ============================================================

def get_connection():

    if not DB_PASSWORD:

        raise RuntimeError(
            "ML_READER_PASSWORD 또는 "
            "ML_DB_PASSWORD 환경변수가 설정되지 않았습니다."
        )

    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )


# ============================================================
# REAL 데이터 조회
# ============================================================

def load_real_rows():

    connection = get_connection()

    try:

        sql = """
            SELECT
                event_id,
                created_at,
                data_source,
                login_region,
                login_frequency,
                failed_login_count,
                ip_changed,
                user_agent_changed,
                is_new_device,
                region_changed,
                has_previous_context,
                sign_count_abnormal,
                credential_mismatch,
                challenge_response_time,
                login_hour,
                day_of_week
            FROM ml_feature_logs
            WHERE data_source = 'REAL'
            ORDER BY created_at ASC, event_id ASC
        """

        with connection.cursor() as cursor:

            cursor.execute(sql)

            return cursor.fetchall()

    finally:

        connection.close()


# ============================================================
# 기본 데이터 요약
# ============================================================

def print_basic_summary(rows):

    print("=" * 70)
    print("REAL 로그인 데이터 품질 분석")
    print("=" * 70)

    print(
        f"DB: {DB_NAME}"
    )

    print(
        f"조회 계정: {DB_USER}"
    )

    print(
        f"REAL 총 데이터 수: "
        f"{len(rows)}건"
    )

    if rows:

        print(
            f"첫 수집 시각: "
            f"{rows[0]['created_at']}"
        )

        print(
            f"최근 수집 시각: "
            f"{rows[-1]['created_at']}"
        )


# ============================================================
# NULL 검사
# ============================================================

def print_null_summary(rows):

    print()
    print("[NULL 검사]")

    fields = (
        NUMERIC_FEATURES
        + BOOLEAN_FEATURES
        + CATEGORICAL_FEATURES
    )

    total_nulls = 0

    for field in fields:

        null_count = sum(
            1
            for row in rows
            if row[field] is None
        )

        total_nulls += null_count

        print(
            f"{field}: "
            f"{null_count}건"
        )

    print(
        f"전체 NULL 수: "
        f"{total_nulls}"
    )


# ============================================================
# Numeric Feature 통계
# ============================================================

def print_numeric_summary(rows):

    print()
    print("[숫자 Feature 통계]")

    for field in NUMERIC_FEATURES:

        values = [
            float(row[field])
            for row in rows
            if row[field] is not None
        ]

        if not values:

            print(
                f"{field}: 데이터 없음"
            )

            continue

        print()
        print(field)

        print(
            f"  MIN: "
            f"{min(values):.2f}"
        )

        print(
            f"  MAX: "
            f"{max(values):.2f}"
        )

        print(
            f"  AVG: "
            f"{sum(values) / len(values):.2f}"
        )

        print(
            f"  UNIQUE: "
            f"{len(set(values))}"
        )


# ============================================================
# Boolean Feature 분포
# ============================================================

def print_boolean_summary(rows):

    print()
    print("[Boolean Feature 분포]")

    for field in BOOLEAN_FEATURES:

        values = [
            int(row[field] or 0)
            for row in rows
        ]

        false_count = values.count(0)
        true_count = values.count(1)

        total = len(values)

        true_rate = (
            true_count / total * 100
            if total
            else 0
        )

        print()
        print(field)

        print(
            f"  0(false): "
            f"{false_count}건"
        )

        print(
            f"  1(true): "
            f"{true_count}건"
        )

        print(
            f"  true 비율: "
            f"{true_rate:.2f}%"
        )

        if field == "sign_count_abnormal":

            if true_count == 0:

                print(
                    "  상태: 현재 비정상 "
                    "signCount 데이터 없음"
                )

            else:

                print(
                    "  상태: 비정상 signCount "
                    "데이터 존재"
                )


# ============================================================
# 로그인 지역 분포
# ============================================================

def print_login_region_distribution(rows):

    print()
    print("[로그인 지역 분포]")

    values = [
        str(row["login_region"])
        for row in rows
        if row["login_region"] is not None
    ]

    if not values:

        print(
            "login_region 데이터 없음"
        )

        return

    counter = Counter(values)

    total = len(values)

    for region, count in sorted(
        counter.items(),
        key=lambda item: (
            -item[1],
            item[0],
        ),
    ):

        rate = (
            count / total * 100
            if total
            else 0
        )

        print(
            f"{region}: "
            f"{count}건 "
            f"({rate:.2f}%)"
        )

    print(
        f"지역 종류 수: "
        f"{len(counter)}"
    )


# ============================================================
# 로그인 시간대 분포
# ============================================================

def print_login_hour_distribution(rows):

    print()
    print("[로그인 시간대 분포]")

    counter = Counter(
        int(row["login_hour"])
        for row in rows
        if row["login_hour"] is not None
    )

    for hour in range(24):

        count = counter.get(
            hour,
            0,
        )

        if count:

            print(
                f"{hour:02d}시: "
                f"{count}건"
            )


# ============================================================
# 요일 분포
# ============================================================

def print_day_distribution(rows):

    print()
    print("[요일 분포]")

    counter = Counter(
        int(row["day_of_week"])
        for row in rows
        if row["day_of_week"] is not None
    )

    day_names = {
        0: "일",
        1: "월",
        2: "화",
        3: "수",
        4: "목",
        5: "금",
        6: "토",
    }

    for day in range(7):

        count = counter.get(
            day,
            0,
        )

        if count:

            print(
                f"{day_names[day]}요일: "
                f"{count}건"
            )


# ============================================================
# Isolation Forest 학습 Feature 상태
#
# 현재 최종 Feature = 10개
# ============================================================

def print_ml_feature_status():

    print()
    print("[Isolation Forest 학습 Feature]")

    ml_features = [
        "login_frequency",
        "failed_login_count",
        "ip_changed",
        "user_agent_changed",
        "is_new_device",
        "region_changed",
        "challenge_response_time",
        "login_hour",
        "day_of_week",
        "has_previous_context",
    ]

    for index, feature in enumerate(
        ml_features,
        start=1,
    ):

        print(
            f"{index}. {feature}"
        )

    print()

    print(
        "현재 ML 학습 Feature 수: "
        f"{len(ml_features)}개"
    )

    print(
        "login_region: "
        "수집/분석만 수행, ML 학습 미포함"
    )

    print(
        "sign_count_abnormal: "
        "수집/분석만 수행, ML 학습 미포함"
    )


# ============================================================
# 데이터 품질 경고
# ============================================================

def print_quality_warnings(rows):

    print()
    print("[데이터 품질 경고]")

    warnings = []

    # --------------------------------------------------------
    # 데이터 개수
    # --------------------------------------------------------

    if len(rows) < 30:

        warnings.append(
            f"REAL 학습 최소 기준 미달: "
            f"{len(rows)}건 / 최소 30건"
        )

    if len(rows) < 80:

        warnings.append(
            f"멘토 실험 목표 미달: "
            f"{len(rows)}건 / 목표 80~100건"
        )


    # --------------------------------------------------------
    # ML Boolean Feature 다양성
    # --------------------------------------------------------

    for field in ML_BOOLEAN_FEATURES:

        values = {
            int(row[field] or 0)
            for row in rows
        }

        if len(values) <= 1:

            warnings.append(
                f"{field} 값 다양성 부족: "
                f"{values}"
            )


    # --------------------------------------------------------
    # Numeric Feature 다양성
    # --------------------------------------------------------

    for field in NUMERIC_FEATURES:

        values = {
            row[field]
            for row in rows
            if row[field] is not None
        }

        if len(values) <= 1:

            warnings.append(
                f"{field} 값 다양성 부족"
            )


    # --------------------------------------------------------
    # login_region 품질
    # --------------------------------------------------------

    login_regions = {
        str(row["login_region"])
        for row in rows
        if row["login_region"] is not None
    }

    if len(login_regions) <= 1:

        warnings.append(
            "login_region 다양성 부족: "
            f"{login_regions}"
        )


    # --------------------------------------------------------
    # sign_count_abnormal 품질
    # --------------------------------------------------------

    sign_count_values = {
        int(
            row["sign_count_abnormal"]
            or 0
        )
        for row in rows
    }

    if len(sign_count_values) <= 1:

        warnings.append(
            "sign_count_abnormal 값 다양성 부족: "
            f"{sign_count_values} "
            "(현재는 수집/분석용 Feature)"
        )


    # --------------------------------------------------------
    # 경고 출력
    # --------------------------------------------------------

    if warnings:

        for warning in warnings:

            print(
                f"- {warning}"
            )

    else:

        print(
            "현재 기준에서 뚜렷한 "
            "품질 경고가 없습니다."
        )


# ============================================================
# 추가 수집 Feature 요약
# ============================================================

def print_additional_feature_summary(rows):

    print()
    print("[추가 수집 Feature 상태]")


    # --------------------------------------------------------
    # loginRegion
    # --------------------------------------------------------

    login_regions = [
        row["login_region"]
        for row in rows
        if row["login_region"] is not None
    ]

    print(
        "loginRegion:"
    )

    print(
        f"  수집 데이터: "
        f"{len(login_regions)}건"
    )

    print(
        f"  UNIQUE: "
        f"{len(set(login_regions))}"
    )

    print(
        "  ML 학습 반영: 보류"
    )

    print(
        "  사유: 문자열 범주형 Feature로 "
        "별도 인코딩 정책 필요"
    )


    # --------------------------------------------------------
    # signCountAbnormal
    # --------------------------------------------------------

    sign_values = [
        int(
            row["sign_count_abnormal"]
            or 0
        )
        for row in rows
    ]

    sign_true_count = (
        sign_values.count(1)
    )

    print()

    print(
        "signCountAbnormal:"
    )

    print(
        f"  수집 데이터: "
        f"{len(sign_values)}건"
    )

    print(
        f"  이상 데이터: "
        f"{sign_true_count}건"
    )

    print(
        "  ML 학습 반영: 보류"
    )

    print(
        "  사유: signCount 이상은 "
        "WebAuthn 검증 단계에서 즉시 탐지"
    )


    # --------------------------------------------------------
    # hasPreviousContext
    # --------------------------------------------------------

    previous_context_values = [
        int(
            row["has_previous_context"]
            or 0
        )
        for row in rows
    ]

    previous_context_true_count = (
        previous_context_values.count(1)
    )

    print()

    print(
        "hasPreviousContext:"
    )

    print(
        f"  수집 데이터: "
        f"{len(previous_context_values)}건"
    )

    print(
        f"  이전 Context 존재: "
        f"{previous_context_true_count}건"
    )

    print(
        "  ML 학습 반영: 채택"
    )


# ============================================================
# Main
# ============================================================

def main():

    print(
        "ML DB 접속 설정:",
        {
            "host": DB_HOST,
            "port": DB_PORT,
            "user": DB_USER,
            "database": DB_NAME,
            "has_password": bool(DB_PASSWORD),
        },
    )

    try:

        rows = load_real_rows()

    except (
        RuntimeError,
        pymysql.MySQLError,
    ) as error:

        print(
            "[실패]",
            error,
        )

        return


    print_basic_summary(
        rows
    )

    if not rows:

        print(
            "REAL 데이터가 없습니다."
        )

        return


    print_null_summary(
        rows
    )

    print_numeric_summary(
        rows
    )

    print_boolean_summary(
        rows
    )

    print_login_region_distribution(
        rows
    )

    print_login_hour_distribution(
        rows
    )

    print_day_distribution(
        rows
    )

    print_ml_feature_status()

    print_additional_feature_summary(
        rows
    )

    print_quality_warnings(
        rows
    )

    print()

    print("=" * 70)

    print(
        "REAL 데이터 분석 완료"
    )

    print("=" * 70)


if __name__ == "__main__":

    main()